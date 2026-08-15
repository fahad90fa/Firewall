//! Read the live ruleset back out of the kernel.
//!
//! `nft list table inet ufw` prints the table this tool itself loaded, plus
//! the per-rule counters `apply` instrumented in. The input space is
//! therefore not "arbitrary nftables" — it is nft's canonical printing of
//! rules this project generated, which is what makes a line-oriented parse
//! honest rather than fragile. Anything unrecognized is kept verbatim in
//! `matchers`, so the dashboard can always show what the kernel showed us.

use std::process::Command;

/// One rule as the kernel holds it. Chain membership lives on [`ChainView`];
/// the rule itself carries only what the API renders.
pub struct RuleView {
    /// The rule name from `comment "…"`; generated rules always carry one.
    pub name: String,
    /// The match expressions, verbatim (e.g. `tcp dport { 21, 23 }`).
    pub matchers: String,
    /// "accept" | "drop" | "reject" | "alert" | "continue".
    pub verdict: String,
    /// Whether the rule logs, and as what (`deny` / `alert`), from the
    /// structured `ufw#<kind>#<rule> ` prefix.
    pub log_kind: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    /// Destination ports named in the matchers, expanded (ranges capped).
    pub dports: Vec<u16>,
    /// The connection-rate cap, if the rule carries an nftables `limit rate`
    /// clause (e.g. `20/minute burst 5`). SYN-flood / brute-force dampening.
    pub rate_limit: Option<String>,
}

pub struct ChainView {
    pub name: String,
    /// The chain's default policy: "accept" or "drop".
    pub policy: String,
    pub rules: Vec<RuleView>,
}

pub struct Ruleset {
    pub loaded: bool,
    pub chains: Vec<ChainView>,
    pub error: Option<String>,
}

pub fn load() -> Ruleset {
    let out = Command::new("nft")
        .args(["list", "table", "inet", "ufw"])
        .output();
    match out {
        Ok(o) if o.status.success() => Ruleset {
            loaded: true,
            chains: parse(&String::from_utf8_lossy(&o.stdout)),
            error: None,
        },
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            let missing =
                err.contains("No such file or directory") || err.contains("does not exist");
            Ruleset {
                loaded: false,
                chains: Vec::new(),
                error: if missing {
                    None
                } else if err.contains("permitted") || err.contains("Permission denied") {
                    Some("nft needs root: run the dashboard with sudo".into())
                } else {
                    Some(format!("nft: {err}"))
                },
            }
        }
        Err(e) => Ruleset {
            loaded: false,
            chains: Vec::new(),
            error: Some(format!("could not run nft: {e}")),
        },
    }
}

pub fn parse(text: &str) -> Vec<ChainView> {
    let mut chains: Vec<ChainView> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("chain ") {
            let name = rest.trim_end_matches('{').trim().to_string();
            chains.push(ChainView {
                name,
                policy: "accept".into(),
                rules: Vec::new(),
            });
            continue;
        }
        let Some(chain) = chains.last_mut() else {
            continue;
        };
        if line.starts_with("type ") {
            if let Some(p) = line.split("policy ").nth(1) {
                chain.policy = p.trim_end_matches(';').trim().to_string();
            }
            continue;
        }
        if line.is_empty() || line == "}" || line.starts_with('#') || line.starts_with("table ") {
            continue;
        }
        chain.rules.push(parse_rule(line));
    }
    chains
}

fn parse_rule(line: &str) -> RuleView {
    // Split the trailing comment off first so a rule name containing a
    // keyword cannot confuse the rest of the parse.
    let (head, name) = match line.rfind(" comment \"") {
        Some(i) => {
            let c = &line[i + " comment \"".len()..];
            (line[..i].trim_end(), c.trim_end_matches('"').to_string())
        }
        None => (line, String::new()),
    };

    // Excise the `counter packets N bytes M` clause, keeping its numbers.
    // Token-wise, because the clause can sit before or after the log
    // statement depending on the verdict.
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let toks: Vec<&str> = head.split_whitespace().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(toks.len());
    let mut k = 0;
    while k < toks.len() {
        if toks[k] == "counter"
            && k + 4 < toks.len()
            && toks[k + 1] == "packets"
            && toks[k + 3] == "bytes"
        {
            packets = toks[k + 2].parse().unwrap_or(0);
            bytes = toks[k + 4].parse().unwrap_or(0);
            k += 5;
            continue;
        }
        kept.push(toks[k]);
        k += 1;
    }
    let mut head = kept.join(" ");

    let mut log_kind = None;
    if let Some(i) = head.find("log prefix \"") {
        let tail = &head[i + "log prefix \"".len()..];
        if let Some(q) = tail.find('"') {
            let prefix = &tail[..q];
            if let Some(rest) = prefix.strip_prefix("ufw#") {
                log_kind = rest.split('#').next().map(|s| s.to_string());
            } else if prefix.starts_with("ufw-alert") {
                log_kind = Some("alert".into());
            }
            let after = tail[q + 1..].trim_start().to_string();
            head = format!("{} {}", head[..i].trim_end(), after)
                .trim()
                .to_string();
        }
    }

    let mut verdict = "continue".to_string();
    for v in ["accept", "drop", "reject", "continue"] {
        if head == v || head.ends_with(&format!(" {v}")) {
            verdict = v.to_string();
            head = head[..head.len() - v.len()].trim_end().to_string();
            break;
        }
    }
    if verdict == "continue" && log_kind.as_deref() == Some("alert") {
        verdict = "alert".to_string();
    }

    let dports = extract_dports(&head);
    let rate_limit = extract_rate_limit(&head);
    RuleView {
        name,
        matchers: head,
        verdict,
        log_kind,
        packets,
        bytes,
        dports,
        rate_limit,
    }
}

/// Pull the rate spec out of an nftables `limit rate 20/minute burst 5 packets`
/// clause: the number, the unit, and an optional burst — dropping the trailing
/// `packets` keyword that is noise to a reader.
fn extract_rate_limit(matchers: &str) -> Option<String> {
    let i = matchers.find("limit rate ")?;
    let tail = &matchers[i + "limit rate ".len()..];
    let mut spec = String::new();
    for word in tail.split_whitespace() {
        if word == "packets" || word == "accept" || word == "drop" {
            break;
        }
        if !spec.is_empty() {
            spec.push(' ');
        }
        spec.push_str(word);
        // `20/minute` alone, or `20/minute burst 5` — stop after the burst count.
        if spec.split_whitespace().count() >= 3 {
            break;
        }
    }
    (!spec.is_empty()).then_some(spec)
}

/// Pull destination ports out of matcher text: `tcp dport { 21, 23, 512-514 }`
/// or `udp dport 53`. Ranges are expanded up to a cap so a `1-65535` cannot
/// balloon the API payload.
fn extract_dports(matchers: &str) -> Vec<u16> {
    let Some(i) = matchers.find("dport") else {
        return Vec::new();
    };
    let tail = matchers[i + "dport".len()..].trim_start();
    let tail = tail.strip_prefix("!=").unwrap_or(tail).trim_start();
    let list: &str = if let Some(rest) = tail.strip_prefix('{') {
        match rest.find('}') {
            Some(j) => &rest[..j],
            None => rest,
        }
    } else {
        tail.split_whitespace().next().unwrap_or("")
    };

    let mut ports = Vec::new();
    for item in list.split(',') {
        let item = item.trim();
        if let Some((lo, hi)) = item.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                for p in lo..=hi.min(lo.saturating_add(31)) {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = item.parse::<u16>() {
            ports.push(p);
        }
        if ports.len() >= 64 {
            break;
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"table inet ufw {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport { 21, 23, 69, 79, 512-514 } log prefix "ufw#deny#deny-cleartext-protocols " counter packets 7 bytes 420 drop comment "deny-cleartext-protocols"
        counter packets 1234 bytes 99999 accept comment "allow-everything-else"
    }
    chain output {
        type filter hook output priority filter; policy drop;
        tcp dport { 5432 } counter packets 2 bytes 120 log prefix "ufw#alert#audit-database-egress " comment "audit-database-egress"
    }
}"#;

    #[test]
    fn parses_chains_policies_and_counters() {
        let chains = parse(SAMPLE);
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].name, "input");
        assert_eq!(chains[0].policy, "accept");
        assert_eq!(chains[1].policy, "drop");

        let deny = &chains[0].rules[0];
        assert_eq!(deny.name, "deny-cleartext-protocols");
        assert_eq!(deny.verdict, "drop");
        assert_eq!(deny.packets, 7);
        assert_eq!(deny.bytes, 420);
        assert_eq!(deny.log_kind.as_deref(), Some("deny"));
        assert!(deny.matchers.contains("tcp dport"));
        assert!(!deny.matchers.contains("counter"), "{}", deny.matchers);
        assert!(!deny.matchers.contains("log prefix"), "{}", deny.matchers);
        assert!(deny.dports.contains(&23));
        assert!(deny.dports.contains(&514));

        let allow = &chains[0].rules[1];
        assert_eq!(allow.verdict, "accept");
        assert_eq!(allow.packets, 1234);
        assert_eq!(allow.matchers, "");
    }

    #[test]
    fn an_alert_rule_reads_as_alert_not_continue() {
        let chains = parse(SAMPLE);
        let alert = &chains[1].rules[0];
        assert_eq!(alert.verdict, "alert");
        assert_eq!(alert.log_kind.as_deref(), Some("alert"));
        assert_eq!(alert.packets, 2);
        assert_eq!(alert.dports, vec![5432]);
    }

    #[test]
    fn range_expansion_is_capped() {
        let ports = extract_dports("tcp dport { 1-65535 }");
        assert!(ports.len() <= 64);
    }

    #[test]
    fn a_rate_limit_clause_is_extracted() {
        let line = "meta l4proto 6 tcp dport { 22 } ct state new limit rate 20/minute burst 5 packets counter packets 3 bytes 180 accept comment \"ssh-in\"";
        let r = parse_rule(line);
        assert_eq!(r.name, "ssh-in");
        assert_eq!(r.verdict, "accept");
        assert_eq!(r.rate_limit.as_deref(), Some("20/minute burst 5"));
        assert!(r.dports.contains(&22));
    }

    #[test]
    fn a_rate_limit_without_a_burst_is_extracted() {
        assert_eq!(
            extract_rate_limit("ct state new limit rate 200/second accept"),
            Some("200/second".to_string())
        );
        assert_eq!(extract_rate_limit("tcp dport { 80 } accept"), None);
    }
}
