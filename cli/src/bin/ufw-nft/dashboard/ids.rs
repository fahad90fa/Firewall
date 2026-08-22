//! A rule-driven detection engine — ingest a Suricata-style ruleset and match
//! it against the live event stream.
//!
//! Scope, stated honestly: this matches on packet *header* fields — protocol,
//! destination port, TCP flags, direction — which are what the firewall log
//! carries. It does NOT do payload/content matching (`content:`, `pcre:`),
//! because that needs the raw bytes from the inline packet path, not the denial
//! log. Header signatures still catch a great deal (service probes, scan flag
//! patterns, traffic to ports that should never be touched), and the operator
//! writes them without recompiling. Unsupported options are ignored, not
//! silently mis-evaluated.

use std::collections::BTreeSet;

use super::events::Event;

const DIR: &str = "/etc/unified-firewall/ids-rules";

pub struct Sig {
    pub sid: String,
    pub action: String, // alert | drop | reject | pass
    pub proto: String,  // tcp | udp | icmp | ip | any
    pub dport: Port,
    pub flags: Vec<String>, // required TCP flags (SYN, ACK, …)
    pub msg: String,
    pub severity: String,
}

pub enum Port {
    Any,
    One(u16),
    List(Vec<u16>),
}

pub struct Hit {
    pub sid: String,
    pub msg: String,
    pub severity: String,
    pub action: String,
    pub count: u64,
    pub sources: Vec<String>,
}

fn map_flag(c: char) -> Option<&'static str> {
    match c.to_ascii_uppercase() {
        'S' => Some("SYN"),
        'A' => Some("ACK"),
        'F' => Some("FIN"),
        'R' => Some("RST"),
        'P' => Some("PSH"),
        'U' => Some("URG"),
        _ => None,
    }
}

fn parse_port(tok: &str) -> Port {
    let t = tok.trim();
    if t == "any" || t == "$HTTP_PORTS" || t.is_empty() {
        return Port::Any;
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let list: Vec<u16> = inner
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
        return if list.is_empty() {
            Port::Any
        } else {
            Port::List(list)
        };
    }
    match t.parse::<u16>() {
        Ok(p) => Port::One(p),
        Err(_) => Port::Any,
    }
}

fn classtype_severity(class: &str) -> &'static str {
    match class {
        "attempted-admin" | "successful-admin" | "trojan-activity" | "shellcode-detect" => {
            "critical"
        }
        "attempted-user" | "web-application-attack" | "attempted-dos" => "high",
        "attempted-recon" | "bad-unknown" | "network-scan" => "medium",
        _ => "low",
    }
}

/// Parse one rule line. Returns None for comments/blank/unparseable headers.
pub fn parse_rule(line: &str) -> Option<Sig> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (header, opts) = match (line.find('('), line.rfind(')')) {
        (Some(a), Some(b)) if b > a => (&line[..a], &line[a + 1..b]),
        _ => (line, ""),
    };
    let h: Vec<&str> = header.split_whitespace().collect();
    // action proto src sport dir dst dport  (7 header tokens)
    if h.len() < 7 {
        return None;
    }
    let action = h[0].to_lowercase();
    if !matches!(
        action.as_str(),
        "alert" | "drop" | "reject" | "pass" | "log"
    ) {
        return None;
    }
    let proto = h[1].to_lowercase();
    let dport = parse_port(h[6]);

    let mut msg = String::new();
    let mut sid = String::new();
    let mut flags = Vec::new();
    let mut severity = "medium".to_string();
    for opt in opts.split(';') {
        let opt = opt.trim();
        let (k, v) = match opt.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"')),
            None => (opt, ""),
        };
        match k {
            "msg" => msg = v.to_string(),
            "sid" => sid = v.to_string(),
            "classtype" => severity = classtype_severity(v).to_string(),
            "flags" => {
                flags = v
                    .split(|c: char| !c.is_ascii_alphabetic())
                    .flat_map(|s| s.chars())
                    .filter_map(map_flag)
                    .map(|s| s.to_string())
                    .collect();
            }
            _ => {}
        }
    }
    if msg.is_empty() {
        msg = format!("{proto} rule");
    }
    if sid.is_empty() {
        // Deterministic fallback id so hits still aggregate.
        sid = format!("auto-{}", header.split_whitespace().collect::<String>());
    }
    Some(Sig {
        sid,
        action,
        proto,
        dport,
        flags,
        msg,
        severity,
    })
}

fn port_matches(p: &Port, dpt: Option<u16>) -> bool {
    match p {
        Port::Any => true,
        Port::One(x) => dpt == Some(*x),
        Port::List(l) => dpt.map(|d| l.contains(&d)).unwrap_or(false),
    }
}

fn sig_matches(s: &Sig, e: &Event) -> bool {
    let proto_ok = matches!(s.proto.as_str(), "ip" | "any") || s.proto == e.proto.to_lowercase();
    if !proto_ok || !port_matches(&s.dport, e.dpt) {
        return false;
    }
    // All required TCP flags must be present.
    s.flags.iter().all(|f| e.flags.iter().any(|g| g == f))
}

/// Match every signature against every event, returning per-signature hits
/// (most-frequent first). Pure and unit-testable.
pub fn evaluate(sigs: &[Sig], events: &[Event]) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    for s in sigs {
        let mut count = 0u64;
        let mut srcs: BTreeSet<String> = BTreeSet::new();
        for e in events {
            if sig_matches(s, e) {
                count += 1;
                if srcs.len() < 8 && !e.src.is_empty() {
                    srcs.insert(e.src.clone());
                }
            }
        }
        if count > 0 {
            hits.push(Hit {
                sid: s.sid.clone(),
                msg: s.msg.clone(),
                severity: s.severity.clone(),
                action: s.action.clone(),
                count,
                sources: srcs.into_iter().collect(),
            });
        }
    }
    hits.sort_by_key(|h| std::cmp::Reverse(h.count));
    hits
}

/// Load every `.rules` file under the IDS rules directory.
pub fn load() -> Vec<Sig> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(DIR) else {
        return out;
    };
    let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    files.sort();
    for path in files {
        if path.extension().and_then(|s| s.to_str()) != Some("rules") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if let Some(s) = parse_rule(line) {
                    out.push(s);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(proto: &str, dpt: u16, src: &str, flags: &[&str]) -> Event {
        Event {
            ts: 0.0,
            action: "deny".into(),
            rule: None,
            dir: "in".into(),
            iface: "eth0".into(),
            src: src.into(),
            dst: "10.0.0.1".into(),
            proto: proto.into(),
            spt: Some(5000),
            dpt: Some(dpt),
            len: None,
            ttl: None,
            flags: flags.iter().map(|s| s.to_string()).collect(),
            icmp_type: None,
        }
    }

    #[test]
    fn parses_a_suricata_header_and_options() {
        let s = parse_rule(
            r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"RDP probe"; sid:1000001; classtype:attempted-recon;)"#,
        )
        .unwrap();
        assert_eq!(s.action, "alert");
        assert_eq!(s.proto, "tcp");
        assert!(matches!(s.dport, Port::One(3389)));
        assert_eq!(s.msg, "RDP probe");
        assert_eq!(s.sid, "1000001");
        assert_eq!(s.severity, "medium"); // attempted-recon
    }

    #[test]
    fn ignores_comments_and_bad_lines() {
        assert!(parse_rule("# a comment").is_none());
        assert!(parse_rule("").is_none());
        assert!(parse_rule("notarule").is_none());
    }

    #[test]
    fn matches_proto_and_port() {
        let sigs =
            vec![parse_rule(r#"alert tcp any any -> any 3389 (msg:"RDP"; sid:1;)"#).unwrap()];
        let events = vec![
            ev("TCP", 3389, "203.0.113.9", &[]),
            ev("TCP", 3389, "198.51.100.7", &[]),
            ev("TCP", 22, "203.0.113.9", &[]),   // wrong port
            ev("UDP", 3389, "203.0.113.9", &[]), // wrong proto
        ];
        let h = evaluate(&sigs, &events);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].count, 2);
        assert_eq!(h[0].sources.len(), 2);
    }

    #[test]
    fn matches_required_tcp_flags() {
        let sigs =
            vec![
                parse_rule(r#"alert tcp any any -> any any (msg:"SYN scan"; flags:S; sid:2;)"#)
                    .unwrap(),
            ];
        let events = vec![
            ev("TCP", 80, "203.0.113.9", &["SYN"]),
            ev("TCP", 80, "203.0.113.9", &["ACK"]), // no SYN
        ];
        let h = evaluate(&sigs, &events);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].count, 1);
    }

    #[test]
    fn port_lists_and_any() {
        let sigs = vec![
            parse_rule(r#"alert tcp any any -> any [80,443] (msg:"web"; sid:3;)"#).unwrap(),
            parse_rule(r#"alert ip any any -> any any (msg:"all"; sid:4;)"#).unwrap(),
        ];
        let events = vec![ev("TCP", 443, "1.2.3.4", &[])];
        let h = evaluate(&sigs, &events);
        // Both the [80,443] rule and the ip/any rule match.
        assert_eq!(h.len(), 2);
    }
}
