//! One-click containment: drop an attacker at the kernel, with auto-expiry.
//!
//! The console's read paths never mutate anything. This is the one deliberate
//! exception — and it is gated accordingly: the handler only accepts it from a
//! loopback caller, every action is appended to an audit log, and each block
//! carries a native nftables set timeout so it *auto-reverts*. A block made in
//! error clears itself; nothing here is permanent unless the operator asks.
//!
//! It owns a small, separate table, `inet ufw_contain`, rather than editing the
//! policy-compiled `inet ufw` table — so re-applying a policy never wipes the
//! blocklist, and containment is independent of whatever policy is loaded. The
//! table's chain hooks input at a priority ahead of the policy table, so a
//! contained source is dropped before any allow rule can see it.

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

const AUDIT: &str = "/var/lib/unified-firewall/contain-audit.log";
/// A block may not outlive this, even if a larger ttl is requested — a runaway
/// UI cannot install a permanent lockout by accident.
const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// A currently-contained source, for the dashboard.
pub struct Contained {
    pub ip: String,
    /// Seconds until the block auto-expires; None for a permanent block.
    pub expires_secs: Option<u64>,
}

/// The nftables program that defines (idempotently) the containment table.
/// `add table/set/chain` are no-ops if they already exist; flushing the chain
/// before re-adding the two drop rules keeps `ensure` safe to call repeatedly
/// without stacking duplicate rules.
const ENSURE: &str = "\
add table inet ufw_contain
add set inet ufw_contain contained { type ipv4_addr; flags timeout; }
add set inet ufw_contain contained6 { type ipv6_addr; flags timeout; }
add chain inet ufw_contain input { type filter hook input priority -10; policy accept; }
flush chain inet ufw_contain input
add rule inet ufw_contain input ip saddr @contained counter drop
add rule inet ufw_contain input ip6 saddr @contained6 counter drop
";

fn ensure() -> Result<(), String> {
    run(&["-f", "-"], Some(ENSURE)).map(|_| ())
}

/// Run nft with `args`, optionally feeding `stdin`. Returns Ok(stdout) or a
/// trimmed error. Bounded so a wedged nft cannot hang the request.
fn run(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("nft")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run nft: {e}"))?;
    if let Some(s) = stdin {
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(s.as_bytes());
        } // dropping `si` closes stdin so nft can proceed
    }
    // nft on a small ruleset returns promptly; a short wall-clock guard keeps a
    // stuck kernel lock from hanging the handler.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("nft timed out".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(
            if err.contains("permission") || err.contains("not permitted") {
                "nft needs root: run the dashboard with sudo".into()
            } else {
                format!("nft: {err}")
            },
        )
    }
}

/// Validate an address string as a real IPv4/IPv6 literal — the one untrusted
/// input that reaches nft. Anything that is not a bare IP is rejected before a
/// command is built, so the address cannot smuggle nft syntax.
fn parse_ip(ip: &str) -> Result<(IpAddr, bool), String> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| format!("`{ip}` is not a valid IP address"))?;
    let v6 = addr.is_ipv6();
    if addr.is_loopback() || addr.is_unspecified() {
        return Err("refusing to contain a loopback/unspecified address".into());
    }
    Ok((addr, v6))
}

fn audit(line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT)
    {
        let _ = writeln!(f, "{} {}", crate::state::now_unix(), line);
    }
}

/// Block `ip` for `ttl_secs` (0 = permanent). Idempotent: re-containing an
/// already-contained address refreshes its timer.
pub fn contain(ip: &str, ttl_secs: u64) -> Result<(), String> {
    let (addr, v6) = parse_ip(ip)?;
    ensure()?;
    let set = if v6 { "contained6" } else { "contained" };
    let elem = if ttl_secs == 0 {
        addr.to_string()
    } else {
        format!("{addr} timeout {}s", ttl_secs.min(MAX_TTL_SECS))
    };
    run(
        &[
            "add",
            "element",
            "inet",
            "ufw_contain",
            set,
            &format!("{{ {elem} }}"),
        ],
        None,
    )?;
    audit(&format!(
        "contain {addr} ttl={}",
        if ttl_secs == 0 {
            "permanent".into()
        } else {
            format!("{ttl_secs}s")
        }
    ));
    Ok(())
}

/// Lift the block on `ip`.
pub fn release(ip: &str) -> Result<(), String> {
    let (addr, v6) = parse_ip(ip)?;
    let set = if v6 { "contained6" } else { "contained" };
    run(
        &[
            "delete",
            "element",
            "inet",
            "ufw_contain",
            set,
            &format!("{{ {addr} }}"),
        ],
        None,
    )?;
    audit(&format!("release {addr}"));
    Ok(())
}

/// The currently-contained sources, newest expiry last. Empty (not an error)
/// when the table does not exist yet.
pub fn list() -> Vec<Contained> {
    let mut out = Vec::new();
    for set in ["contained", "contained6"] {
        if let Ok(text) = run(&["list", "set", "inet", "ufw_contain", set], None) {
            out.extend(parse_set(&text));
        }
    }
    out
}

/// Extract `{ip, expires_secs}` from `nft list set` output. The element block
/// looks like: `elements = { 1.2.3.4 timeout 1h expires 3599s, 5.6.7.8 ... }`.
fn parse_set(text: &str) -> Vec<Contained> {
    let mut out = Vec::new();
    let Some(start) = text.find("elements = {") else {
        return out;
    };
    let rest = &text[start + "elements = {".len()..];
    let block = rest.split('}').next().unwrap_or(rest);
    for item in block.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let mut words = item.split_whitespace();
        let Some(ip) = words.next() else { continue };
        if ip.parse::<IpAddr>().is_err() {
            continue;
        }
        // "... expires 3599s" — capture the seconds if present.
        let expires_secs = item
            .split_whitespace()
            .skip_while(|w| *w != "expires")
            .nth(1)
            .and_then(parse_duration);
        out.push(Contained {
            ip: ip.to_string(),
            expires_secs,
        });
    }
    out
}

/// nft prints durations like `3599s`, `59m59s988ms`, `1h`, `1d2h`. Sum the
/// whole-second parts; sub-second units (`ms`/`us`/`ns`) are just dropped.
fn parse_duration(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    let mut total = 0u64;
    let mut seen = false;
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None; // a unit with no number in front of it
        }
        let n: u64 = s[start..i].parse().ok()?;
        let ustart = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let mult = match &s[ustart..i] {
            "d" => 86400,
            "h" => 3600,
            "m" => 60,
            "s" => 1,
            "ms" | "us" | "ns" => 0,
            _ => return None,
        };
        total += n * mult;
        seen = true;
    }
    seen.then_some(total)
}

/// Reverse-DNS (PTR) for the dossier, via the system resolver — bounded, and
/// nothing more than a name lookup (no WHOIS, no outbound beyond DNS).
pub fn reverse_dns(ip: &str) -> Option<String> {
    let (addr, _) = parse_ip(ip).ok()?;
    let mut cmd = Command::new("getent");
    cmd.args(["hosts", &addr.to_string()]);
    let out = super::bounded::run_bounded(cmd, Duration::from_secs(2)).ok()?;
    if !out.status.success() {
        return None;
    }
    // "1.2.3.4   host.example.com  alias" — the name is the second field.
    let line = String::from_utf8_lossy(&out.stdout);
    let name = line.split_whitespace().nth(1)?.to_string();
    (!name.is_empty() && name != addr.to_string()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_set_extracts_ips_and_expiry() {
        let text = "table inet ufw_contain {\n\tset contained {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 203.0.113.9 timeout 1h expires 3599s,\n\t\t\t198.51.100.7 timeout 1h expires 59m }\n\t}\n}";
        let v = parse_set(text);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].ip, "203.0.113.9");
        assert_eq!(v[0].expires_secs, Some(3599));
        assert_eq!(v[1].ip, "198.51.100.7");
        assert_eq!(v[1].expires_secs, Some(3540));
    }

    #[test]
    fn parse_set_empty_when_no_elements() {
        assert!(parse_set("set contained { type ipv4_addr }").is_empty());
    }

    #[test]
    fn durations_sum_units() {
        assert_eq!(parse_duration("3599s"), Some(3599));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("1d2h"), Some(93600));
        // Real nft output includes a sub-second tail, which we drop.
        assert_eq!(parse_duration("59m59s988ms"), Some(3599));
        assert_eq!(parse_duration("nope"), None);
    }

    #[test]
    fn bad_ips_are_rejected_before_nft() {
        assert!(parse_ip("not-an-ip").is_err());
        assert!(parse_ip("1.2.3.4; drop table").is_err());
        assert!(parse_ip("127.0.0.1").is_err()); // loopback refused
        assert!(parse_ip("203.0.113.9").is_ok());
        assert!(parse_ip("2001:db8::1").is_ok());
    }
}
