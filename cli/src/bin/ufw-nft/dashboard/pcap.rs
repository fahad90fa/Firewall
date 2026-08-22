//! On-demand packet capture for the investigation dossier.
//!
//! "Show me what this source is actually sending" — a bounded `tcpdump` that
//! captures up to N packets (or a few seconds) to/from one address and returns
//! a standard pcap the operator can open in Wireshark offline. It is gated to
//! loopback callers exactly like containment, the address is validated before
//! it reaches tcpdump, and the capture is time-bounded so it can never run
//! unattended.
//!
//! tcpdump is wrapped in `timeout` rather than relying on the request-path
//! killer, because a hard kill would discard the partially-written pcap;
//! `timeout` sends SIGTERM, on which tcpdump flushes a valid file for whatever
//! it captured. run_bounded stays as a backstop with a slightly larger budget.

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

/// Wall-clock ceiling for a single capture.
const CAPTURE_SECS: u64 = 12;
const MAX_PACKETS: u32 = 500;
/// A pcap file always begins with a 24-byte global header; anything shorter
/// means no packets (and probably an error on stderr).
const PCAP_HEADER_LEN: usize = 24;

/// Validate the target address — the one untrusted input. Rejects non-IPs and
/// loopback/unspecified (capturing those is pointless and noisy).
fn validate(ip: &str) -> Result<IpAddr, String> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| format!("`{ip}` is not a valid IP address"))?;
    if addr.is_loopback() || addr.is_unspecified() {
        return Err("refusing to capture a loopback/unspecified address".into());
    }
    Ok(addr)
}

/// Capture up to `n` packets to/from `ip`, returning the raw pcap bytes.
pub fn capture(ip: &str, n: u32) -> Result<Vec<u8>, String> {
    let addr = validate(ip)?;
    let n = n.clamp(1, MAX_PACKETS).to_string();
    let host = addr.to_string();
    let secs = CAPTURE_SECS.to_string();

    // timeout --signal=TERM <secs> tcpdump -n -i any -c <n> -U -w - host <ip>
    let mut cmd = Command::new("timeout");
    cmd.args([
        "--signal=TERM",
        &secs,
        "tcpdump",
        "-n",
        "-i",
        "any",
        "-c",
        &n,
        "-U",
        "-w",
        "-",
        "host",
        &host,
    ]);

    match super::bounded::run_bounded(cmd, Duration::from_secs(CAPTURE_SECS + 3)) {
        Ok(out) => {
            if out.stdout.len() >= PCAP_HEADER_LEN {
                return Ok(out.stdout);
            }
            let err = String::from_utf8_lossy(&out.stderr);
            Err(diagnose(&err, &host))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("`timeout`/`tcpdump` are not available on this host".into())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn diagnose(stderr: &str, host: &str) -> String {
    let e = stderr.to_lowercase();
    if e.contains("not found") || e.contains("no such file") {
        "tcpdump is not installed on this host".into()
    } else if e.contains("permission") || e.contains("not permitted") || e.contains("root") {
        "packet capture needs root / CAP_NET_RAW — run the dashboard with sudo".into()
    } else {
        format!("no packets from {host} in {CAPTURE_SECS}s — the source may be quiet or already contained")
    }
}

/// A safe download filename for a capture of `ip`.
pub fn filename(ip: &str) -> String {
    let safe: String = ip
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("ufw-capture-{safe}.pcap")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_addresses() {
        assert!(validate("203.0.113.9").is_ok());
        assert!(validate("2001:db8::1").is_ok());
        assert!(validate("not-an-ip").is_err());
        assert!(validate("127.0.0.1").is_err()); // loopback refused
        assert!(validate("0.0.0.0").is_err()); // unspecified refused
        assert!(validate("1.2.3.4; rm -rf /").is_err()); // not a bare IP
    }

    #[test]
    fn filename_is_sanitized() {
        assert_eq!(filename("203.0.113.9"), "ufw-capture-203.0.113.9.pcap");
        assert_eq!(filename("2001:db8::1"), "ufw-capture-2001_db8__1.pcap");
        assert_eq!(filename("../etc/passwd"), "ufw-capture-.._etc_passwd.pcap");
    }

    #[test]
    fn diagnose_maps_common_errors() {
        assert!(diagnose("tcpdump: command not found", "x").contains("not installed"));
        assert!(diagnose("you don't have permission", "x").contains("root"));
        assert!(diagnose("", "203.0.113.9").contains("no packets"));
    }
}
