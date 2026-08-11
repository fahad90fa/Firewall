//! Every denied or alerted packet, read back from the kernel log.
//!
//! The ruleset logs denies and alerts with a structured prefix —
//! `ufw#deny#rule-name ` — and netfilter appends the packet facts
//! (`SRC= DST= PROTO= SPT= DPT=` …). This module collects those lines and
//! parses them into events the dashboard can show and the attack classifier
//! can reason over.
//!
//! Collection prefers `journalctl -k` (persistent, absolute unix
//! timestamps) and falls back to `dmesg` (ring buffer, boot-relative
//! timestamps rebased with /proc/stat's btime). Both failing is itself
//! reported, never hidden.

use std::process::Command;

#[derive(Debug, Clone)]
pub struct Event {
    /// Unix seconds (fractional).
    pub ts: f64,
    /// "deny" or "alert".
    pub action: String,
    /// Rule name from the log prefix; None for a legacy `ufw-alert ` line.
    pub rule: Option<String>,
    /// "in", "out", or "" when neither interface field was present.
    pub dir: String,
    pub iface: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub spt: Option<u16>,
    pub dpt: Option<u16>,
    pub len: Option<u32>,
    pub ttl: Option<u32>,
    /// TCP flags present on the packet (SYN, ACK, FIN, RST, PSH, URG).
    pub flags: Vec<String>,
    /// ICMP type, when the packet was ICMP.
    pub icmp_type: Option<u8>,
}

/// Which log source `collect` should parse, and whether its timestamps are
/// dmesg-style boot-relative.
enum Source {
    /// journalctl short-unix lines: absolute timestamps.
    Journal(Vec<String>),
    /// dmesg lines: rebase against boot time.
    Dmesg(Vec<String>),
    /// Nothing to parse.
    None,
}

/// Decide which source to parse from the two collectors' results, pushing any
/// problems onto `errors`. Pure, so the fallthrough rule that actually
/// bit us — journalctl succeeding but empty must still try dmesg — is
/// testable without a kernel.
fn choose_source(
    journal: Result<Vec<String>, String>,
    dmesg: impl FnOnce() -> Result<Vec<String>, String>,
    errors: &mut Vec<String>,
) -> Source {
    let journal_ok = match journal {
        // A non-empty journal is the answer; an empty one is not (a live
        // system with no kernel journal returns exactly this), so fall
        // through to dmesg.
        Ok(lines) if !lines.is_empty() => return Source::Journal(lines),
        Ok(_) => true,
        Err(e) => {
            errors.push(e);
            false
        }
    };

    match dmesg() {
        Ok(lines) if !lines.is_empty() => Source::Dmesg(lines),
        // Both sources readable but empty: genuinely no logged denials yet.
        Ok(_) => Source::None,
        Err(e) => {
            errors.push(e);
            if !journal_ok {
                errors.push(
                    "no kernel log source is readable; denied-packet history is unavailable \
                     (is this running with sudo?)"
                        .into(),
                );
            }
            Source::None
        }
    }
}

/// Newest-last list of events plus any collection problems worth surfacing.
///
/// journalctl is preferred for its absolute timestamps, but having a kernel
/// journal at all is not guaranteed: on a stock Parrot/Kali live system
/// `journalctl -k` exits 0 and prints nothing while every firewall log line
/// sits in dmesg's ring buffer. See [`choose_source`] for the fallthrough.
pub fn collect(max: usize) -> (Vec<Event>, Vec<String>) {
    let mut errors = Vec::new();
    match choose_source(journalctl_lines(), dmesg_lines, &mut errors) {
        Source::Journal(lines) => (parse_lines(&lines, None, max), errors),
        Source::Dmesg(lines) => {
            let boot = boot_epoch();
            if boot == 0.0 {
                errors.push("could not read boot time; dmesg event times are boot-relative".into());
            }
            (parse_lines(&lines, Some(boot), max), errors)
        }
        Source::None => (Vec::new(), errors),
    }
}

fn journalctl_lines() -> Result<Vec<String>, String> {
    let out = Command::new("journalctl")
        .args([
            "-k",
            "-o",
            "short-unix",
            "--no-pager",
            "-q",
            "--since",
            "48 hours ago",
        ])
        .output()
        .map_err(|e| format!("journalctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "journalctl: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("ufw#") || l.contains("ufw-alert "))
        .map(str::to_string)
        .collect())
}

fn dmesg_lines() -> Result<Vec<String>, String> {
    let out = Command::new("dmesg")
        .output()
        .map_err(|e| format!("dmesg: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "dmesg: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("ufw#") || l.contains("ufw-alert "))
        .map(str::to_string)
        .collect())
}

/// Boot time as unix seconds, from /proc/stat's `btime` — the exact value
/// the kernel stamps, not an uptime subtraction that drifts.
fn boot_epoch() -> f64 {
    let Ok(stat) = std::fs::read_to_string("/proc/stat") else {
        return 0.0;
    };
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Parse raw log lines. `boot` present means the line timestamps are
/// dmesg-style `[seconds.frac]` needing a rebase; absent means journalctl
/// short-unix with the epoch as the first token.
fn parse_lines(lines: &[String], boot: Option<f64>, max: usize) -> Vec<Event> {
    let mut events: Vec<Event> = lines.iter().filter_map(|l| parse_line(l, boot)).collect();
    events.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap_or(std::cmp::Ordering::Equal));
    if events.len() > max {
        events.drain(..events.len() - max);
    }
    events
}

fn parse_line(line: &str, boot: Option<f64>) -> Option<Event> {
    let ts = match boot {
        // `[  123.456789] …`
        Some(boot) => {
            let open = line.find('[')?;
            let close = line[open..].find(']')? + open;
            boot + line[open + 1..close].trim().parse::<f64>().ok()?
        }
        // `1723400000.123456 host kernel: …`
        None => line.split_whitespace().next()?.parse::<f64>().ok()?,
    };

    let (action, rule, rest) = if let Some(i) = line.find("ufw#") {
        let tail = &line[i + "ufw#".len()..];
        let mut parts = tail.splitn(2, '#');
        let action = parts.next()?.to_string();
        let after = parts.next()?;
        let sp = after.find(' ')?;
        (action, Some(after[..sp].to_string()), &after[sp..])
    } else if let Some(i) = line.find("ufw-alert ") {
        ("alert".to_string(), None, &line[i + "ufw-alert".len()..])
    } else {
        return None;
    };
    if action != "deny" && action != "alert" {
        return None;
    }

    let mut ev = Event {
        ts,
        action,
        rule,
        dir: String::new(),
        iface: String::new(),
        src: String::new(),
        dst: String::new(),
        proto: String::new(),
        spt: None,
        dpt: None,
        len: None,
        ttl: None,
        flags: Vec::new(),
        icmp_type: None,
    };

    // For an ICMP error, netfilter appends the *offending* packet's header in
    // brackets: `… PROTO=ICMP TYPE=3 CODE=3 [SRC=… DST=… PROTO=TCP SPT=… DPT=…]`.
    // Those inner fields describe a different packet; parsing past the `[`
    // would overwrite the real DST/PROTO/SPT/DPT with the embedded ones. Stop
    // at the bracket so the event always reflects the packet the rule matched.
    let rest = match rest.find(" [") {
        Some(i) => &rest[..i],
        None => rest,
    };

    for tok in rest.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            match k {
                "IN" if !v.is_empty() => {
                    ev.dir = "in".into();
                    ev.iface = v.to_string();
                }
                "OUT" if !v.is_empty() => {
                    if ev.dir.is_empty() {
                        ev.dir = "out".into();
                        ev.iface = v.to_string();
                    }
                }
                "SRC" => ev.src = v.to_string(),
                "DST" => ev.dst = v.to_string(),
                "PROTO" => ev.proto = v.to_string(),
                "SPT" => ev.spt = v.parse().ok(),
                "DPT" => ev.dpt = v.parse().ok(),
                "LEN" if ev.len.is_none() => ev.len = v.parse().ok(),
                "TTL" | "HOPLIMIT" => ev.ttl = v.parse().ok(),
                "TYPE" => ev.icmp_type = v.parse().ok(),
                _ => {}
            }
        } else if matches!(tok, "SYN" | "ACK" | "FIN" | "RST" | "PSH" | "URG") {
            ev.flags.push(tok.to_string());
        }
    }
    if ev.src.is_empty() && ev.dst.is_empty() {
        // A prefix match with no packet fields is not a netfilter log line.
        return None;
    }
    Some(ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOURNAL_LINE: &str = "1723400000.123456 parrot kernel: ufw#deny#deny-cleartext-protocols IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=203.0.113.7 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=40123 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0";

    #[test]
    fn a_journalctl_deny_line_parses_fully() {
        let ev = parse_line(JOURNAL_LINE, None).unwrap();
        assert_eq!(ev.action, "deny");
        assert_eq!(ev.rule.as_deref(), Some("deny-cleartext-protocols"));
        assert_eq!(ev.dir, "in");
        assert_eq!(ev.iface, "eth0");
        assert_eq!(ev.src, "203.0.113.7");
        assert_eq!(ev.dst, "192.168.1.10");
        assert_eq!(ev.proto, "TCP");
        assert_eq!(ev.spt, Some(40123));
        assert_eq!(ev.dpt, Some(23));
        assert_eq!(ev.ttl, Some(52));
        assert_eq!(ev.flags, vec!["SYN"]);
        assert!((ev.ts - 1723400000.123456).abs() < 1e-3);
    }

    #[test]
    fn a_dmesg_line_rebases_onto_boot_time() {
        let line = "[  512.250000] ufw#deny#deny-inbound IN=wlan0 OUT= SRC=198.51.100.9 DST=10.0.0.5 LEN=40 TTL=240 PROTO=TCP SPT=55555 DPT=3389 SYN";
        let ev = parse_line(line, Some(1_723_000_000.0)).unwrap();
        assert!((ev.ts - 1_723_000_512.25).abs() < 1e-6);
        assert_eq!(ev.dpt, Some(3389));
    }

    #[test]
    fn an_outbound_line_reads_direction_from_out() {
        let line = "1723400001.0 parrot kernel: ufw#deny#deny-smb-egress IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.44 LEN=60 TTL=64 PROTO=TCP SPT=51000 DPT=445 SYN";
        let ev = parse_line(line, None).unwrap();
        assert_eq!(ev.dir, "out");
        assert_eq!(ev.dpt, Some(445));
    }

    #[test]
    fn a_legacy_alert_prefix_still_parses() {
        let line = "1723400002.0 parrot kernel: ufw-alert IN= OUT=eth0 SRC=10.0.0.5 DST=203.0.113.9 LEN=60 TTL=64 PROTO=TCP SPT=51001 DPT=5432 SYN";
        let ev = parse_line(line, None).unwrap();
        assert_eq!(ev.action, "alert");
        assert_eq!(ev.rule, None);
    }

    #[test]
    fn an_ipv6_line_parses() {
        let line = "1723400003.0 parrot kernel: ufw#deny#deny-all IN=eth0 OUT= SRC=2001:0db8:0000:0000:0000:0000:0000:0001 DST=2001:0db8:0000:0000:0000:0000:0000:0002 LEN=72 TC=0 HOPLIMIT=60 PROTO=TCP SPT=40000 DPT=445 SYN";
        let ev = parse_line(line, None).unwrap();
        assert!(ev.src.starts_with("2001:0db8"));
        assert_eq!(ev.ttl, Some(60));
    }

    #[test]
    fn unrelated_kernel_lines_are_ignored() {
        assert!(parse_line("1723400000.0 host kernel: usb 1-1: reset", None).is_none());
        // Prefix present but no packet fields: not a netfilter line.
        assert!(parse_line("1723400000.0 host kernel: ufw#deny#x something", None).is_none());
    }

    fn kinds(s: &Source) -> &'static str {
        match s {
            Source::Journal(_) => "journal",
            Source::Dmesg(_) => "dmesg",
            Source::None => "none",
        }
    }

    #[test]
    fn an_empty_journal_still_falls_through_to_dmesg() {
        // The exact production bug: journalctl exits 0 with no ufw lines, but
        // dmesg has them. dmesg must win, not the empty journal.
        let mut errors = Vec::new();
        let src = choose_source(
            Ok(vec![]),
            || {
                Ok(vec![
                    "1.0 host kernel: ufw#deny#x SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=23".into(),
                ])
            },
            &mut errors,
        );
        assert_eq!(kinds(&src), "dmesg");
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_non_empty_journal_wins_and_dmesg_is_never_run() {
        let mut errors = Vec::new();
        let src = choose_source(
            Ok(vec![
                "1.0 host kernel: ufw#deny#x SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=23".into(),
            ]),
            || panic!("dmesg must not be consulted when the journal has lines"),
            &mut errors,
        );
        assert_eq!(kinds(&src), "journal");
    }

    #[test]
    fn a_failed_journal_falls_through_without_double_reporting() {
        let mut errors = Vec::new();
        let src = choose_source(
            Err("journalctl: not found".into()),
            || {
                Ok(vec![
                    "1.0 host kernel: ufw#deny#x SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=23".into(),
                ])
            },
            &mut errors,
        );
        assert_eq!(kinds(&src), "dmesg");
        // The journal error is surfaced, but not the "no source readable"
        // line, because dmesg did work.
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn both_sources_failing_reports_the_no_source_message() {
        let mut errors = Vec::new();
        let src = choose_source(
            Err("journalctl: denied".into()),
            || Err("dmesg: denied".into()),
            &mut errors,
        );
        assert_eq!(kinds(&src), "none");
        assert!(errors.iter().any(|e| e.contains("no kernel log source")));
    }

    #[test]
    fn both_sources_empty_is_quiet_not_an_error() {
        let mut errors = Vec::new();
        let src = choose_source(Ok(vec![]), || Ok(vec![]), &mut errors);
        assert_eq!(kinds(&src), "none");
        assert!(errors.is_empty());
    }

    #[test]
    fn icmp_type_is_captured() {
        let line = "1723400004.0 parrot kernel: ufw#deny#deny-inbound IN=eth0 OUT= SRC=203.0.113.8 DST=10.0.0.5 LEN=84 TTL=55 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1";
        let ev = parse_line(line, None).unwrap();
        assert_eq!(ev.proto, "ICMP");
        assert_eq!(ev.icmp_type, Some(8));
    }

    #[test]
    fn an_icmp_error_keeps_the_outer_packet_not_the_embedded_one() {
        // ICMP dest-unreachable carrying the offending UDP packet in brackets.
        // The event must describe the ICMP error (SRC=router, PROTO=ICMP),
        // not the embedded UDP header (DST=8.8.8.8, DPT=53).
        let line = "1723400005.0 parrot kernel: ufw#deny#deny-inbound IN=eth0 OUT= SRC=203.0.113.1 DST=10.0.0.5 LEN=120 TTL=64 PROTO=ICMP TYPE=3 CODE=3 [SRC=10.0.0.5 DST=8.8.8.8 LEN=60 TTL=63 PROTO=UDP SPT=51000 DPT=53 LEN=40]";
        let ev = parse_line(line, None).unwrap();
        assert_eq!(ev.src, "203.0.113.1");
        assert_eq!(
            ev.dst, "10.0.0.5",
            "embedded DST must not overwrite the outer"
        );
        assert_eq!(
            ev.proto, "ICMP",
            "embedded PROTO must not overwrite the outer"
        );
        assert_eq!(ev.icmp_type, Some(3));
        assert_eq!(
            ev.dpt, None,
            "the embedded DPT is a different packet's port"
        );
    }
}
