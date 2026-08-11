//! Turn a pile of denied packets into a story about who is doing what.
//!
//! Heuristics, deliberately simple and explainable: every classification
//! names its evidence (counts, ports, time span) and says in plain words
//! what the pattern usually means and why the firewall stopped it. No
//! machine learning, no scores that cannot be explained to the person
//! reading them at 2am.

use std::collections::{BTreeMap, BTreeSet};

use super::events::Event;
use super::ports;

#[derive(Debug)]
pub struct Attack {
    /// The remote address driving the pattern (or this host, for egress).
    pub src: String,
    /// Stable machine tag: "port-scan", "rdp-vnc-probe", …
    pub kind: String,
    /// "critical" | "high" | "medium" | "low" | "info".
    pub severity: String,
    pub title: String,
    /// The plain-words explanation of what happened and why it was blocked.
    pub detail: String,
    pub count: usize,
    /// Human-labeled ports involved, e.g. "23 (telnet)".
    pub ports: Vec<String>,
    pub first_ts: f64,
    pub last_ts: f64,
    /// The rules that produced the evidence.
    pub rules: Vec<String>,
}

const SCAN_DISTINCT_PORTS: usize = 10;
const SWEEP_DISTINCT_PORTS: usize = 4;
const HAMMER_SINGLE_PORT: usize = 12;
const ICMP_FLOOD: usize = 60;

pub fn classify(events: &[Event]) -> Vec<Attack> {
    let mut out = Vec::new();

    // --- Inbound denials, grouped by source ------------------------------
    let mut inbound: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for e in events {
        if e.action == "deny" && e.dir == "in" && !e.src.is_empty() {
            inbound.entry(e.src.as_str()).or_default().push(e);
        }
    }

    for (src, evs) in &inbound {
        let dports: BTreeSet<u16> = evs.iter().filter_map(|e| e.dpt).collect();
        let span = time_span(evs);
        let rules = rule_names(evs);
        let icmp = evs.iter().filter(|e| e.proto.starts_with("ICMP")).count();
        let mk =
            |kind: &str, severity: &str, title: String, detail: String, ports: &[u16]| Attack {
                src: src.to_string(),
                kind: kind.into(),
                severity: severity.into(),
                title,
                detail,
                count: evs.len(),
                ports: label_ports(ports),
                first_ts: span.0,
                last_ts: span.1,
                rules: rules.clone(),
            };

        // Port scan: one source walking many distinct ports. The single
        // strongest signal there is; everything below refines it.
        if dports.len() >= SCAN_DISTINCT_PORTS {
            let sample: Vec<u16> = dports.iter().copied().take(16).collect();
            out.push(mk(
                "port-scan",
                "high",
                format!("Port scan from {src}"),
                format!(
                    "{src} probed {} different ports in {}. This is reconnaissance: an \
                     attacker mapping which services this machine runs before choosing \
                     an exploit. Every probe was dropped before reaching a service.",
                    dports.len(),
                    span_words(span),
                ),
                &sample,
            ));
        } else if dports.len() >= SWEEP_DISTINCT_PORTS {
            let sample: Vec<u16> = dports.iter().copied().collect();
            out.push(mk(
                "service-sweep",
                "medium",
                format!("Service sweep from {src}"),
                format!(
                    "{src} tried {} specific ports — a targeted check for particular \
                     services rather than a full scan. All attempts were dropped.",
                    dports.len(),
                ),
                &sample,
            ));
        }

        // Named-service patterns. These can coexist with the scan finding:
        // a scan that keeps returning to RDP is worth both lines.
        for (kind, severity, set, title, why) in service_patterns() {
            let hits: Vec<&&Event> = evs
                .iter()
                .filter(|e| e.dpt.map(|p| set.contains(&p)).unwrap_or(false))
                .collect();
            let hit_ports: BTreeSet<u16> = hits.iter().filter_map(|e| e.dpt).collect();
            if hits.len() >= 3 && !hit_ports.is_empty() {
                let ports_v: Vec<u16> = hit_ports.iter().copied().collect();
                let mut a = mk(
                    kind,
                    severity,
                    format!("{title} from {src}"),
                    format!(
                        "{src} made {} blocked attempts on {}. {}",
                        hits.len(),
                        label_ports(&ports_v).join(", "),
                        why
                    ),
                    &ports_v,
                );
                a.count = hits.len();
                out.push(a);
            }
        }

        // One port, hammered: brute force against a single service.
        let mut per_port: BTreeMap<u16, usize> = BTreeMap::new();
        for e in evs.iter() {
            if let Some(p) = e.dpt {
                *per_port.entry(p).or_default() += 1;
            }
        }
        for (port, n) in per_port {
            if n >= HAMMER_SINGLE_PORT && dports.len() < SWEEP_DISTINCT_PORTS {
                // Both the count and the time span describe this port's hits,
                // not the source's whole activity, so the sentence's numbers
                // are all about the same set of packets.
                let port_evs: Vec<&&Event> = evs.iter().filter(|e| e.dpt == Some(port)).collect();
                let port_span = time_span_ref(&port_evs);
                let mut a = mk(
                    "brute-force",
                    "high",
                    format!("Repeated attack on {} from {src}", ports::label(port)),
                    format!(
                        "{src} hit port {} {n} times in {}. Repeated connections to one \
                         blocked service are usually credential guessing or an exploit \
                         being retried; none of them got through.",
                        ports::label(port),
                        span_words(port_span),
                    ),
                    &[port],
                );
                a.count = n;
                a.first_ts = port_span.0;
                a.last_ts = port_span.1;
                out.push(a);
            }
        }

        if icmp >= ICMP_FLOOD {
            let mut a = mk(
                "icmp-flood",
                "medium",
                format!("ICMP flood from {src}"),
                format!(
                    "{src} sent {icmp} blocked ICMP packets — ping sweeping at best, a \
                     flood at worst."
                ),
                &[],
            );
            // The ICMP packet count, not the source's total across all protocols.
            a.count = icmp;
            out.push(a);
        }
    }

    // --- Outbound denials: something on THIS host tried to leave ----------
    let mut outbound: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for e in events {
        if e.action == "deny" && e.dir == "out" {
            outbound
                .entry(e.rule.as_deref().unwrap_or("egress"))
                .or_default()
                .push(e);
        }
    }
    for (rule, evs) in &outbound {
        let span = time_span(evs);
        let dports: BTreeSet<u16> = evs.iter().filter_map(|e| e.dpt).collect();
        let dsts: BTreeSet<&str> = evs.iter().map(|e| e.dst.as_str()).collect();
        let ports_v: Vec<u16> = dports.iter().copied().take(16).collect();
        out.push(Attack {
            src: "this host".into(),
            kind: "blocked-egress".into(),
            severity: "high".into(),
            title: format!("Outbound traffic blocked by `{rule}`"),
            detail: format!(
                "A process on this machine tried {} outbound connection(s) to {} \
                 destination(s) that the policy forbids. Blocked egress is worth \
                 investigating: it is how exfiltration, worms, and misconfigured \
                 software look from the firewall's seat.",
                evs.len(),
                dsts.len(),
            ),
            count: evs.len(),
            ports: label_ports(&ports_v),
            first_ts: span.0,
            last_ts: span.1,
            rules: vec![rule.to_string()],
        });
    }

    // --- Alerts: traffic the policy wants inventoried ---------------------
    let alerts: Vec<&Event> = events.iter().filter(|e| e.action == "alert").collect();
    if !alerts.is_empty() {
        let span = time_span(&alerts);
        let dports: BTreeSet<u16> = alerts.iter().filter_map(|e| e.dpt).collect();
        let ports_v: Vec<u16> = dports.iter().copied().take(16).collect();
        out.push(Attack {
            src: "this host".into(),
            kind: "audited-traffic".into(),
            severity: "info".into(),
            title: "Traffic flagged for audit".into(),
            detail: format!(
                "{} packet(s) matched the policy's alert rules — traffic that is \
                 allowed for now but that a finished policy should name explicitly.",
                alerts.len(),
            ),
            count: alerts.len(),
            ports: label_ports(&ports_v),
            first_ts: span.0,
            last_ts: span.1,
            rules: rule_names(&alerts),
        });
    }

    // Severity first, then volume, so the top of the list is the headline.
    out.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(b.count.cmp(&a.count))
    });
    out
}

type Pattern = (
    &'static str,
    &'static str,
    &'static [u16],
    &'static str,
    &'static str,
);

fn service_patterns() -> &'static [Pattern] {
    &[
        (
            "rdp-vnc-probe",
            "high",
            &[
                3389, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910,
            ],
            "Remote-desktop break-in attempts",
            "RDP and VNC are the front door for ransomware crews; scanning for them \
             precedes most intrusions that make the news. The policy drops them on sight.",
        ),
        (
            "smb-probe",
            "high",
            &[135, 137, 138, 139, 445],
            "SMB/RPC lateral-movement probing",
            "Windows file-sharing ports are how worms (WannaCry, NotPetya) and \
             hash-relay attacks spread between machines. Nothing legitimate probes \
             them from outside.",
        ),
        (
            "ssh-probe",
            "medium",
            &[22],
            "SSH intrusion attempts",
            "Automated SSH credential guessing runs continuously across the whole \
             internet; these attempts died at the packet filter.",
        ),
        (
            "cleartext-probe",
            "medium",
            &[21, 23, 69, 79, 512, 513, 514],
            "Legacy cleartext-service probing",
            "Telnet, FTP, TFTP and the r-services authenticate in cleartext; botnets \
             scan for them to harvest credentials and conscript devices.",
        ),
        (
            "database-probe",
            "high",
            &[1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
            "Database attack attempts",
            "Exposed databases are ransomed or drained within hours; attackers scan \
             for them methodically. The policy refuses them at the perimeter.",
        ),
    ]
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn time_span(evs: &[&Event]) -> (f64, f64) {
    span_of(evs.iter().map(|e| e.ts))
}

/// Same, for a subset already collected as `&&Event` (a filter over a
/// per-source slice).
fn time_span_ref(evs: &[&&Event]) -> (f64, f64) {
    span_of(evs.iter().map(|e| e.ts))
}

fn span_of(times: impl Iterator<Item = f64>) -> (f64, f64) {
    let mut first = f64::MAX;
    let mut last = 0.0f64;
    for ts in times {
        if ts < first {
            first = ts;
        }
        if ts > last {
            last = ts;
        }
    }
    if first > last {
        (0.0, 0.0)
    } else {
        (first, last)
    }
}

fn span_words(span: (f64, f64)) -> String {
    let secs = (span.1 - span.0).max(0.0) as u64;
    if secs < 120 {
        format!("{secs}s")
    } else if secs < 7200 {
        format!("{} minutes", secs / 60)
    } else {
        format!("{} hours", secs / 3600)
    }
}

fn rule_names(evs: &[&Event]) -> Vec<String> {
    let set: BTreeSet<&str> = evs.iter().filter_map(|e| e.rule.as_deref()).collect();
    set.into_iter().map(str::to_string).collect()
}

fn label_ports(ports: &[u16]) -> Vec<String> {
    ports.iter().map(|p| ports::label(*p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(src: &str, dpt: u16, ts: f64) -> Event {
        Event {
            ts,
            action: "deny".into(),
            rule: Some("deny-inbound".into()),
            dir: "in".into(),
            iface: "eth0".into(),
            src: src.into(),
            dst: "10.0.0.5".into(),
            proto: "TCP".into(),
            spt: Some(40000),
            dpt: Some(dpt),
            len: Some(60),
            ttl: Some(52),
            flags: vec!["SYN".into()],
            icmp_type: None,
        }
    }

    #[test]
    fn many_distinct_ports_reads_as_a_port_scan() {
        let evs: Vec<Event> = (0..20)
            .map(|i| deny("203.0.113.7", 1000 + i, i as f64))
            .collect();
        let attacks = classify(&evs);
        assert!(attacks.iter().any(|a| a.kind == "port-scan"), "{attacks:?}");
        let scan = attacks.iter().find(|a| a.kind == "port-scan").unwrap();
        assert_eq!(scan.src, "203.0.113.7");
        assert_eq!(scan.severity, "high");
        assert!(scan.detail.contains("20 different ports"));
    }

    #[test]
    fn rdp_hammering_is_named_as_remote_desktop_attack() {
        let evs: Vec<Event> = (0..6)
            .map(|i| deny("198.51.100.3", 3389, i as f64))
            .collect();
        let attacks = classify(&evs);
        assert!(
            attacks.iter().any(|a| a.kind == "rdp-vnc-probe"),
            "{attacks:?}"
        );
    }

    #[test]
    fn a_single_hammered_port_reads_as_brute_force() {
        let evs: Vec<Event> = (0..15)
            .map(|i| deny("198.51.100.4", 8443, i as f64))
            .collect();
        let attacks = classify(&evs);
        let bf = attacks
            .iter()
            .find(|a| a.kind == "brute-force")
            .unwrap_or_else(|| panic!("{attacks:?}"));
        // The count is this port's hits, matching the "hit port X 15 times"
        // detail — not a larger source total.
        assert_eq!(bf.count, 15);
    }

    #[test]
    fn icmp_flood_count_is_the_icmp_packets_only() {
        // 65 ICMP denials plus a handful of TCP denials from the same source:
        // the flood finding must count the ICMP packets, not the total.
        let mut evs: Vec<Event> = (0..65)
            .map(|i| {
                let mut e = deny("203.0.113.50", 0, i as f64);
                e.proto = "ICMP".into();
                e.dpt = None;
                e.icmp_type = Some(8);
                e
            })
            .collect();
        for i in 0..5 {
            evs.push(deny("203.0.113.50", 3389, 100.0 + i as f64));
        }
        let attacks = classify(&evs);
        let flood = attacks
            .iter()
            .find(|a| a.kind == "icmp-flood")
            .unwrap_or_else(|| panic!("{attacks:?}"));
        assert_eq!(flood.count, 65);
    }

    #[test]
    fn blocked_egress_is_reported_from_this_host() {
        let mut e = deny("10.0.0.5", 445, 1.0);
        e.dir = "out".into();
        e.rule = Some("deny-smb-egress".into());
        e.dst = "203.0.113.44".into();
        let attacks = classify(&[e]);
        let egress = attacks.iter().find(|a| a.kind == "blocked-egress").unwrap();
        assert_eq!(egress.src, "this host");
        assert!(egress.title.contains("deny-smb-egress"));
    }

    #[test]
    fn quiet_logs_classify_to_nothing() {
        assert!(classify(&[]).is_empty());
        let one = vec![deny("203.0.113.9", 23, 1.0)];
        // One probe on one port: below every threshold.
        assert!(classify(&one).is_empty());
    }

    #[test]
    fn findings_sort_most_severe_first() {
        let mut evs: Vec<Event> = (0..20)
            .map(|i| deny("203.0.113.7", 1000 + i, i as f64))
            .collect();
        let mut alert = deny("10.0.0.5", 5432, 30.0);
        alert.action = "alert".into();
        alert.dir = "out".into();
        evs.push(alert);
        let attacks = classify(&evs);
        assert!(attacks.len() >= 2);
        assert!(
            severity_rank(&attacks[0].severity) <= severity_rank(&attacks.last().unwrap().severity)
        );
    }
}
