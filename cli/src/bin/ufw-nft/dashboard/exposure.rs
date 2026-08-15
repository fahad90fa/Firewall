//! Server attack-surface analysis: what this host exposes inbound, and to whom.
//!
//! The events view answers "who is knocking"; this answers the prior question
//! "which doors are open at all". It reads the live inbound chain and, for
//! every rule that admits traffic, reports the port it opens and the source
//! scope it opens it to. A port open to the whole internet is a different
//! statement from the same port open to one management subnet, and the whole
//! point of the server-role policies (`policies/server/`) is to make that
//! difference explicit — so the dashboard shows it explicitly too.
//!
//! Same discipline as `attacks.rs`: heuristics that name their evidence, no
//! score that cannot be explained to the person reading it. The grade is a
//! sum of concrete findings, not a black box.

use super::ports;
use super::ruleset::Ruleset;

/// One exposed (or notably well-scoped) inbound surface.
pub struct Finding {
    /// "critical" | "high" | "medium" | "low" | "good".
    pub severity: String,
    pub port: Option<u16>,
    pub service: String,
    /// "any source" or the CIDR/host the rule scopes the source to.
    pub scope: String,
    pub title: String,
    pub detail: String,
    pub rule: String,
    pub packets: u64,
}

pub struct Exposure {
    /// "hardened" | "reasonable" | "exposed" | "unknown".
    pub grade: String,
    /// 0-100; 100 is nothing risky open to the world.
    pub score: u32,
    /// Ports admitted from any source.
    pub open_world: usize,
    /// Ports admitted only from a scoped source set.
    pub scoped: usize,
    pub findings: Vec<Finding>,
}

/// Administrative and data-tier ports that should essentially never be open to
/// the whole internet. Open to *any* source, each is a finding; scoped to a
/// source set, each is the recommended pattern and reads as `good`.
fn sensitivity(port: u16) -> Option<(&'static str, &'static str)> {
    // (severity-when-world-open, why)
    Some(match port {
        22 => ("high", "SSH grants a shell; exposed to the world it is the first thing credential-stuffing and brute-force tooling finds"),
        23 => ("critical", "Telnet is cleartext remote login; there is no safe way to expose it"),
        3389 => ("critical", "RDP exposed to the internet is the single most common ransomware entry point"),
        445 | 139 | 137 => ("critical", "SMB exposed to the internet is how network worms spread"),
        135 => ("high", "MS-RPC endpoint mapper exposed to the world is a lateral-movement surface"),
        5900..=5910 => ("high", "VNC exposed to the world is remote control, often unauthenticated"),
        5985 | 5986 => ("high", "WinRM exposed to the world is remote PowerShell execution"),
        3306 => ("high", "MySQL should be reachable from the app tier, not the internet"),
        5432 => ("high", "PostgreSQL should be reachable from the app tier, not the internet"),
        6379 => ("high", "Redis is frequently unauthenticated; exposed to the world it is an open data store"),
        27017 => ("high", "MongoDB exposed to the world is a recurring breach headline"),
        1433 => ("high", "MSSQL should be reachable from the app tier, not the internet"),
        9200 | 9300 => ("high", "Elasticsearch exposed to the world is an open, often unauthenticated index"),
        _ => return None,
    })
}

/// Ports whose exposure to the world is the host doing its job, not a mistake.
fn is_public_service(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 53 | 25 | 587 | 993 | 995)
}

/// Whether a rule admits (rather than blocks) the traffic it matches.
fn admits(verdict: &str) -> bool {
    matches!(verdict, "accept" | "continue" | "alert")
}

/// Pull the source scope out of matcher text: `ip saddr { 10.30.0.0/24 } …`
/// or `ip6 saddr …`. Absent means the rule matches any source.
fn source_scope(matchers: &str) -> Option<String> {
    let i = matchers.find("saddr")?;
    let tail = matchers[i + "saddr".len()..].trim_start();
    let tail = tail.strip_prefix("!=").unwrap_or(tail).trim_start();
    if let Some(rest) = tail.strip_prefix('{') {
        let inner = rest.find('}').map(|j| &rest[..j]).unwrap_or(rest);
        Some(inner.split(',').map(str::trim).collect::<Vec<_>>().join(", "))
    } else {
        Some(tail.split_whitespace().next().unwrap_or("").to_string())
    }
}

pub fn analyze(rs: &Ruleset) -> Exposure {
    if !rs.loaded {
        return Exposure {
            grade: "unknown".into(),
            score: 0,
            open_world: 0,
            scoped: 0,
            findings: Vec::new(),
        };
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut open_world = 0usize;
    let mut scoped = 0usize;
    let mut penalty = 0u32;

    for chain in &rs.chains {
        // Inbound only; the output chain is egress, a different question.
        if !chain.name.contains("input") {
            continue;
        }
        for r in &chain.rules {
            if !admits(&r.verdict) || r.dports.is_empty() {
                continue;
            }
            let scope = source_scope(&r.matchers);
            let world = scope.is_none();
            let scope_label = scope.clone().unwrap_or_else(|| "any source".into());

            for &port in &r.dports {
                let service = ports::label(port);
                if world {
                    open_world += 1;
                } else {
                    scoped += 1;
                }

                match sensitivity(port) {
                    Some((sev, why)) if world => {
                        penalty += match sev {
                            "critical" => 34,
                            "high" => 18,
                            _ => 8,
                        };
                        findings.push(Finding {
                            severity: sev.into(),
                            port: Some(port),
                            service: service.clone(),
                            scope: scope_label.clone(),
                            title: format!("{service} open to the world"),
                            detail: format!(
                                "{why}. Scope it to a management or application \
                                 network in policy, the way `policies/server/` does."
                            ),
                            rule: r.name.clone(),
                            packets: r.packets,
                        });
                    }
                    Some((_, _)) => {
                        // Sensitive but scoped: the recommended pattern.
                        findings.push(Finding {
                            severity: "good".into(),
                            port: Some(port),
                            service: service.clone(),
                            scope: scope_label.clone(),
                            title: format!("{service} scoped to {scope_label}"),
                            detail: format!(
                                "A sensitive service reachable only from {scope_label}, \
                                 not the whole network — this is the intended shape."
                            ),
                            rule: r.name.clone(),
                            packets: r.packets,
                        });
                    }
                    None if world && is_public_service(port) => {
                        findings.push(Finding {
                            severity: "low".into(),
                            port: Some(port),
                            service: service.clone(),
                            scope: scope_label.clone(),
                            title: format!("{service} open to the world"),
                            detail:
                                "A public-facing service; open to the internet is expected. \
                                 Ensure a WAF/edge sits in front for the application layer."
                                    .into(),
                            rule: r.name.clone(),
                            packets: r.packets,
                        });
                    }
                    None if world => {
                        penalty += 6;
                        findings.push(Finding {
                            severity: "medium".into(),
                            port: Some(port),
                            service: service.clone(),
                            scope: scope_label.clone(),
                            title: format!("{service} open to the world"),
                            detail:
                                "A non-standard port open to any source. Confirm it is a \
                                 service you mean to expose, and scope it if not."
                                    .into(),
                            rule: r.name.clone(),
                            packets: r.packets,
                        });
                    }
                    None => {
                        // Scoped, non-sensitive: unremarkable, not worth a row.
                    }
                }
            }
        }
    }

    // Most severe first, then by traffic seen.
    findings.sort_by(|a, b| {
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then(b.packets.cmp(&a.packets))
    });

    let score = 100u32.saturating_sub(penalty);
    let grade = if !rs.loaded {
        "unknown"
    } else if score >= 90 {
        "hardened"
    } else if score >= 65 {
        "reasonable"
    } else {
        "exposed"
    };

    Exposure {
        grade: grade.into(),
        score,
        open_world,
        scoped,
        findings,
    }
}

/// Lower rank sorts first: worst finding at the top.
fn sev_rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "good" => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::ruleset;

    fn rs_from(nft: &str) -> Ruleset {
        Ruleset {
            loaded: true,
            chains: ruleset::parse(nft),
            error: None,
        }
    }

    const WEB: &str = r#"table inet ufw {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport { 80, 443 } counter packets 5000 bytes 400000 accept comment "allow-web-inbound"
        ip saddr { 10.20.0.0/24 } tcp dport { 22 } counter packets 40 bytes 3000 accept comment "allow-ssh-admin"
    }
    chain output {
        type filter hook output priority 0; policy drop;
        tcp dport { 5432 } counter packets 9 bytes 500 accept comment "web-app-to-database"
    }
}"#;

    const RISKY: &str = r#"table inet ufw {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport { 3389 } counter packets 12 bytes 700 accept comment "allow-rdp"
        tcp dport { 22 } counter packets 300 bytes 20000 accept comment "allow-ssh-anywhere"
    }
}"#;

    #[test]
    fn a_well_scoped_server_grades_well_and_praises_the_scoped_admin_port() {
        let e = analyze(&rs_from(WEB));
        assert_eq!(e.grade, "hardened", "score was {}", e.score);
        // 80 and 443 world-open (public, low), 22 scoped to management (good).
        assert!(e.findings.iter().any(|f| f.port == Some(22) && f.severity == "good"));
        assert!(e.findings.iter().any(|f| f.port == Some(443) && f.severity == "low"));
        // The output chain (postgres egress) is not an inbound exposure.
        assert!(!e.findings.iter().any(|f| f.port == Some(5432)));
    }

    #[test]
    fn rdp_and_ssh_open_to_the_world_are_flagged_and_tank_the_grade() {
        let e = analyze(&rs_from(RISKY));
        assert_eq!(e.grade, "exposed", "score was {}", e.score);
        let rdp = e.findings.iter().find(|f| f.port == Some(3389)).unwrap();
        assert_eq!(rdp.severity, "critical");
        assert_eq!(rdp.scope, "any source");
        // Worst finding sorts first.
        assert_eq!(e.findings[0].severity, "critical");
        assert!(e.open_world >= 2);
    }

    #[test]
    fn an_unloaded_ruleset_is_unknown_not_a_false_all_clear() {
        let e = analyze(&Ruleset {
            loaded: false,
            chains: Vec::new(),
            error: None,
        });
        assert_eq!(e.grade, "unknown");
        assert!(e.findings.is_empty());
    }

    #[test]
    fn source_scope_reads_a_cidr_set() {
        assert_eq!(
            source_scope("ip saddr { 10.30.0.0/24 } tcp dport { 5432 }").as_deref(),
            Some("10.30.0.0/24")
        );
        assert_eq!(source_scope("tcp dport { 80 }"), None);
    }
}
