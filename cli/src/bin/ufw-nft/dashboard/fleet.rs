//! Multi-host fleet view — aggregate every host that publishes a compact
//! self-summary into a shared directory.
//!
//! Each host's console writes its own one-line summary to
//! `/var/lib/unified-firewall/fleet/<host>.json` (throttled). Point a sync tool
//! (or the daemon's fleet plane) at that directory across the fleet and this
//! console aggregates the lot: who is enforcing, who is under attack, who has
//! auto-response on, and who has gone silent. A single host sees itself; a
//! synced fleet sees everyone. No central server, no push — just files.

use std::sync::atomic::{AtomicU64, Ordering};

use ufw_shared::json::{self, Json, JsonWriter};

const DIR: &str = "/var/lib/unified-firewall/fleet";
/// A host is "stale" if its summary is older than this — likely offline.
const STALE_SECS: u64 = 120;
/// Don't rewrite our own summary more than this often.
const PUBLISH_EVERY_SECS: u64 = 15;

pub struct Host {
    pub hostname: String,
    pub generated_at: u64,
    pub enforced: bool,
    pub denied: u64,
    pub attackers: u64,
    pub contained: u64,
    pub autoresponse: bool,
    pub stale: bool,
}

/// Write this host's summary to the fleet directory, throttled so a busy poll
/// loop does not hammer the disk. Best-effort: failures are silent.
pub fn publish_self(
    hostname: &str,
    enforced: bool,
    denied: u64,
    attackers: u64,
    contained: u64,
    autoresponse: bool,
) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = crate::state::now_unix();
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < PUBLISH_EVERY_SECS {
        return;
    }
    LAST.store(now, Ordering::Relaxed);

    if std::fs::create_dir_all(DIR).is_err() {
        return;
    }
    let safe: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe = if safe.is_empty() { "host".into() } else { safe };

    let mut w = JsonWriter::with_capacity(256);
    w.begin_object();
    w.str_field("hostname", hostname);
    w.u64_field("generated_at", now);
    w.bool_field("enforced", enforced);
    w.u64_field("denied", denied);
    w.u64_field("attackers", attackers);
    w.u64_field("contained", contained);
    w.bool_field("autoresponse", autoresponse);
    w.end_object();
    let _ = std::fs::write(format!("{DIR}/{safe}.json"), w.finish());
}

/// Read and aggregate every host summary in the fleet directory.
pub fn snapshot() -> Vec<Host> {
    let now = crate::state::now_unix();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(DIR) else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(h) = parse_host(&text, now) {
            out.push(h);
        }
    }
    // Attackers first, then most-recently-seen.
    out.sort_by(|a, b| {
        b.attackers
            .cmp(&a.attackers)
            .then(b.generated_at.cmp(&a.generated_at))
    });
    out
}

fn parse_host(text: &str, now: u64) -> Option<Host> {
    let v = json::parse(text).ok()?;
    let hostname = v.get("hostname").and_then(Json::as_str)?.to_string();
    let generated_at = v.get("generated_at").and_then(Json::as_u64).unwrap_or(0);
    Some(Host {
        hostname,
        generated_at,
        enforced: v.get("enforced").and_then(Json::as_bool).unwrap_or(false),
        denied: v.get("denied").and_then(Json::as_u64).unwrap_or(0),
        attackers: v.get("attackers").and_then(Json::as_u64).unwrap_or(0),
        contained: v.get("contained").and_then(Json::as_u64).unwrap_or(0),
        autoresponse: v
            .get("autoresponse")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        stale: now.saturating_sub(generated_at) > STALE_SECS,
    })
}

/// The fleet page's JSON: the aggregate roll-up plus every host row.
pub fn fleet_json() -> String {
    let hosts = snapshot();
    let live = hosts.iter().filter(|h| !h.stale).count();
    let enforcing = hosts.iter().filter(|h| h.enforced && !h.stale).count();
    let attackers: u64 = hosts.iter().filter(|h| !h.stale).map(|h| h.attackers).sum();
    let denied: u64 = hosts.iter().filter(|h| !h.stale).map(|h| h.denied).sum();
    let contained: u64 = hosts.iter().filter(|h| !h.stale).map(|h| h.contained).sum();
    let autoresponse = hosts.iter().filter(|h| h.autoresponse && !h.stale).count();

    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.begin_object_field("totals");
    w.u64_field("hosts", hosts.len() as u64);
    w.u64_field("live", live as u64);
    w.u64_field("enforcing", enforcing as u64);
    w.u64_field("attackers", attackers);
    w.u64_field("denied", denied);
    w.u64_field("contained", contained);
    w.u64_field("autoresponse", autoresponse as u64);
    w.end_object();
    w.begin_array_field("hosts");
    for h in &hosts {
        w.begin_object();
        w.str_field("hostname", &h.hostname);
        w.u64_field("generated_at", h.generated_at);
        w.bool_field("enforced", h.enforced);
        w.u64_field("denied", h.denied);
        w.u64_field("attackers", h.attackers);
        w.u64_field("contained", h.contained);
        w.bool_field("autoresponse", h.autoresponse);
        w.bool_field("stale", h.stale);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_host_summary() {
        let now = 1_000_000;
        let h = parse_host(
            r#"{"hostname":"web-1","generated_at":999950,"enforced":true,"denied":42,"attackers":3,"contained":1,"autoresponse":true}"#,
            now,
        )
        .unwrap();
        assert_eq!(h.hostname, "web-1");
        assert_eq!(h.denied, 42);
        assert!(h.enforced && h.autoresponse);
        assert!(!h.stale); // 50s old < 120s
    }

    #[test]
    fn marks_old_hosts_stale() {
        let now = 1_000_000;
        let h = parse_host(r#"{"hostname":"old","generated_at":900000}"#, now).unwrap();
        assert!(h.stale); // 100_000s old
    }

    #[test]
    fn rejects_summary_without_hostname() {
        assert!(parse_host(r#"{"denied":5}"#, 0).is_none());
        assert!(parse_host("not json", 0).is_none());
    }
}
