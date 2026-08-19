//! Best-effort read of the daemon's and `ufw-waf`'s telemetry files.
//!
//! The daemon and `ufw-waf` publish compact status files into the project's
//! state directory (see `ufw_daemon::telemetry`). This read-only console reads
//! them the same best-effort way it reads apply-time policy metadata: present,
//! parseable and fresh → the "ready" defense layers light up with live counts;
//! absent, stale or unreadable → the console degrades to what the kernel alone
//! can tell it, and the layers stay "ready". Enforcement never depends on this.

use ufw_shared::json::{self, Json, JsonWriter};

const DAEMON_STATUS: &str = "/var/lib/unified-firewall/ufw-daemon-status.json";
const WAF_STATUS: &str = "/var/lib/unified-firewall/ufw-waf-status.json";
/// Telemetry older than this is treated as stale — the writer likely died, and
/// a dead daemon must not leave its layers showing "active" forever.
const STALE_SECS: u64 = 30;

/// The `daemon` object the console embeds into `/api/state`.
pub fn read_json() -> String {
    let now = crate::state::now_unix();
    let daemon = read_parsed(DAEMON_STATUS);
    let waf = read_parsed(WAF_STATUS);
    build_json(daemon.as_ref(), waf.as_ref(), now)
}

fn read_parsed(path: &str) -> Option<Json> {
    let text = std::fs::read_to_string(path).ok()?;
    json::parse(&text).ok()
}

fn fresh(v: &Json, now: u64) -> bool {
    v.get("updated_at")
        .and_then(Json::as_u64)
        .map(|u| now.saturating_sub(u) <= STALE_SECS)
        .unwrap_or(false)
}

fn u(v: &Json, k: &str) -> u64 {
    v.get(k).and_then(Json::as_u64).unwrap_or(0)
}

fn build_json(daemon: Option<&Json>, waf: Option<&Json>, now: u64) -> String {
    let mut w = JsonWriter::with_capacity(512);
    w.begin_object();
    match daemon.filter(|v| fresh(v, now)) {
        Some(v) => {
            w.bool_field("available", true);
            w.u64_field("revision", u(v, "revision"));
            w.u64_field("rules", u(v, "rules"));
            w.u64_field("signature_revision", u(v, "signature_revision"));
            let logging = v.get("status").and_then(|s| s.get("logging"));
            let lg = |k: &str| {
                logging
                    .and_then(|l| l.get(k))
                    .and_then(Json::as_u64)
                    .unwrap_or(0)
            };
            w.u64_field("correlations", lg("correlations"));
            w.u64_field("anomalies", lg("anomalies"));
            let fleet = v.get("fleet");
            w.bool_field(
                "fleet_enabled",
                fleet
                    .and_then(|f| f.get("enabled"))
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
            );
            w.u64_field(
                "fleet_members",
                fleet
                    .and_then(|f| f.get("members"))
                    .and_then(Json::as_u64)
                    .unwrap_or(0),
            );
        }
        None => {
            w.bool_field("available", false);
        }
    }
    match waf.filter(|v| fresh(v, now)) {
        Some(v) => {
            w.bool_field("waf_available", true);
            w.u64_field("waf_requests", u(v, "requests"));
            w.u64_field("waf_blocked", u(v, "blocked"));
        }
        None => {
            w.bool_field("waf_available", false);
        }
    }
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        json::parse(s).unwrap()
    }

    #[test]
    fn fresh_daemon_and_waf_light_up_with_counts() {
        let d = parse(
            r#"{"updated_at":1000,"revision":7,"rules":42,"signature_revision":3,
                "status":{"logging":{"correlations":5,"anomalies":2}},
                "fleet":{"enabled":true,"members":4}}"#,
        );
        let waf = parse(r#"{"updated_at":1000,"requests":900,"blocked":12}"#);
        let out = build_json(Some(&d), Some(&waf), 1010); // 10s old — fresh
        let v = parse(&out);
        assert_eq!(v.get("available").and_then(Json::as_bool), Some(true));
        assert_eq!(u(&v, "correlations"), 5);
        assert_eq!(u(&v, "anomalies"), 2);
        assert_eq!(u(&v, "fleet_members"), 4);
        assert_eq!(v.get("fleet_enabled").and_then(Json::as_bool), Some(true));
        assert_eq!(v.get("waf_available").and_then(Json::as_bool), Some(true));
        assert_eq!(u(&v, "waf_blocked"), 12);
    }

    #[test]
    fn stale_telemetry_is_treated_as_unavailable() {
        let d = parse(r#"{"updated_at":1000,"revision":7}"#);
        let out = build_json(Some(&d), None, 2000); // 1000s old — stale
        let v = parse(&out);
        assert_eq!(v.get("available").and_then(Json::as_bool), Some(false));
        assert_eq!(v.get("waf_available").and_then(Json::as_bool), Some(false));
    }

    #[test]
    fn missing_files_report_unavailable_not_a_crash() {
        let v = parse(&build_json(None, None, 100));
        assert_eq!(v.get("available").and_then(Json::as_bool), Some(false));
        assert_eq!(v.get("waf_available").and_then(Json::as_bool), Some(false));
    }
}
