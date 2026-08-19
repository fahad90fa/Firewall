//! Best-effort telemetry export for the read-only console.
//!
//! The `ufw-nft` dashboard reads the kernel table and `/proc` directly and
//! never talks to the daemon over the network. So that it can still surface the
//! daemon-only signals — cross-host correlations, egress anomalies, fleet
//! rollout, signature revision — the daemon periodically writes a compact
//! status file into the project's state directory, which the console reads the
//! same best-effort way it reads apply-time policy metadata.
//!
//! Everything here is best-effort: a write error is ignored and never touches
//! enforcement. The file is written atomically (temp + rename) so the console
//! never observes a half-written document.

use std::sync::Arc;
use std::time::Duration;

use ufw_shared::json::JsonWriter;

use crate::state::DaemonState;

/// Compact daemon status, beside the console's own `ufw-nft-state.json`.
pub const STATUS_PATH: &str = "/var/lib/unified-firewall/ufw-daemon-status.json";
/// Where `ufw-waf` writes its request/block counters.
pub const WAF_STATUS_PATH: &str = "/var/lib/unified-firewall/ufw-waf-status.json";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `body` to `path` atomically: a temp file in the same directory, then a
/// rename, so a reader never sees a partially-written document.
pub fn atomic_write(path: &str, body: &str) -> std::io::Result<()> {
    let p = std::path::Path::new(path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

/// The compact status the console consumes. The full status and fleet payloads
/// are embedded so the console can pull whatever it needs (correlations,
/// anomalies, fleet membership) from one file, without the daemon and console
/// having to agree on a second, hand-maintained schema.
pub fn compact_status(state: &DaemonState) -> String {
    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.str_field("schema", "ufw-daemon-status/1");
    w.u64_field("updated_at", now_unix());
    w.u64_field("revision", state.active_revision());
    w.u64_field("rules", state.rule_count() as u64);
    w.u64_field("signature_revision", state.signature_revision());
    w.raw_field("status", &state.status_json());
    w.raw_field("fleet", &state.fleet_status_json());
    w.end_object();
    w.finish()
}

/// Spawn a thread that writes [`compact_status`] to [`STATUS_PATH`] every
/// `period` until the daemon shuts down, with one final write on the way out so
/// the console shows the last known state. The thread polls the shutdown flag in
/// short slices so it exits promptly.
pub fn spawn(state: Arc<DaemonState>, period: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let slice = Duration::from_millis(250);
        while !state.is_shutting_down() {
            let _ = atomic_write(STATUS_PATH, &compact_status(&state));
            let mut left = period;
            while left > Duration::ZERO && !state.is_shutting_down() {
                let s = left.min(slice);
                std::thread::sleep(s);
                left = left.saturating_sub(s);
            }
        }
        let _ = atomic_write(STATUS_PATH, &compact_status(&state));
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_and_replaces() {
        let path = std::env::temp_dir()
            .join(format!("ufw-tel-{}.json", std::process::id()))
            .to_str()
            .unwrap()
            .to_string();
        atomic_write(&path, "{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":1}");
        // A second write fully replaces the first — no leftover bytes.
        atomic_write(&path, "{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":2}");
        // The temp file is gone (renamed, not left behind).
        assert!(!std::path::Path::new(&format!("{path}.tmp.{}", std::process::id())).exists());
        let _ = std::fs::remove_file(&path);
    }
}
