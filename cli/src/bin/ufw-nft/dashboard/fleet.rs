//! Multi-host fleet view — aggregate every host that publishes a compact
//! self-summary into a shared directory.
//!
//! Each host's console writes its own one-line summary to
//! `/var/lib/unified-firewall/fleet/<host>.json` (throttled). Point a sync tool
//! (or the daemon's fleet plane) at that directory across the fleet and this
//! console aggregates the lot: who is enforcing, who is under attack, who has
//! auto-response on, and who has gone silent. A single host sees itself; a
//! synced fleet sees everyone. No central server, no push — just files.
//!
//! # Integrity
//!
//! A shared directory is a shared trust boundary: any host that can write its
//! own summary can, by default, overwrite another host's. So a summary may be
//! authenticated. If `/etc/unified-firewall/fleet-key` exists, each published
//! summary carries an `HMAC-SHA256` (`ufw_shared::hash`, the same
//! length-extension-resistant primitive the daemon's signed bundles use) over
//! its fields, keyed by that secret. On read, a summary is marked `verified`,
//! `tampered` (a MAC that does not check — surfaced, never silently trusted or
//! dropped), or `unsigned` (no key configured, today's behavior unchanged).
//!
//! The honest limit, stated the same way the daemon's fleet module states it: a
//! shared HMAC key means every host can forge every other host's summary — it
//! authenticates "a fleet member wrote this", not "*that* host wrote this".
//! Per-host public-key identity needs a real signature (Ed25519) and belongs
//! behind the `tls` feature's vetted crypto, not a hand-rolled one. This closes
//! the outside-tamper gap; it does not make one fleet member trust another less.

use std::sync::atomic::{AtomicU64, Ordering};

use ufw_shared::hash::{self, constant_time_eq, hmac_sha256};
use ufw_shared::json::{self, Json, JsonWriter};

const DIR: &str = "/var/lib/unified-firewall/fleet";
/// Optional shared fleet key; its presence turns on summary authentication.
const KEY_PATH: &str = "/etc/unified-firewall/fleet-key";
/// A host is "stale" if its summary is older than this — likely offline.
const STALE_SECS: u64 = 120;
/// Don't rewrite our own summary more than this often.
const PUBLISH_EVERY_SECS: u64 = 15;

/// A published summary's authentication state, as this reader sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Integrity {
    /// No fleet key configured on this reader — summaries are taken as-is.
    Unsigned,
    /// A MAC was present and verified against the configured key.
    Verified,
    /// A MAC was present (or required) and did not verify: forged, corrupted,
    /// or signed with a different key. Surfaced, not silently trusted.
    Tampered,
}

impl Integrity {
    fn as_str(self) -> &'static str {
        match self {
            Integrity::Unsigned => "unsigned",
            Integrity::Verified => "verified",
            Integrity::Tampered => "tampered",
        }
    }
}

pub struct Host {
    pub hostname: String,
    pub generated_at: u64,
    pub enforced: bool,
    pub denied: u64,
    pub attackers: u64,
    pub contained: u64,
    pub autoresponse: bool,
    pub stale: bool,
    pub integrity: Integrity,
}

/// Read the optional shared fleet key. Absent (the default) means summaries are
/// published and read unauthenticated, exactly as before this was added.
fn fleet_key() -> Option<Vec<u8>> {
    let raw = std::fs::read(KEY_PATH).ok()?;
    // Trim a trailing newline an editor adds; an all-whitespace file is no key.
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)?;
    Some(raw[..end].to_vec())
}

/// The authenticated fields of a published summary, in one place so the signer
/// (publish) and the verifier (read) cover exactly the same bytes.
struct Summary<'a> {
    hostname: &'a str,
    generated_at: u64,
    enforced: bool,
    denied: u64,
    attackers: u64,
    contained: u64,
    autoresponse: bool,
}

/// The bytes a summary's MAC covers. Length-prefixed and domain-separated so no
/// two distinct summaries share a signing input (the same discipline the
/// daemon's bundle signer uses).
fn signing_input(s: &Summary) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.hostname.len() + 64);
    out.extend_from_slice(b"ufw-fleet-summary-v1");
    out.extend_from_slice(&(s.hostname.len() as u64).to_le_bytes());
    out.extend_from_slice(s.hostname.as_bytes());
    out.extend_from_slice(&s.generated_at.to_le_bytes());
    out.push(s.enforced as u8);
    out.extend_from_slice(&s.denied.to_le_bytes());
    out.extend_from_slice(&s.attackers.to_le_bytes());
    out.extend_from_slice(&s.contained.to_le_bytes());
    out.push(s.autoresponse as u8);
    out
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

    let mut w = JsonWriter::with_capacity(320);
    w.begin_object();
    w.str_field("hostname", hostname);
    w.u64_field("generated_at", now);
    w.bool_field("enforced", enforced);
    w.u64_field("denied", denied);
    w.u64_field("attackers", attackers);
    w.u64_field("contained", contained);
    w.bool_field("autoresponse", autoresponse);
    // Authenticate the summary if a shared fleet key is configured, so a peer
    // sharing the directory cannot forge or alter this host's row undetected.
    if let Some(key) = fleet_key() {
        let mac = hmac_sha256(
            &key,
            &signing_input(&Summary {
                hostname,
                generated_at: now,
                enforced,
                denied,
                attackers,
                contained,
                autoresponse,
            }),
        );
        w.str_field("mac", &hash::hex(&mac));
    }
    w.end_object();
    let _ = std::fs::write(format!("{DIR}/{safe}.json"), w.finish());
}

/// Read and aggregate every host summary in the fleet directory.
pub fn snapshot() -> Vec<Host> {
    let now = crate::state::now_unix();
    let key = fleet_key();
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
        if let Some(h) = parse_host(&text, now, key.as_deref()) {
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

/// Decide a summary's integrity given the reader's optional key and the MAC the
/// summary carried. Pure, so the trust decision is unit-tested directly.
fn check_integrity(key: Option<&[u8]>, mac_hex: Option<&str>, s: &Summary) -> Integrity {
    let Some(key) = key else {
        // No key configured: authentication is off; take summaries as-is.
        return Integrity::Unsigned;
    };
    // A key is configured, so a summary must carry a MAC that verifies.
    let Some(mac_hex) = mac_hex else {
        return Integrity::Tampered;
    };
    let Some(mac) = hash::unhex(mac_hex) else {
        return Integrity::Tampered;
    };
    let expected = hmac_sha256(key, &signing_input(s));
    if constant_time_eq(&expected, &mac) {
        Integrity::Verified
    } else {
        Integrity::Tampered
    }
}

fn parse_host(text: &str, now: u64, key: Option<&[u8]>) -> Option<Host> {
    let v = json::parse(text).ok()?;
    let hostname = v.get("hostname").and_then(Json::as_str)?.to_string();
    let generated_at = v.get("generated_at").and_then(Json::as_u64).unwrap_or(0);
    let enforced = v.get("enforced").and_then(Json::as_bool).unwrap_or(false);
    let denied = v.get("denied").and_then(Json::as_u64).unwrap_or(0);
    let attackers = v.get("attackers").and_then(Json::as_u64).unwrap_or(0);
    let contained = v.get("contained").and_then(Json::as_u64).unwrap_or(0);
    let autoresponse = v
        .get("autoresponse")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let integrity = check_integrity(
        key,
        v.get("mac").and_then(Json::as_str),
        &Summary {
            hostname: &hostname,
            generated_at,
            enforced,
            denied,
            attackers,
            contained,
            autoresponse,
        },
    );
    Some(Host {
        hostname,
        generated_at,
        enforced,
        denied,
        attackers,
        contained,
        autoresponse,
        stale: now.saturating_sub(generated_at) > STALE_SECS,
        integrity,
    })
}

/// The fleet page's JSON: the aggregate roll-up plus every host row.
///
/// A summary that fails authentication is listed (with its `tampered` state) but
/// excluded from the trusted roll-up: a forged row must not inflate "enforcing"
/// or hide under "denied". When no fleet key is configured every summary is
/// `unsigned` and the roll-up is exactly what it was before signing existed.
pub fn fleet_json() -> String {
    let hosts = snapshot();
    let signing_on = fleet_key().is_some();
    // The roll-up counts only summaries we can trust: live, and not tampered.
    let trusted = |h: &&Host| !h.stale && h.integrity != Integrity::Tampered;
    let live = hosts.iter().filter(trusted).count();
    let enforcing = hosts.iter().filter(|h| h.enforced && trusted(h)).count();
    let attackers: u64 = hosts.iter().filter(trusted).map(|h| h.attackers).sum();
    let denied: u64 = hosts.iter().filter(trusted).map(|h| h.denied).sum();
    let contained: u64 = hosts.iter().filter(trusted).map(|h| h.contained).sum();
    let autoresponse = hosts
        .iter()
        .filter(|h| h.autoresponse && trusted(h))
        .count();
    let tampered = hosts
        .iter()
        .filter(|h| h.integrity == Integrity::Tampered)
        .count();
    let verified = hosts
        .iter()
        .filter(|h| h.integrity == Integrity::Verified)
        .count();

    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.bool_field("signing", signing_on);
    w.begin_object_field("totals");
    w.u64_field("hosts", hosts.len() as u64);
    w.u64_field("live", live as u64);
    w.u64_field("enforcing", enforcing as u64);
    w.u64_field("attackers", attackers);
    w.u64_field("denied", denied);
    w.u64_field("contained", contained);
    w.u64_field("autoresponse", autoresponse as u64);
    w.u64_field("verified", verified as u64);
    w.u64_field("tampered", tampered as u64);
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
        w.str_field("integrity", h.integrity.as_str());
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
            None,
        )
        .unwrap();
        assert_eq!(h.hostname, "web-1");
        assert_eq!(h.denied, 42);
        assert!(h.enforced && h.autoresponse);
        assert!(!h.stale); // 50s old < 120s
                           // No key configured -> unsigned, taken as-is.
        assert_eq!(h.integrity, Integrity::Unsigned);
    }

    #[test]
    fn marks_old_hosts_stale() {
        let now = 1_000_000;
        let h = parse_host(r#"{"hostname":"old","generated_at":900000}"#, now, None).unwrap();
        assert!(h.stale); // 100_000s old
    }

    #[test]
    fn rejects_summary_without_hostname() {
        assert!(parse_host(r#"{"denied":5}"#, 0, None).is_none());
        assert!(parse_host("not json", 0, None).is_none());
    }

    /// Build the exact JSON `publish_self` writes for a signed summary, so the
    /// reader path is tested against the writer path's format.
    fn signed_summary(key: &[u8], hostname: &str, gen: u64, denied: u64) -> String {
        let mac = hmac_sha256(
            key,
            &signing_input(&Summary {
                hostname,
                generated_at: gen,
                enforced: true,
                denied,
                attackers: 0,
                contained: 0,
                autoresponse: false,
            }),
        );
        format!(
            r#"{{"hostname":"{hostname}","generated_at":{gen},"enforced":true,"denied":{denied},"attackers":0,"contained":0,"autoresponse":false,"mac":"{}"}}"#,
            hash::hex(&mac)
        )
    }

    #[test]
    fn a_correctly_signed_summary_verifies() {
        let key = b"fleet-secret-key";
        let text = signed_summary(key, "web-1", 999_950, 42);
        let h = parse_host(&text, 1_000_000, Some(key)).unwrap();
        assert_eq!(h.integrity, Integrity::Verified);
        assert_eq!(h.denied, 42);
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let key = b"fleet-secret-key";
        // Sign for denied=42, then rewrite the body to claim denied=0 while
        // keeping the old MAC: exactly the forgery signing is meant to catch.
        let text =
            signed_summary(key, "web-1", 999_950, 42).replace(r#""denied":42"#, r#""denied":0"#);
        let h = parse_host(&text, 1_000_000, Some(key)).unwrap();
        assert_eq!(h.integrity, Integrity::Tampered);
    }

    #[test]
    fn the_wrong_key_does_not_verify() {
        let text = signed_summary(b"theirs", "web-1", 999_950, 42);
        let h = parse_host(&text, 1_000_000, Some(b"ours")).unwrap();
        assert_eq!(h.integrity, Integrity::Tampered);
    }

    #[test]
    fn a_key_configured_but_no_mac_is_tampered() {
        // A summary with no MAC, read by a host that requires one, cannot be
        // trusted — an attacker would simply omit the field otherwise.
        let text = r#"{"hostname":"web-1","generated_at":999950,"enforced":true,"denied":42,"attackers":0,"contained":0,"autoresponse":false}"#;
        let h = parse_host(text, 1_000_000, Some(b"key")).unwrap();
        assert_eq!(h.integrity, Integrity::Tampered);
    }

    #[test]
    fn check_integrity_covers_every_state() {
        let s = Summary {
            hostname: "h",
            generated_at: 1,
            enforced: true,
            denied: 0,
            attackers: 0,
            contained: 0,
            autoresponse: false,
        };
        // Unsigned: no key.
        assert_eq!(check_integrity(None, None, &s), Integrity::Unsigned);
        // Malformed hex MAC with a key -> tampered, not a panic.
        assert_eq!(
            check_integrity(Some(b"k"), Some("zz"), &s),
            Integrity::Tampered
        );
    }
}
