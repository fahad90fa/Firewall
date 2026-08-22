//! Node-locked activation for the packaged (paid) firewall.
//!
//! # What this is, and what it is not
//!
//! A license key activates **one machine** for a fixed period. The firewall
//! phones home once to activate (binding the key to this machine's fingerprint)
//! and then re-checks periodically; when the key expires — or an admin suspends
//! or blocks it — the periodic check **reverts the nftables table and warns**,
//! so the machine stops enforcing rather than silently keeping stale ones.
//!
//! This is a **deterrent, not DRM**. The agent runs as root on the customer's
//! own machine, the signing secret is symmetric and lives on the server, and a
//! determined owner can bypass any client-side check. The honest security
//! boundary is the server: activation, expiry, suspend and block are all decided
//! there and merely *cached* here, bounded by a short offline grace window.
//!
//! # Opt-in by construction
//!
//! Gating is enabled only when the config file [`LICENSE_CONF`] exists. The
//! `.deb` installs it, so packaged installs are gated. A source/CI build has no
//! such file, so `apply` is ungated there and the project's own tests and
//! `scripts/live-run.sh` keep working unchanged.

use std::path::Path;
use std::process::Command;

use ufw_shared::hash::{hex, sha256};
use ufw_shared::json::{self, Json, JsonWriter};

use crate::state;

/// Present ⇒ this install enforces licensing. Absent ⇒ ungated (source/dev).
pub const LICENSE_CONF: &str = "/etc/unified-firewall/license.conf";
/// The cached server verdict for this machine. Root-only (0600).
pub const LICENSE_STORE: &str = "/var/lib/unified-firewall/license.json";

const DEFAULT_ENDPOINT: &str = "https://bpcylnfjdsjouqoezbpa.supabase.co/functions/v1";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

/// Where to phone home, and how. Parsed from [`LICENSE_CONF`].
pub struct Config {
    pub endpoint: String,
    /// The project's public anon key. Sent as `apikey` + bearer so the Supabase
    /// gateway routes the request; optional because the activate/validate
    /// functions themselves do not verify a JWT.
    pub apikey: Option<String>,
    pub timeout_secs: u64,
}

/// Parse a `key = value` config (blank lines and `#` comments ignored).
fn parse_config(text: &str) -> Config {
    let mut endpoint = DEFAULT_ENDPOINT.to_string();
    let mut apikey = None;
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim().trim_matches('"'));
        match k {
            "endpoint" if !v.is_empty() => endpoint = v.trim_end_matches('/').to_string(),
            "apikey" if !v.is_empty() => apikey = Some(v.to_string()),
            "timeout_secs" => {
                if let Ok(n) = v.parse::<u64>() {
                    if n > 0 {
                        timeout_secs = n;
                    }
                }
            }
            _ => {}
        }
    }
    Config {
        endpoint,
        apikey,
        timeout_secs,
    }
}

fn load_config() -> Result<Config, String> {
    let text = std::fs::read_to_string(LICENSE_CONF).map_err(|_| {
        format!("licensing is not configured on this host ({LICENSE_CONF} is missing)")
    })?;
    Ok(parse_config(&text))
}

/// Whether this install enforces licensing at all.
pub fn licensing_enabled() -> bool {
    Path::new(LICENSE_CONF).exists()
}

// ---------------------------------------------------------------------------
// machine fingerprint
// ---------------------------------------------------------------------------

/// A stable, privacy-preserving per-machine id: a salted SHA-256 of the host's
/// machine-id, so the raw id never leaves the box.
fn fingerprint_from(raw: &str) -> String {
    let mut buf = b"ufw-license-node\0".to_vec();
    buf.extend_from_slice(raw.trim().as_bytes());
    hex(&sha256(&buf))
}

fn machine_fingerprint() -> Result<String, String> {
    let raw = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map_err(|_| {
            "cannot read /etc/machine-id — this host has no stable machine id".to_string()
        })?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("/etc/machine-id is empty".into());
    }
    Ok(fingerprint_from(raw))
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "linux".to_string())
}

// ---------------------------------------------------------------------------
// local store
// ---------------------------------------------------------------------------

/// The cached server verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub key: String,
    pub machine_id: String,
    pub plan: String,
    /// Last server verdict: active / suspended / blocked / expired.
    pub status: String,
    pub expires_at_unix: u64,
    /// Deadline by which we must re-check online; the offline grace window.
    pub recheck_by_unix: u64,
    pub token: String,
    pub last_check: u64,
    /// Last time an online check succeeded.
    pub last_ok: u64,
}

fn store_to_json(s: &Store) -> String {
    let mut w = JsonWriter::with_capacity(512);
    w.begin_object();
    w.str_field("key", &s.key);
    w.str_field("machine_id", &s.machine_id);
    w.str_field("plan", &s.plan);
    w.str_field("status", &s.status);
    w.u64_field("expires_at_unix", s.expires_at_unix);
    w.u64_field("recheck_by_unix", s.recheck_by_unix);
    w.str_field("token", &s.token);
    w.u64_field("last_check", s.last_check);
    w.u64_field("last_ok", s.last_ok);
    w.end_object();
    w.finish()
}

fn store_from_json(text: &str) -> Option<Store> {
    let v = json::parse(text).ok()?;
    let s = |k: &str| v.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let n = |k: &str| v.get(k).and_then(Json::as_u64).unwrap_or(0);
    let key = s("key");
    if key.is_empty() {
        return None;
    }
    Some(Store {
        key,
        machine_id: s("machine_id"),
        plan: s("plan"),
        status: s("status"),
        expires_at_unix: n("expires_at_unix"),
        recheck_by_unix: n("recheck_by_unix"),
        token: s("token"),
        last_check: n("last_check"),
        last_ok: n("last_ok"),
    })
}

pub fn load_store() -> Option<Store> {
    store_from_json(&std::fs::read_to_string(LICENSE_STORE).ok()?)
}

fn save_store(s: &Store) -> Result<(), String> {
    let dir = Path::new(LICENSE_STORE)
        .parent()
        .expect("constant has a parent");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(LICENSE_STORE, store_to_json(s)).map_err(|e| format!("{LICENSE_STORE}: {e}"))?;
    // Root-only: the token is a bearer of the machine's activation.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(LICENSE_STORE, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// validity decision (pure)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Blocked,
    Suspended,
    Expired,
    Unknown,
}

impl Reason {
    fn describe(self) -> &'static str {
        match self {
            Reason::Blocked => "blocked by the vendor",
            Reason::Suspended => "suspended by the vendor",
            Reason::Expired => "expired",
            Reason::Unknown => "in an unknown state",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    /// Cached verdict is good and still within the offline grace window.
    Valid,
    /// The grace window has elapsed — must confirm online before trusting it.
    NeedsRecheck,
    /// Definitively not enforcing.
    Invalid(Reason),
    /// No key has ever been activated on this machine.
    NotActivated,
}

/// Decide validity purely from a cached store and the current time.
pub fn evaluate(store: Option<&Store>, now: u64) -> Validity {
    let s = match store {
        None => return Validity::NotActivated,
        Some(s) => s,
    };
    match s.status.as_str() {
        "blocked" => return Validity::Invalid(Reason::Blocked),
        "suspended" => return Validity::Invalid(Reason::Suspended),
        "active" => {}
        "expired" => return Validity::Invalid(Reason::Expired),
        _ => return Validity::Invalid(Reason::Unknown),
    }
    if s.expires_at_unix != 0 && now >= s.expires_at_unix {
        return Validity::Invalid(Reason::Expired);
    }
    if s.recheck_by_unix != 0 && now > s.recheck_by_unix {
        return Validity::NeedsRecheck;
    }
    Validity::Valid
}

// ---------------------------------------------------------------------------
// phone-home (curl)
// ---------------------------------------------------------------------------

/// A parsed server response.
struct Verdict {
    http_code: u16,
    ok: bool,
    status: String,
    plan: String,
    expires_at_unix: u64,
    recheck_by_unix: u64,
    token: String,
    reason: String,
}

fn parse_verdict(http_code: u16, body: &Json) -> Verdict {
    let s = |k: &str| body.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let n = |k: &str| body.get(k).and_then(Json::as_u64).unwrap_or(0);
    Verdict {
        http_code,
        ok: body.get("ok").and_then(Json::as_bool).unwrap_or(false),
        status: s("status"),
        plan: s("plan"),
        expires_at_unix: n("expires_at_unix"),
        recheck_by_unix: n("recheck_by_unix"),
        token: s("token"),
        reason: s("reason"),
    }
}

/// POST `body` to `<endpoint>/<path>` with curl and parse the JSON reply.
/// Returns the HTTP status and the parsed body, or an error if curl/JSON failed.
fn call_endpoint(cfg: &Config, path: &str, body: &str) -> Result<Verdict, String> {
    let url = format!("{}/{}", cfg.endpoint, path);
    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("-m")
        .arg(cfg.timeout_secs.to_string())
        .arg("-X")
        .arg("POST")
        .arg(&url)
        .arg("-H")
        .arg("Content-Type: application/json");
    if let Some(k) = &cfg.apikey {
        cmd.arg("-H").arg(format!("apikey: {k}"));
        cmd.arg("-H").arg(format!("Authorization: Bearer {k}"));
    }
    cmd.arg("-d").arg(body).arg("-w").arg("\n%{http_code}");

    let out = cmd
        .output()
        .map_err(|e| format!("could not run curl (is it installed?): {e}"))?;
    if !out.status.success() && out.stdout.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "network error contacting the license server: {}",
            err.trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (json_text, code) = match text.trim_end().rsplit_once('\n') {
        Some((b, c)) => (b, c.trim().parse::<u16>().unwrap_or(0)),
        None => (text.trim(), 0),
    };
    let parsed = json::parse(json_text.trim())
        .map_err(|e| format!("license server returned unparseable response: {e}"))?;
    Ok(parse_verdict(code, &parsed))
}

/// Fold a server verdict into a fresh store (used by activate and validate).
fn store_from_verdict(key: &str, machine_id: &str, v: &Verdict, now: u64) -> Store {
    Store {
        key: key.to_string(),
        machine_id: machine_id.to_string(),
        plan: if v.plan.is_empty() {
            "pro".into()
        } else {
            v.plan.clone()
        },
        status: if v.status.is_empty() {
            "active".into()
        } else {
            v.status.clone()
        },
        expires_at_unix: v.expires_at_unix,
        recheck_by_unix: v.recheck_by_unix,
        token: v.token.clone(),
        last_check: now,
        last_ok: now,
    }
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

/// `ufw-nft license <activate|status|check|deactivate>`
pub fn cmd_license(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("activate") => activate(args.get(1..).unwrap_or(&[])),
        Some("status") => status(args.get(1..).unwrap_or(&[])),
        Some("check") => check(),
        Some("deactivate") => deactivate(),
        _ => Err(
            "usage: ufw-nft license <activate <KEY> | status [--refresh] | check | deactivate>"
                .into(),
        ),
    }
}

fn activate(args: &[String]) -> Result<(), String> {
    let key = args
        .first()
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .ok_or("usage: ufw-nft license activate <KEY>")?;
    let cfg = load_config()?;
    let machine_id = machine_fingerprint()?;

    let mut body = JsonWriter::with_capacity(256);
    body.begin_object();
    body.str_field("license_key", &key);
    body.str_field("machine_id", &machine_id);
    body.str_field("machine_label", &hostname());
    body.end_object();

    let v = call_endpoint(&cfg, "activate", &body.finish())?;
    if !v.ok {
        let why = if v.reason.is_empty() {
            v.status.clone()
        } else {
            v.reason.clone()
        };
        return Err(match why.as_str() {
            "key_bound_to_another_machine" => {
                "this key is already activated on another machine (one key, one machine). \
                 Ask the vendor to release it, or use a different key."
                    .to_string()
            }
            "unknown_key" => "that key was not recognised — check for typos.".to_string(),
            "expired" => "that key has expired.".to_string(),
            "blocked" | "suspended" => format!("that key is {why}."),
            other if !other.is_empty() => format!("activation refused: {other}"),
            _ => format!("activation refused (HTTP {})", v.http_code),
        });
    }

    let store = store_from_verdict(&key, &machine_id, &v, state::now_unix());
    save_store(&store)?;
    println!(
        "activated: {} plan, this machine is now licensed.",
        store.plan
    );
    if store.expires_at_unix != 0 {
        println!(
            "  expires:  {} (UTC unix {})",
            fmt_unix(store.expires_at_unix),
            store.expires_at_unix
        );
    }
    println!("  enforce:  sudo ufw-nft apply default_allow");
    Ok(())
}

fn status(args: &[String]) -> Result<(), String> {
    let refresh = args.iter().any(|a| a == "--refresh");
    if !licensing_enabled() {
        println!("licensing: not enabled on this host (no {LICENSE_CONF}); `apply` is ungated.");
        return Ok(());
    }
    if refresh {
        // Best-effort online re-check; ignore network errors for a status read.
        if let Err(e) = check() {
            eprintln!("  note: online re-check failed: {e}");
        }
    }
    let store = load_store();
    let now = state::now_unix();
    match evaluate(store.as_ref(), now) {
        Validity::NotActivated => {
            println!("licensing: enabled, but NO key is activated on this machine.");
            println!("  activate: sudo ufw-nft license activate <KEY>");
        }
        v => {
            let s = store.as_ref().expect("evaluated a present store");
            println!("licensing: enabled");
            println!("  key:      {}", mask_key(&s.key));
            println!("  plan:     {}", s.plan);
            println!("  status:   {}", describe_validity(v, s, now));
            if s.expires_at_unix != 0 {
                println!(
                    "  expires:  {} (unix {})",
                    fmt_unix(s.expires_at_unix),
                    s.expires_at_unix
                );
            }
            if s.last_ok != 0 {
                println!("  last ok:  {} (unix {})", fmt_unix(s.last_ok), s.last_ok);
            }
        }
    }
    Ok(())
}

/// The periodic heartbeat (run by a systemd timer). Re-validates online, caches
/// the verdict, and — on a definitive lapse — reverts enforcement and warns.
fn check() -> Result<(), String> {
    let cfg = load_config()?;
    let store = load_store()
        .ok_or("no activated key on this machine (run: ufw-nft license activate <KEY>)")?;
    let machine_id = machine_fingerprint()?;

    let mut body = JsonWriter::with_capacity(256);
    body.begin_object();
    body.str_field("license_key", &store.key);
    body.str_field("machine_id", &machine_id);
    body.end_object();

    let v = call_endpoint(&cfg, "validate", &body.finish())?;
    let now = state::now_unix();

    if v.ok {
        let mut updated = store_from_verdict(&store.key, &machine_id, &v, now);
        // validate returns no plan change normally; keep prior plan if blank.
        if v.plan.is_empty() {
            updated.plan = store.plan.clone();
        }
        save_store(&updated)?;
        println!(
            "license OK ({} plan), next re-check by unix {}.",
            updated.plan, updated.recheck_by_unix
        );
        return Ok(());
    }

    // Not ok → cache the lapse, then stop enforcing.
    let reason = match v.status.as_str() {
        "blocked" => Reason::Blocked,
        "suspended" => Reason::Suspended,
        "expired" => Reason::Expired,
        _ => Reason::Unknown,
    };
    let mut lapsed = store.clone();
    lapsed.status = if v.status.is_empty() {
        "expired".into()
    } else {
        v.status.clone()
    };
    lapsed.last_check = now;
    let _ = save_store(&lapsed);

    revert_enforcement();
    Err(format!(
        "license {} — enforcement reverted; this machine is no longer secured. \
         Renew or contact the vendor, then: sudo ufw-nft license activate <KEY>",
        reason.describe()
    ))
}

fn deactivate() -> Result<(), String> {
    let _ = std::fs::remove_file(LICENSE_STORE);
    println!("removed the local license activation from this machine.");
    println!("  note: this does not release the key on the vendor's side — ask an admin to Release it to move it.");
    Ok(())
}

/// Remove the enforced ruleset and its recorded state — the machine returns to
/// unprotected. Used when a license lapses.
fn revert_enforcement() {
    let _ = crate::nft_run(&["delete", "table", "inet", "ufw"]);
    state::clear();
    eprintln!("  \u{26a0} reverted table inet ufw — the packet filter is no longer active.");
}

// ---------------------------------------------------------------------------
// enforcement gate (called by apply / boot-apply / trial)
// ---------------------------------------------------------------------------

/// Result of the pre-enforcement license gate.
pub enum Gate {
    /// Licensing is off, or the license is valid — go ahead.
    Allow,
    /// Licensing is on and the license is not valid — the caller must not enforce.
    Deny(String),
}

/// Decide whether enforcement is permitted right now. When the cached verdict's
/// grace window has elapsed, this attempts one online re-check before denying.
pub fn gate_enforcement() -> Gate {
    if !licensing_enabled() {
        return Gate::Allow;
    }
    let now = state::now_unix();
    match evaluate(load_store().as_ref(), now) {
        Validity::Valid => Gate::Allow,
        Validity::NeedsRecheck => {
            // Grace elapsed — confirm online. check() saves the fresh verdict.
            match check() {
                Ok(()) => match evaluate(load_store().as_ref(), state::now_unix()) {
                    Validity::Valid => Gate::Allow,
                    other => Gate::Deny(deny_message(other)),
                },
                Err(e) => Gate::Deny(format!(
                    "the license needs an online re-check and it could not be completed: {e}"
                )),
            }
        }
        other => Gate::Deny(deny_message(other)),
    }
}

fn deny_message(v: Validity) -> String {
    match v {
        Validity::NotActivated => "this firewall is not activated on this machine. \
             Activate it first: sudo ufw-nft license activate <KEY>"
            .to_string(),
        Validity::Invalid(r) => format!(
            "the license for this machine is {} — enforcement is disabled until it is renewed. \
             Then: sudo ufw-nft license activate <KEY>",
            r.describe()
        ),
        Validity::NeedsRecheck => "the license needs an online re-check.".to_string(),
        Validity::Valid => "ok".to_string(),
    }
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn mask_key(key: &str) -> String {
    // Show the group prefix, hide the rest: UFW-4KD2-****-****-****-****
    match key
        .split_once('-')
        .and_then(|(p, rest)| rest.split_once('-').map(|(a, _)| (p, a)))
    {
        Some((p, a)) => format!("{p}-{a}-****-****-****-****"),
        None => "****".to_string(),
    }
}

fn describe_validity(v: Validity, s: &Store, now: u64) -> String {
    match v {
        Validity::Valid => {
            if s.recheck_by_unix > now {
                format!(
                    "active (offline grace for {})",
                    fmt_duration(s.recheck_by_unix - now)
                )
            } else {
                "active".to_string()
            }
        }
        Validity::NeedsRecheck => "active, but due for an online re-check".to_string(),
        Validity::Invalid(r) => r.describe().to_string(),
        Validity::NotActivated => "not activated".to_string(),
    }
}

fn fmt_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// A compact UTC date-time from a unix timestamp, without pulling in a date
/// crate. Civil-date conversion (Howard Hinnant's algorithm).
fn fmt_unix(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs_of_day = ts % 86_400;
    let (h, mi, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn store(status: &str, expires: u64, recheck: u64) -> Store {
        Store {
            key: "UFW-AAAA-BBBB-CCCC-DDDD-EEEE".into(),
            machine_id: "mid".into(),
            plan: "pro".into(),
            status: status.into(),
            expires_at_unix: expires,
            recheck_by_unix: recheck,
            token: "tok".into(),
            last_check: 0,
            last_ok: 0,
        }
    }

    #[test]
    fn not_activated_when_no_store() {
        assert_eq!(evaluate(None, 1000), Validity::NotActivated);
    }

    #[test]
    fn active_within_grace_is_valid() {
        let s = store("active", 10_000, 5_000);
        assert_eq!(evaluate(Some(&s), 1_000), Validity::Valid);
    }

    #[test]
    fn past_grace_needs_recheck() {
        let s = store("active", 10_000, 5_000);
        assert_eq!(evaluate(Some(&s), 6_000), Validity::NeedsRecheck);
    }

    #[test]
    fn past_expiry_is_invalid_expired_even_before_grace() {
        // Expiry beats the grace window: once expired, it is invalid immediately.
        let s = store("active", 4_000, 9_000);
        assert_eq!(
            evaluate(Some(&s), 4_500),
            Validity::Invalid(Reason::Expired)
        );
    }

    #[test]
    fn suspended_and_blocked_short_circuit() {
        assert_eq!(
            evaluate(Some(&store("suspended", 10_000, 9_000)), 1),
            Validity::Invalid(Reason::Suspended)
        );
        assert_eq!(
            evaluate(Some(&store("blocked", 10_000, 9_000)), 1),
            Validity::Invalid(Reason::Blocked)
        );
    }

    #[test]
    fn unknown_status_is_invalid() {
        assert_eq!(
            evaluate(Some(&store("weird", 10_000, 9_000)), 1),
            Validity::Invalid(Reason::Unknown)
        );
    }

    #[test]
    fn zero_timestamps_do_not_force_expiry() {
        // A store with no expiry/recheck info (0) should not be treated as expired.
        let s = store("active", 0, 0);
        assert_eq!(evaluate(Some(&s), 9_999_999), Validity::Valid);
    }

    #[test]
    fn store_json_round_trips() {
        let s = store("active", 1_777_000_000, 1_700_300_000);
        let back = store_from_json(&store_to_json(&s)).expect("parse");
        assert_eq!(back, s);
    }

    #[test]
    fn store_from_json_rejects_missing_key() {
        assert!(store_from_json("{\"plan\":\"pro\"}").is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_not_the_raw_id() {
        let a = fingerprint_from("abc123");
        let b = fingerprint_from("  abc123\n");
        assert_eq!(a, b, "trimming makes it stable");
        assert_ne!(a, "abc123", "the raw id never leaves");
        assert_eq!(a.len(), 64, "hex sha-256");
        assert_ne!(a, fingerprint_from("abc124"), "distinct ids differ");
    }

    #[test]
    fn config_parses_and_defaults() {
        let c = parse_config(
            "# comment\nendpoint = https://x/functions/v1/\napikey=\"pub-key\"\ntimeout_secs=30\n",
        );
        assert_eq!(c.endpoint, "https://x/functions/v1");
        assert_eq!(c.apikey.as_deref(), Some("pub-key"));
        assert_eq!(c.timeout_secs, 30);
        let d = parse_config("");
        assert_eq!(d.endpoint, DEFAULT_ENDPOINT);
        assert!(d.apikey.is_none());
        assert_eq!(d.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn verdict_parse_ok_and_reject() {
        let ok = json::parse(
            "{\"ok\":true,\"status\":\"active\",\"plan\":\"pro\",\"expires_at_unix\":1777000000,\"recheck_by_unix\":1700300000,\"token\":\"t\"}",
        )
        .unwrap();
        let v = parse_verdict(200, &ok);
        assert!(v.ok);
        assert_eq!(v.plan, "pro");
        assert_eq!(v.expires_at_unix, 1_777_000_000);

        let rej = json::parse("{\"ok\":false,\"status\":\"machine_mismatch\",\"reason\":\"key_bound_to_another_machine\"}").unwrap();
        let v = parse_verdict(409, &rej);
        assert!(!v.ok);
        assert_eq!(v.reason, "key_bound_to_another_machine");
    }

    #[test]
    fn mask_key_hides_all_but_prefix() {
        assert_eq!(
            mask_key("UFW-4KD2-9QMT-XXXX-YYYY-ZZZZ"),
            "UFW-4KD2-****-****-****-****"
        );
    }

    #[test]
    fn civil_date_matches_known_epochs() {
        assert_eq!(fmt_unix(0), "1970-01-01 00:00:00Z");
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(fmt_unix(1_609_459_200), "2021-01-01 00:00:00Z");
        // 2025-08-22T00:00:00Z = 1755820800
        assert_eq!(fmt_unix(1_755_820_800), "2025-08-22 00:00:00Z");
        // 2026-08-22T13:45:07Z = 1787406307
        assert_eq!(fmt_unix(1_787_406_307), "2026-08-22 13:45:07Z");
    }
}
