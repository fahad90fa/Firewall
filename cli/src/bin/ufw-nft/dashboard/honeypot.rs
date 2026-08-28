//! Honeypot / deception layer for the console.
//!
//! Two trap surfaces, one shared alert log, and an OPT-IN, structurally
//! spoof-proof auto-contain:
//!
//!   * **Tier 2 — dashboard decoy routes ("traps").** The console serves paths no
//!     legitimate user or tool ever requests (`/.git/config`, `/.env`, `/admin`,
//!     `/wp-login.php`, …). Any hit is an intruder probing the box. Because the
//!     hit is handled only *after* `accept()` + the request head is read, its
//!     source is a **completed TCP handshake** — not spoofable — which is what
//!     makes auto-contain safe here.
//!   * **Canary honeytoken.** The fake pages embed a per-install random token. If
//!     that token is ever replayed as `Authorization: Bearer` to a real endpoint,
//!     it proves the fake page was scraped and the "secret" exfiltrated — the
//!     highest-signal, lowest-false-positive event in the whole feature.
//!
//! Tier 1 — passive *network* decoy ports — lives in policy, not here: a rule
//! with `action: alert` over a decoy port set lowers to an nftables `log`
//! (`policy-lang` `Action::Alert`), needs no listening service, and its
//! single-SYN source is UNVERIFIED/spoofable — so those alerts surface on the
//! dashboard but are **never** eligible for auto-contain. Only the
//! handshake-proven Tier-2 touches here can contain, and only when an operator
//! has explicitly enabled it.
//!
//! Safety, so a trap can never become a self-inflicted outage:
//!   * Auto-contain is **OFF by default** (opt-in), and even on, only contains
//!     **public** sources (never loopback/LAN/CGNAT) at a **rate cap**.
//!   * The recorded path/User-Agent are **sanitised** before they touch the
//!     audit log (no log injection).
//!   * State is bounded (a fixed-size recent-hits ring).

use std::collections::VecDeque;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use ufw_shared::json::{self, Json, JsonWriter};

use super::contain;

const AUDIT: &str = "/var/lib/unified-firewall/honeypot-audit.log";
const CONFIG: &str = "/var/lib/unified-firewall/honeypot.json";
const RING_CAP: usize = 500;
/// How long a honeypot auto-contain lasts (well under contain's own cap).
const CONTAIN_TTL: u64 = 6 * 3600;
/// Auto-contains permitted per rolling hour, so a flood of decoy hits from many
/// spoof-proof sources still cannot mass-block.
const CONTAIN_MAX_PER_HOUR: usize = 20;

/// Decoy paths no legitimate user or tool ever requests. A hit is an intruder.
pub const DECOYS: &[&str] = &[
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/.git/config",
    "/.env",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/api/keys",
    "/api/secrets",
    "/actuator/env",
    "/config.json",
    "/backup.zip",
    "/server-status",
    "/.DS_Store",
    "/cgi-bin/",
];

/// Is `route` a decoy path? Exact match, or under a decoy directory prefix
/// (`/cgi-bin/...`, `/.git/...`) so scanners walking a tree still trip it.
pub fn is_decoy(route: &str) -> bool {
    DECOYS.iter().any(|d| {
        route == *d || (d.ends_with('/') && route.starts_with(d)) || route.starts_with("/.git/")
    })
}

// --- canary honeytoken (per-install, NOT in the source) --------------------

fn canary_cell() -> &'static Mutex<Option<String>> {
    static C: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// The per-install canary token: loaded from disk, else freshly generated from
/// the OS RNG and persisted. Generating it per install (rather than a constant
/// in this open-source file) means an attacker cannot learn it by reading the
/// code — only by scraping the running fake page, which is the whole point.
pub fn canary() -> String {
    if let Ok(mut cell) = canary_cell().lock() {
        if let Some(t) = cell.as_ref() {
            return t.clone();
        }
        // Prefer a value already persisted (survives restarts so a replay days
        // later still matches).
        if let Some(saved) = std::fs::read_to_string(CONFIG)
            .ok()
            .and_then(|t| json::parse(&t).ok())
            .and_then(|v| v.get("canary").and_then(Json::as_str).map(str::to_string))
            .filter(|s| !s.is_empty())
        {
            *cell = Some(saved.clone());
            return saved;
        }
        let fresh = gen_token();
        persist_field("canary", &fresh);
        *cell = Some(fresh.clone());
        return fresh;
    }
    gen_token()
}

/// 32 hex chars from the OS RNG, falling back to a machine-derived value if
/// `/dev/urandom` is unavailable (still non-obvious, still per-host).
///
/// Reads EXACTLY 16 bytes with `read_exact` — never `fs::read`, which would try
/// to read `/dev/urandom` to EOF and block forever.
fn gen_token() -> String {
    let mut raw = [0u8; 16];
    let from_rng = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut raw))
        .is_ok();
    let bytes = if from_rng {
        raw.to_vec()
    } else {
        let seed = std::fs::read("/etc/machine-id").unwrap_or_else(|_| b"ufw-fallback".to_vec());
        ufw_shared::hash::sha256(&seed)[..16].to_vec()
    };
    format!("ufw_canary_{}", ufw_shared::hash::hex(&bytes))
}

/// Does `token` equal this install's canary? A true result means a secret the
/// console only ever placed in a *fake* decoy page has come back.
pub fn is_canary(token: &str) -> bool {
    !token.is_empty() && token == canary()
}

// --- fake responses --------------------------------------------------------

/// A convincing-but-inert body for a decoy path. Fake secrets embed the canary
/// so that scraping-and-replaying it is caught. Nothing here is real or
/// exploitable — the strings are static.
pub fn fake_body(route: &str) -> (&'static str, String) {
    let tok = canary();
    if route.ends_with(".env") {
        return (
            "text/plain",
            format!(
                "APP_ENV=production\nDB_HOST=10.0.0.12\nDB_USER=svc_app\nDB_PASSWORD=hunter2\nAPI_TOKEN={tok}\n"
            ),
        );
    }
    if route.contains("/.git/config") {
        return (
            "text/plain",
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://svc:${API_TOKEN}@git.internal/app.git\n".into(),
        );
    }
    if route.contains("/api/keys") || route.contains("/api/secrets") {
        return (
            "application/json",
            format!("{{\"keys\":[{{\"id\":\"prod-1\",\"token\":\"{tok}\",\"scope\":\"admin\"}}]}}"),
        );
    }
    // A generic fake login form for /admin, /wp-login.php, etc. The canary rides
    // in a hidden field / comment so a scraper that harvests "credentials" gets
    // a token that only ever existed here.
    (
        "text/html; charset=utf-8",
        format!(
            "<!doctype html><title>Admin</title><body><h2>Administrator sign in</h2>\
             <form method=post action=/admin><input name=user placeholder=Username>\
             <input type=password name=pass placeholder=Password>\
             <input type=hidden name=csrf value=\"{tok}\"><button>Sign in</button></form>\
             <!-- session api_token={tok} --></body>"
        ),
    )
}

// --- hit log ---------------------------------------------------------------

#[derive(Clone)]
struct Hit {
    ts: u64,
    src: String,
    path: String,
    ua: String,
    mtls: Option<String>,
    kind: String,
    contained: bool,
}

struct HpLog {
    hits: VecDeque<Hit>,
    total: u64,
    /// Rolling-hour auto-contain rate limiter: (hour_index, count_this_hour).
    contain_window: (u64, usize),
}

fn hp_log() -> &'static Mutex<HpLog> {
    static L: OnceLock<Mutex<HpLog>> = OnceLock::new();
    L.get_or_init(|| {
        Mutex::new(HpLog {
            hits: VecDeque::new(),
            total: 0,
            contain_window: (0, 0),
        })
    })
}

/// Strip anything that could corrupt a log line or a JSON field: keep only
/// printable ASCII, drop CR/LF/control, and cap the length. This is the
/// log-injection guard for the attacker-controlled path and User-Agent.
fn sanitize(s: &str, cap: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(cap)
        .collect()
}

/// Is `ip` a public, internet-routable address — the ONLY class eligible for
/// auto-contain (never loopback, LAN, CGNAT, link-local)?
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40;
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_unspecified()
                || o[0] == 0
                || cgnat)
        }
        IpAddr::V6(a) => {
            let s0 = a.segments()[0];
            let link_local = (s0 & 0xffc0) == 0xfe80;
            let ula = (s0 & 0xfe00) == 0xfc00;
            !(a.is_loopback() || a.is_unspecified() || link_local || ula)
        }
    }
}

/// PURE decision: should a decoy hit from `src` be auto-contained right now?
/// `enabled` = the opt-in flag, `under_cap` = the rate limiter has room. Kept
/// side-effect-free so the anti-spoof / public-only / opt-in logic is unit-tested
/// without touching nftables or the clock.
pub fn contain_decision(enabled: bool, src: Option<IpAddr>, under_cap: bool) -> bool {
    enabled && under_cap && src.map(|ip| is_public(&ip)).unwrap_or(false)
}

/// Record a decoy hit or a canary replay: bounded ring + sanitised audit line,
/// and — only if opt-in auto-contain is on and the source is a public,
/// rate-limited, handshake-proven address — a `contain`.
pub fn record_hit(src: Option<IpAddr>, cert_fp: Option<&str>, path: &str, ua: &str, kind: &str) {
    let ts = crate::state::now_unix();
    let path = sanitize(path, 256);
    let ua = sanitize(ua, 256);
    let src_s = src
        .map(|i| i.to_string())
        .unwrap_or_else(|| "unknown".into());

    // Auto-contain gate (all side effects below the pure decision).
    let mut contained = false;
    if contain_enabled() {
        let under_cap = rate_ok(ts);
        if contain_decision(true, src, under_cap) {
            if let Some(ip) = src {
                if contain::contain_note(&ip.to_string(), CONTAIN_TTL, &format!("honeypot:{path}"))
                    .is_ok()
                {
                    contained = true;
                    bump_rate(ts);
                }
            }
        }
    }

    if let Ok(mut log) = hp_log().lock() {
        log.total += 1;
        log.hits.push_front(Hit {
            ts,
            src: src_s.clone(),
            path: path.clone(),
            ua: ua.clone(),
            mtls: cert_fp.map(|c| c.to_string()),
            kind: kind.to_string(),
            contained,
        });
        log.hits.truncate(RING_CAP);
    }

    // Best-effort append to the audit log (mirrors contain.rs's AUDIT pattern).
    if let Some(dir) = std::path::Path::new(AUDIT).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT)
    {
        let _ = writeln!(
            f,
            "{ts} kind={kind} src={src_s} path={path} contained={contained} ua=\"{ua}\""
        );
    }
}

// --- rate limiter ----------------------------------------------------------

fn rate_ok(now: u64) -> bool {
    if let Ok(log) = hp_log().lock() {
        let hour = now / 3600;
        let (h, n) = log.contain_window;
        return h != hour || n < CONTAIN_MAX_PER_HOUR;
    }
    false
}

fn bump_rate(now: u64) {
    if let Ok(mut log) = hp_log().lock() {
        let hour = now / 3600;
        if log.contain_window.0 == hour {
            log.contain_window.1 += 1;
        } else {
            log.contain_window = (hour, 1);
        }
    }
}

// --- config (opt-in auto-contain) ------------------------------------------

fn persist_field(key: &str, val: &str) {
    if let Some(dir) = std::path::Path::new(CONFIG).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut enabled = contain_enabled();
    let mut canary_v = String::new();
    if let Ok(v) = std::fs::read_to_string(CONFIG)
        .map_err(|_| ())
        .and_then(|t| json::parse(&t).map_err(|_| ()))
    {
        enabled = v
            .get("auto_contain")
            .and_then(Json::as_bool)
            .unwrap_or(enabled);
        canary_v = v
            .get("canary")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
    }
    if key == "canary" {
        canary_v = val.to_string();
    }
    if key == "auto_contain" {
        enabled = val == "true";
    }
    let mut w = JsonWriter::with_capacity(256);
    w.begin_object();
    w.bool_field("auto_contain", enabled);
    w.str_field("canary", &canary_v);
    w.end_object();
    let _ = std::fs::write(CONFIG, w.finish());
}

/// Is opt-in honeypot auto-contain enabled? Default false.
pub fn contain_enabled() -> bool {
    std::fs::read_to_string(CONFIG)
        .ok()
        .and_then(|t| json::parse(&t).ok())
        .and_then(|v| v.get("auto_contain").and_then(Json::as_bool))
        .unwrap_or(false)
}

/// Turn opt-in auto-contain on or off (an Admin-gated action in the router).
pub fn set_contain_enabled(on: bool) -> Result<(), String> {
    persist_field("auto_contain", if on { "true" } else { "false" });
    Ok(())
}

// --- rendering -------------------------------------------------------------

/// `(total hits ever, hits in the ring)` — for the dashboard state summary.
pub fn summary() -> (u64, usize) {
    hp_log()
        .lock()
        .map(|l| (l.total, l.hits.len()))
        .unwrap_or((0, 0))
}

/// The full Traps page payload: recent hits + totals + config.
pub fn honeypot_json() -> String {
    let mut w = JsonWriter::with_capacity(8192);
    w.begin_object();
    w.bool_field("auto_contain", contain_enabled());
    w.u64_field("decoy_count", DECOYS.len() as u64);
    if let Ok(log) = hp_log().lock() {
        w.u64_field("total", log.total);
        w.begin_array_field("hits");
        for h in log.hits.iter() {
            w.begin_object();
            w.u64_field("ts", h.ts);
            w.str_field("src", &h.src);
            w.str_field("path", &h.path);
            w.str_field("ua", &h.ua);
            w.str_field("kind", &h.kind);
            w.bool_field("contained", h.contained);
            w.opt_str_field("mtls", h.mtls.as_deref());
            w.end_object();
        }
        w.end_array();
    }
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_paths_match_real_ones_do_not() {
        assert!(is_decoy("/.git/config"));
        assert!(is_decoy("/.env"));
        assert!(is_decoy("/wp-login.php"));
        assert!(is_decoy("/cgi-bin/anything")); // dir prefix
        assert!(is_decoy("/.git/HEAD")); // git tree walk
        assert!(!is_decoy("/"));
        assert!(!is_decoy("/api/state"));
        assert!(!is_decoy("/api/features"));
    }

    #[test]
    fn sanitize_strips_log_injection() {
        let dirty = "GET /x\r\nInjected: evil\u{0}\u{1}line";
        let clean = sanitize(dirty, 256);
        assert!(!clean.contains('\n') && !clean.contains('\r') && !clean.contains('\u{0}'));
        assert!(clean.starts_with("GET /x"));
        assert_eq!(sanitize(&"a".repeat(1000), 10).len(), 10);
    }

    #[test]
    fn auto_contain_is_off_by_default_and_public_only() {
        // Opt-in OFF → never contain.
        assert!(!contain_decision(
            false,
            Some("203.0.113.9".parse().unwrap()),
            true
        ));
        // ON + public + under-cap → contain.
        assert!(contain_decision(
            true,
            Some("203.0.113.9".parse().unwrap()),
            true
        ));
        // ON but private/loopback/cgnat → never (anti-lockout).
        assert!(!contain_decision(
            true,
            Some("192.168.1.10".parse().unwrap()),
            true
        ));
        assert!(!contain_decision(
            true,
            Some("127.0.0.1".parse().unwrap()),
            true
        ));
        assert!(!contain_decision(
            true,
            Some("100.64.0.1".parse().unwrap()),
            true
        ));
        // ON + public but over the rate cap → held.
        assert!(!contain_decision(
            true,
            Some("8.8.8.8".parse().unwrap()),
            false
        ));
        // Unknown source (no handshake addr) → never.
        assert!(!contain_decision(true, None, true));
    }

    #[test]
    fn canary_is_nonempty_stable_and_matches_itself() {
        let a = canary();
        let b = canary();
        assert!(a.starts_with("ufw_canary_"));
        assert_eq!(a, b, "canary must be stable within a process");
        assert!(is_canary(&a));
        assert!(!is_canary("wrong"));
        assert!(!is_canary(""));
    }

    #[test]
    fn fake_bodies_embed_the_canary_and_are_inert() {
        let tok = canary();
        let (_ct, env) = fake_body("/.env");
        assert!(env.contains(&tok), "the .env decoy must carry the canary");
        let (_ct, keys) = fake_body("/api/keys");
        assert!(keys.contains(&tok));
        let (_ct, login) = fake_body("/admin");
        assert!(login.contains(&tok));
    }
}
