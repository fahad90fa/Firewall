//! Adaptive auto-response — opt-in playbooks that contain an attacking source
//! at the kernel automatically, with escalation for repeat offenders and
//! native auto-expiry.
//!
//! Deliberate safety constraints, so an automated block can never become an
//! automated outage:
//!   * OFF by default. Nothing fires until an operator turns the engine on.
//!   * Every action auto-expires (via `contain`'s native nftables timeout) and
//!     is written to the same audit log as a manual contain, tagged with the
//!     playbook that fired it.
//!   * Only PUBLIC sources are eligible unless a playbook explicitly opts in,
//!     so a misfire can never lock out LAN or management access.
//!   * The playbook catalogue is fixed and explainable. Operators tune
//!     thresholds and toggle playbooks on/off; they do not author free-form
//!     logic that could misfire in ways nobody can read at 2am.
//!
//! The engine runs as a background thread in the dashboard server (which is
//! itself always-on once installed), evaluating the same attack classification
//! the console shows, on a slow cadence.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use ufw_shared::json::{self, Json, JsonWriter};

use super::attacks::Attack;
use super::contain;

const CONFIG: &str = "/var/lib/unified-firewall/auto-response.json";
const HISTORY: &str = "/var/lib/unified-firewall/auto-response-history.json";
/// A block may never outlive this, even after escalation.
const MAX_TTL: u64 = 7 * 24 * 3600;
/// Offender history older than this is pruned (they have served their time).
const HISTORY_TTL: u64 = 30 * 24 * 3600;
const RECENT_CAP: usize = 100;

/// One playbook. `id`/`name`/`desc` are fixed catalogue metadata; the rest are
/// the operator-tunable, persisted fields.
#[derive(Clone)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub enabled: bool,
    /// Minimum severity to act on: critical|high|medium|low.
    pub min_severity: String,
    /// Minimum denied-packet count from the source.
    pub min_count: u64,
    /// Minimum distinct ports (scan breadth); 0 = any.
    pub min_ports: u64,
    /// Only act on public-internet sources (never LAN/loopback).
    pub public_only: bool,
    /// Only act on sources that appear on an installed threat-intel feed.
    pub known_bad_only: bool,
    /// First-offence block duration, seconds.
    pub base_ttl: u64,
    /// Repeat offenders get progressively longer blocks.
    pub escalate: bool,
}

pub struct Config {
    pub enabled: bool,
    pub rules: Vec<Rule>,
}

/// A block the engine decided to apply.
#[derive(Clone)]
pub struct Decision {
    pub src: String,
    pub rule: String,
    pub ttl: u64,
    pub reason: String,
    pub ts: u64,
}

/// The fixed catalogue, with sensible starting thresholds. `enabled` here is
/// the per-playbook default; the ENGINE is still off until switched on.
fn catalog() -> Vec<Rule> {
    vec![
        Rule {
            id: "known-bad",
            name: "Known-bad source",
            desc: "Contain any source on an installed threat-intel feed, at any severity.",
            enabled: true,
            min_severity: "low".into(),
            min_count: 1,
            min_ports: 0,
            public_only: true,
            known_bad_only: true,
            base_ttl: 24 * 3600,
            escalate: true,
        },
        Rule {
            id: "critical",
            name: "Critical attack",
            desc: "Contain any source classified critical — exploit attempts, injection, RCE.",
            enabled: true,
            min_severity: "critical".into(),
            min_count: 1,
            min_ports: 0,
            public_only: true,
            known_bad_only: false,
            base_ttl: 6 * 3600,
            escalate: true,
        },
        Rule {
            id: "port-scan",
            name: "Aggressive port scan",
            desc: "Contain a source sweeping many distinct ports in a short span.",
            enabled: true,
            min_severity: "medium".into(),
            min_count: 1,
            min_ports: 10,
            public_only: true,
            known_bad_only: false,
            base_ttl: 3600,
            escalate: true,
        },
        Rule {
            id: "brute-force",
            name: "Brute-force / hammering",
            desc: "Contain a source hammering one service with a high denial count.",
            enabled: true,
            min_severity: "high".into(),
            min_count: 40,
            min_ports: 0,
            public_only: true,
            known_bad_only: false,
            base_ttl: 3600,
            escalate: true,
        },
        Rule {
            id: "persistent",
            name: "Persistent high-severity",
            desc: "Contain any high-or-worse source with sustained denials. Off by default.",
            enabled: false,
            min_severity: "high".into(),
            min_count: 20,
            min_ports: 0,
            public_only: true,
            known_bad_only: false,
            base_ttl: 3600,
            escalate: true,
        },
    ]
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Is `ip` a public (internet-routable) address? Stable-std checks only; CGNAT
/// (100.64/10) and 0.0.0.0/8 are handled by hand. A source that fails to parse
/// is treated as non-public (never auto-contained under public_only).
fn is_public(ip: &str) -> bool {
    // Fold an IPv4-mapped IPv6 literal to its v4 form first, or a mapped
    // private/loopback source would slip past the v6 arm as "public".
    match ip.parse::<IpAddr>().map(super::canonical_ip) {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40; // 100.64.0.0/10
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_unspecified()
                || o[0] == 0
                || cgnat)
        }
        Ok(IpAddr::V6(a)) => {
            let s0 = a.segments()[0];
            let link_local = (s0 & 0xffc0) == 0xfe80;
            let ula = (s0 & 0xfe00) == 0xfc00;
            !(a.is_loopback() || a.is_unspecified() || link_local || ula)
        }
        Err(_) => false,
    }
}

fn ttl_for(r: &Rule, prior: u64) -> u64 {
    if !r.escalate {
        return r.base_ttl.min(MAX_TTL);
    }
    let mult = match prior {
        0 => 1,
        1 => 6,
        2 => 24,
        _ => 72,
    };
    r.base_ttl.saturating_mul(mult).min(MAX_TTL)
}

/// Decide which sources to contain. Pure: no side effects, so it is unit-testable.
/// The first enabled playbook (catalogue order = priority) that matches a source
/// wins; already-contained sources are skipped.
pub fn evaluate(
    cfg: &Config,
    attacks: &[Attack],
    contained: &BTreeSet<String>,
    hist: &BTreeMap<String, (u64, u64)>,
    known_bad: &BTreeSet<String>,
) -> Vec<Decision> {
    let mut out = Vec::new();
    if !cfg.enabled {
        return out;
    }
    for a in attacks {
        if a.src.is_empty() || a.src == "this host" || contained.contains(&a.src) {
            continue;
        }
        for r in &cfg.rules {
            if !r.enabled
                || sev_rank(&a.severity) > sev_rank(&r.min_severity)
                || (a.count as u64) < r.min_count
                || (r.min_ports > 0 && (a.ports.len() as u64) < r.min_ports)
                || (r.public_only && !is_public(&a.src))
                || (r.known_bad_only && !known_bad.contains(&a.src))
            {
                continue;
            }
            let prior = hist.get(&a.src).map(|(c, _)| *c).unwrap_or(0);
            out.push(Decision {
                src: a.src.clone(),
                rule: r.name.into(),
                ttl: ttl_for(r, prior),
                reason: format!(
                    "auto:{} sev={} count={} ports={}",
                    r.id,
                    a.severity,
                    a.count,
                    a.ports.len()
                ),
                ts: crate::state::now_unix(),
            });
            break;
        }
    }
    out
}

/// One evaluation pass: load config, classify against the live set, apply blocks.
/// Called by the background thread. No-op (and no log read) when the engine is off.
pub fn tick(attacks: &[Attack]) {
    let cfg = load();
    if !cfg.enabled {
        return;
    }
    let contained: BTreeSet<String> = contain::list().into_iter().map(|c| c.ip).collect();
    // Which of the current sources are on an installed threat-intel feed.
    let feeds = super::threatintel::load();
    let known_bad: BTreeSet<String> = attacks
        .iter()
        .filter(|a| feeds.lookup(&a.src).is_some())
        .map(|a| a.src.clone())
        .collect();
    let mut hist = load_history();
    let decisions = evaluate(&cfg, attacks, &contained, &hist, &known_bad);
    if decisions.is_empty() {
        return;
    }
    let now = crate::state::now_unix();
    let mut changed = false;
    for d in decisions {
        if contain::contain_note(&d.src, d.ttl, &d.reason).is_ok() {
            let e = hist.entry(d.src.clone()).or_insert((0, now));
            e.0 += 1;
            e.1 = now;
            changed = true;
            record_recent(d);
        }
    }
    if changed {
        prune_history(&mut hist, now);
        save_history(&hist);
    }
}

// --- persistence -----------------------------------------------------------

fn load() -> Config {
    let mut rules = catalog();
    let mut enabled = false;
    if let Ok(text) = std::fs::read_to_string(CONFIG) {
        if let Ok(v) = json::parse(&text) {
            enabled = v.get("enabled").and_then(Json::as_bool).unwrap_or(false);
            if let Some(Json::Array(items)) = v.get("rules") {
                for item in items {
                    let Some(id) = item.get("id").and_then(Json::as_str) else {
                        continue;
                    };
                    if let Some(r) = rules.iter_mut().find(|r| r.id == id) {
                        overlay(r, item);
                    }
                }
            }
        }
    }
    Config { enabled, rules }
}

/// Apply the persisted, tunable fields of `item` onto catalogue rule `r`.
fn overlay(r: &mut Rule, item: &Json) {
    if let Some(b) = item.get("enabled").and_then(Json::as_bool) {
        r.enabled = b;
    }
    if let Some(s) = item.get("min_severity").and_then(Json::as_str) {
        if sev_rank(s) < 4 {
            r.min_severity = s.to_string();
        }
    }
    if let Some(n) = item.get("min_count").and_then(Json::as_u64) {
        r.min_count = n;
    }
    if let Some(n) = item.get("min_ports").and_then(Json::as_u64) {
        r.min_ports = n;
    }
    if let Some(b) = item.get("public_only").and_then(Json::as_bool) {
        r.public_only = b;
    }
    if let Some(b) = item.get("known_bad_only").and_then(Json::as_bool) {
        r.known_bad_only = b;
    }
    if let Some(n) = item.get("base_ttl").and_then(Json::as_u64) {
        r.base_ttl = n.clamp(60, MAX_TTL);
    }
    if let Some(b) = item.get("escalate").and_then(Json::as_bool) {
        r.escalate = b;
    }
}

fn save(cfg: &Config) -> Result<(), String> {
    if let Some(dir) = std::path::Path::new(CONFIG).parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    w.bool_field("enabled", cfg.enabled);
    w.begin_array_field("rules");
    for r in &cfg.rules {
        w.begin_object();
        w.str_field("id", r.id);
        w.bool_field("enabled", r.enabled);
        w.str_field("min_severity", &r.min_severity);
        w.u64_field("min_count", r.min_count);
        w.u64_field("min_ports", r.min_ports);
        w.bool_field("public_only", r.public_only);
        w.bool_field("known_bad_only", r.known_bad_only);
        w.u64_field("base_ttl", r.base_ttl);
        w.bool_field("escalate", r.escalate);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    std::fs::write(CONFIG, w.finish()).map_err(|e| e.to_string())
}

fn load_history() -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(HISTORY) {
        if let Ok(Json::Object(pairs)) = json::parse(&text) {
            for (ip, v) in pairs {
                let count = v.get("count").and_then(Json::as_u64).unwrap_or(0);
                let last = v.get("last").and_then(Json::as_u64).unwrap_or(0);
                out.insert(ip, (count, last));
            }
        }
    }
    out
}

fn prune_history(hist: &mut BTreeMap<String, (u64, u64)>, now: u64) {
    hist.retain(|_, (_, last)| now.saturating_sub(*last) < HISTORY_TTL);
}

fn save_history(hist: &BTreeMap<String, (u64, u64)>) {
    if let Some(dir) = std::path::Path::new(HISTORY).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut w = JsonWriter::with_capacity(2048);
    w.begin_object();
    for (ip, (count, last)) in hist {
        w.begin_object_field(ip);
        w.u64_field("count", *count);
        w.u64_field("last", *last);
        w.end_object();
    }
    w.end_object();
    let _ = std::fs::write(HISTORY, w.finish());
}

// --- recent ring (in-memory, newest first) ---------------------------------

fn recent_ring() -> &'static Mutex<Vec<Decision>> {
    static RING: OnceLock<Mutex<Vec<Decision>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(Vec::new()))
}

fn record_recent(d: Decision) {
    if let Ok(mut ring) = recent_ring().lock() {
        ring.insert(0, d);
        ring.truncate(RECENT_CAP);
    }
}

// --- public API used by the server -----------------------------------------

/// Cheap check the background loop uses to skip the expensive log read.
pub fn is_enabled() -> bool {
    std::fs::read_to_string(CONFIG)
        .ok()
        .and_then(|t| json::parse(&t).ok())
        .and_then(|v| v.get("enabled").and_then(Json::as_bool))
        .unwrap_or(false)
}

/// How many auto-blocks the engine has applied since the process started.
pub fn recent_count() -> usize {
    recent_ring().lock().map(|r| r.len()).unwrap_or(0)
}

/// Turn the engine on or off.
pub fn set_enabled(on: bool) -> Result<(), String> {
    let mut cfg = load();
    cfg.enabled = on;
    save(&cfg)
}

/// Update one playbook's tunable fields; `None` leaves a field unchanged.
/// Returns false if the id is not in the catalogue.
#[allow(clippy::too_many_arguments)]
pub fn update_rule(
    id: &str,
    enabled: Option<bool>,
    min_severity: Option<String>,
    min_count: Option<u64>,
    min_ports: Option<u64>,
    public_only: Option<bool>,
    known_bad_only: Option<bool>,
    base_ttl: Option<u64>,
    escalate: Option<bool>,
) -> bool {
    let mut cfg = load();
    let Some(r) = cfg.rules.iter_mut().find(|r| r.id == id) else {
        return false;
    };
    if let Some(b) = enabled {
        r.enabled = b;
    }
    if let Some(s) = min_severity {
        if sev_rank(&s) < 4 {
            r.min_severity = s;
        }
    }
    if let Some(n) = min_count {
        r.min_count = n;
    }
    if let Some(n) = min_ports {
        r.min_ports = n;
    }
    if let Some(b) = public_only {
        r.public_only = b;
    }
    if let Some(b) = known_bad_only {
        r.known_bad_only = b;
    }
    if let Some(n) = base_ttl {
        r.base_ttl = n.clamp(60, MAX_TTL);
    }
    if let Some(b) = escalate {
        r.escalate = b;
    }
    save(&cfg).is_ok()
}

/// The full state the console's Auto-response page renders.
pub fn config_json() -> String {
    let cfg = load();
    let mut w = JsonWriter::with_capacity(4096);
    w.begin_object();
    w.bool_field("enabled", cfg.enabled);
    w.u64_field("max_ttl", MAX_TTL);
    w.begin_array_field("rules");
    for r in &cfg.rules {
        w.begin_object();
        w.str_field("id", r.id);
        w.str_field("name", r.name);
        w.str_field("desc", r.desc);
        w.bool_field("enabled", r.enabled);
        w.str_field("min_severity", &r.min_severity);
        w.u64_field("min_count", r.min_count);
        w.u64_field("min_ports", r.min_ports);
        w.bool_field("public_only", r.public_only);
        w.bool_field("known_bad_only", r.known_bad_only);
        w.u64_field("base_ttl", r.base_ttl);
        w.bool_field("escalate", r.escalate);
        w.end_object();
    }
    w.end_array();
    w.begin_array_field("recent");
    if let Ok(ring) = recent_ring().lock() {
        for d in ring.iter() {
            w.begin_object();
            w.u64_field("ts", d.ts);
            w.str_field("src", &d.src);
            w.str_field("rule", &d.rule);
            w.u64_field("ttl", d.ttl);
            w.str_field("reason", &d.reason);
            w.end_object();
        }
    }
    w.end_array();
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atk(src: &str, sev: &str, count: usize, ports: usize) -> Attack {
        Attack {
            src: src.into(),
            kind: "test".into(),
            severity: sev.into(),
            title: "t".into(),
            detail: "d".into(),
            count,
            ports: (0..ports).map(|p| p.to_string()).collect(),
            first_ts: 0.0,
            last_ts: 0.0,
            rules: vec![],
        }
    }

    fn cfg_on(rules: Vec<Rule>) -> Config {
        Config {
            enabled: true,
            rules,
        }
    }

    #[test]
    fn disabled_engine_never_acts() {
        let cfg = Config {
            enabled: false,
            rules: catalog(),
        };
        let d = evaluate(
            &cfg,
            &[atk("203.0.113.9", "critical", 5, 2)],
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn critical_public_source_is_contained() {
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("203.0.113.9", "critical", 1, 1)],
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].src, "203.0.113.9");
        assert_eq!(d[0].ttl, 6 * 3600); // critical base ttl, first offence
    }

    #[test]
    fn private_source_is_never_auto_contained() {
        // A LAN address, even doing something "critical", is skipped: public_only.
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("192.168.1.10", "critical", 50, 20)],
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn already_contained_is_skipped() {
        let mut contained = BTreeSet::new();
        contained.insert("203.0.113.9".to_string());
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("203.0.113.9", "critical", 5, 2)],
            &contained,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn low_severity_below_threshold_is_ignored() {
        // A single low-severity probe on few ports matches no enabled playbook.
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("203.0.113.9", "low", 1, 1)],
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(d.is_empty());
    }

    #[test]
    fn port_scan_breadth_triggers() {
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("198.51.100.7", "medium", 12, 15)],
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule, "Aggressive port scan");
    }

    #[test]
    fn escalation_lengthens_repeat_offenders() {
        let mut hist = BTreeMap::new();
        hist.insert("203.0.113.9".to_string(), (1u64, 0u64)); // one prior block
        let d = evaluate(
            &cfg_on(catalog()),
            &[atk("203.0.113.9", "critical", 1, 1)],
            &BTreeSet::new(),
            &hist,
            &BTreeSet::new(),
        );
        assert_eq!(d[0].ttl, 6 * 3600 * 6); // second offence: x6
    }

    #[test]
    fn escalation_is_capped() {
        assert!(
            ttl_for(
                &Rule {
                    id: "x",
                    name: "x",
                    desc: "x",
                    enabled: true,
                    min_severity: "low".into(),
                    min_count: 0,
                    min_ports: 0,
                    public_only: true,
                    known_bad_only: false,
                    base_ttl: MAX_TTL,
                    escalate: true,
                },
                9
            ) == MAX_TTL
        );
    }

    #[test]
    fn known_bad_only_requires_a_feed_hit() {
        // The "known-bad" playbook (first in the catalogue) only fires for a
        // source present in the threat-intel set — regardless of severity.
        let low = atk("203.0.113.9", "low", 1, 1);
        // Not on a feed: no playbook matches a single low-severity probe.
        assert!(evaluate(
            &cfg_on(catalog()),
            std::slice::from_ref(&low),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        )
        .is_empty());
        // On a feed: the known-bad playbook contains it.
        let mut kb = BTreeSet::new();
        kb.insert("203.0.113.9".to_string());
        let d = evaluate(
            &cfg_on(catalog()),
            std::slice::from_ref(&low),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &kb,
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule, "Known-bad source");
    }

    #[test]
    fn public_classifier() {
        assert!(is_public("203.0.113.9"));
        assert!(is_public("8.8.8.8"));
        assert!(!is_public("192.168.1.1"));
        assert!(!is_public("10.0.0.5"));
        assert!(!is_public("127.0.0.1"));
        assert!(!is_public("100.64.0.1")); // CGNAT
        assert!(!is_public("169.254.1.1")); // link-local
        assert!(!is_public("not-an-ip"));
    }
}
