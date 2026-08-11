//! What `apply` remembers for the dashboard.
//!
//! nftables holds the rules but not the story: which policy file they came
//! from, when it was loaded, and the author's `description:` for each rule —
//! the "why" a denial gets shown with. `apply` and `trial` write that here;
//! `revert` (and the trial watchdog) remove it. Everything is best-effort:
//! the dashboard degrades to what the kernel can tell it when this file is
//! missing or stale, and enforcement never depends on it.

use std::path::Path;

use ufw_shared::json::{self, Json, JsonWriter};

use crate::CompiledRuleset;

/// Lives beside the daemon's state, in the directory the project owns.
pub const STATE_PATH: &str = "/var/lib/unified-firewall/ufw-nft-state.json";

pub struct State {
    pub policy_path: String,
    pub policy_name: String,
    pub revision: u64,
    /// "apply" or "trial".
    pub mode: String,
    /// Unix seconds when the ruleset was loaded.
    pub applied_at: u64,
    /// Trial duration; 0 for a plain apply.
    pub trial_secs: u64,
    pub restrictive: bool,
    /// Rule name → YAML description.
    pub descriptions: Vec<(String, String)>,
}

pub fn record(
    path: &Path,
    compiled: &CompiledRuleset,
    mode: &str,
    trial_secs: u64,
) -> Result<(), String> {
    let dir = Path::new(STATE_PATH)
        .parent()
        .expect("constant has a parent");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let mut w = JsonWriter::with_capacity(4096);
    w.begin_object();
    w.str_field("policy_path", &path.display().to_string());
    w.str_field("policy_name", &compiled.policy_name);
    w.u64_field("revision", compiled.revision);
    w.str_field("mode", mode);
    w.u64_field("applied_at", now_unix());
    w.u64_field("trial_secs", trial_secs);
    w.bool_field("restrictive", compiled.restrictive);
    w.begin_object_field("descriptions");
    for (name, desc) in &compiled.descriptions {
        w.str_field(name, desc);
    }
    w.end_object();
    w.raw_field("policy", &compiled.policy_json);
    w.end_object();

    std::fs::write(STATE_PATH, w.finish()).map_err(|e| format!("{STATE_PATH}: {e}"))
}

pub fn load() -> Option<State> {
    let text = std::fs::read_to_string(STATE_PATH).ok()?;
    let v = json::parse(&text).ok()?;
    let s = |k: &str| v.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let n = |k: &str| v.get(k).and_then(Json::as_u64).unwrap_or(0);
    let mut descriptions = Vec::new();
    if let Some(Json::Object(pairs)) = v.get("descriptions") {
        for (k, d) in pairs {
            if let Some(d) = d.as_str() {
                descriptions.push((k.clone(), d.to_string()));
            }
        }
    }
    Some(State {
        policy_path: s("policy_path"),
        policy_name: s("policy_name"),
        revision: n("revision"),
        mode: s("mode"),
        applied_at: n("applied_at"),
        trial_secs: n("trial_secs"),
        restrictive: v
            .get("restrictive")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        descriptions,
    })
}

pub fn clear() {
    let _ = std::fs::remove_file(STATE_PATH);
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
