//! Egress baseline anomaly detection.
//!
//! [`correlation`](super::correlation) watches what the policy *denied* — the
//! same block fanning out is an incident. This watches the other side: what the
//! policy *allowed*. A permitted flow is, by definition, one the rules did not
//! stop, and that is exactly where exfiltration lives — a compromised but
//! *signed* process reaching a destination it has no business reaching, on a
//! port the policy opened for legitimate use.
//!
//! Signatures cannot catch this because there is no signature for "a
//! destination this identity has never contacted before". Only a baseline can,
//! and a baseline is a strictly simpler object than the correlation window: for
//! each application identity, the set of external destinations it has been seen
//! reaching. The first time an *established* identity reaches a *new* external
//! destination, that is worth an alert.
//!
//! # Why this does not alert on boot
//!
//! An unsupervised baseline that alerted on everything it had not yet seen
//! would alert on everything, because on the first day it has seen nothing.
//! Two gates prevent that, and both must pass before a single alert fires:
//!
//!   - **A learning window.** Nothing an identity does in its first
//!     `learning_secs` is novel; it is how the baseline is built.
//!   - **A minimum baseline.** An identity that has reached only one or two
//!     destinations has not established a pattern worth deviating from.
//!
//! The cost is a cold-start blind spot: a compromise already present when the
//! baseline is first learned is learned as normal. That is inherent to
//! unsupervised baselining, and is documented rather than hidden.
//!
//! # Bounded memory
//!
//! Identities are capped (LRU by last-seen, the same eviction the correlation
//! engine uses); destinations per identity are capped (insertion-order
//! eviction). Each remembered destination is one `u64` — a hash of the peer's
//! network bucketed to a /24 (v4) or /48 (v6), which collapses a CDN's spread
//! of addresses into one destination rather than minting an alert per edge.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::{Decision, Direction};

/// Configuration for the egress baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyConfig {
    /// How long an identity is observed before its baseline is trusted.
    pub learning_secs: u64,
    /// Distinct destinations an identity must reach before deviation means
    /// anything.
    pub min_baseline: usize,
    /// Identities tracked. Beyond this, the least recently seen is dropped.
    pub max_identities: usize,
    /// Destinations remembered per identity.
    pub max_dests_per_identity: usize,
    /// Minimum gap between alerts for the same identity.
    pub realert_interval_secs: u64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        AnomalyConfig {
            learning_secs: 3600,
            min_baseline: 5,
            max_identities: 4096,
            max_dests_per_identity: 256,
            realert_interval_secs: 300,
        }
    }
}

#[derive(Debug, Default)]
struct IdentityState {
    /// O(1) membership over destination-bucket hashes.
    known: HashSet<u64>,
    /// Insertion order, so the cap evicts the oldest destination.
    order: VecDeque<u64>,
    first_seen_us: u64,
    last_seen_us: u64,
    last_alert_us: u64,
}

/// A deviation from an identity's learned egress baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub identity: String,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// How many destinations the identity had learned before this one.
    pub baseline_size: usize,
    /// How long the baseline had been building when this fired.
    pub span_secs: u64,
}

impl Anomaly {
    /// Render as a log event so it travels the same sinks as everything else.
    pub fn to_event(&self, host_id: &str, sequence: u64) -> LogEvent {
        // Decision is `Allow` because that is what happened — the flow was
        // permitted; the anomaly is *that it was novel*. It is an `Alert`, not
        // a `FlowDecision`, so the allow-suppression filter never touches it.
        let mut event = LogEvent::new(
            self.span_end_us(),
            host_id,
            Decision::Allow,
            ufw_shared::constants::RULE_ID_DEFAULT,
            Default::default(),
        );
        event.sequence = sequence;
        event.kind = EventKind::Alert;
        event.severity = Severity::Warning;
        event.message = Some(format!(
            "identity `{}` reached a new external destination {}:{}, not among the \
             {} destination(s) it learned over {}s",
            self.identity,
            self.dst,
            self.dst_port,
            self.baseline_size,
            self.span_secs.max(1),
        ));
        event.tags = vec!["anomaly".into(), "egress-baseline".into()];
        event
    }

    // Only used to stamp the event timestamp; the caller has the real `now`,
    // but keeping the event self-describing avoids threading it through.
    fn span_end_us(&self) -> u64 {
        self.span_secs.saturating_mul(1_000_000)
    }
}

/// Per-identity first-seen-destination baseline over allowed egress.
#[derive(Debug)]
pub struct EgressBaseline {
    config: AnomalyConfig,
    identities: HashMap<String, IdentityState>,
    alerts_raised: u64,
}

impl EgressBaseline {
    pub fn new(config: AnomalyConfig) -> Self {
        EgressBaseline {
            config,
            identities: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_identities(&self) -> usize {
        self.identities.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// Feed an event. Returns an anomaly when an established identity reaches a
    /// destination outside its baseline.
    pub fn observe(&mut self, event: &LogEvent) -> Option<Anomaly> {
        // Egress-only, permitted-only, leaving-the-perimeter-only. Each gate
        // removes a class of noise: inbound is not this identity's choice,
        // denials are correlation's job, and internal traffic is not exfil.
        if event.kind != EventKind::FlowDecision {
            return None;
        }
        if event.decision != Decision::Allow {
            return None;
        }
        if event.direction != Direction::Outbound {
            return None;
        }
        if !event.perimeter_crossing {
            return None;
        }

        // No identity, nothing to baseline. Same derivation as
        // `LogEvent::correlation_key`: prefer the content hash, fall back to
        // the path, because the hash is stable across a binary's reinstalls.
        let identity = event.identity.as_ref()?;
        let id_key = identity
            .sha256_hex
            .clone()
            .unwrap_or_else(|| identity.path.clone());
        if id_key.is_empty() {
            return None;
        }

        let now = event.timestamp_us;
        let dst_ip = event.five_tuple.dst_ip;
        let dst_port = event.five_tuple.dst_port;
        let dkey = dest_key(dst_ip);

        self.evict_if_needed(now);

        let max_dests = self.config.max_dests_per_identity;
        let min_baseline = self.config.min_baseline;
        let learning_us = self.config.learning_secs.saturating_mul(1_000_000);
        let realert_us = self.config.realert_interval_secs.saturating_mul(1_000_000);

        let state = self.identities.entry(id_key.clone()).or_default();
        if state.first_seen_us == 0 {
            state.first_seen_us = now;
        }
        state.last_seen_us = now;

        // Already known: routine, learned-good egress.
        if state.known.contains(&dkey) {
            return None;
        }

        // Novel destination. Record it (bounded), then decide.
        state.known.insert(dkey);
        state.order.push_back(dkey);
        while state.order.len() > max_dests {
            if let Some(old) = state.order.pop_front() {
                state.known.remove(&old);
            }
        }

        // Warm-up: still inside the learning window, or the baseline is too
        // thin to deviate from. Either way, learn silently.
        let learning = now.saturating_sub(state.first_seen_us) < learning_us;
        if learning || state.known.len() <= min_baseline {
            return None;
        }

        // Established baseline, genuinely new destination — but rate-limited so
        // one busy identity does not mint an alert per novel peer.
        if state.last_alert_us != 0 && now.saturating_sub(state.last_alert_us) < realert_us {
            return None;
        }
        state.last_alert_us = now;

        self.alerts_raised += 1;
        Some(Anomaly {
            identity: id_key,
            dst: dst_ip,
            dst_port,
            baseline_size: state.known.len().saturating_sub(1),
            span_secs: now.saturating_sub(state.first_seen_us) / 1_000_000,
        })
    }

    /// Drop the least-recently-seen identities when the table is full.
    fn evict_if_needed(&mut self, now: u64) {
        if self.identities.len() < self.config.max_identities {
            return;
        }
        // A long window: an identity is worth remembering well past the
        // learning period, so evict only when genuinely full.
        let stale_us = self
            .config
            .learning_secs
            .saturating_mul(2)
            .saturating_mul(1_000_000);
        self.identities
            .retain(|_, s| now.saturating_sub(s.last_seen_us) <= stale_us);

        while self.identities.len() >= self.config.max_identities {
            let Some(oldest) = self
                .identities
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.identities.remove(&oldest);
        }
    }

    /// Drop identities not seen for well over the learning window. Called on a
    /// timer so a quiet daemon does not hold a stale table forever.
    pub fn expire(&mut self, now_us: u64) {
        let stale_us = self
            .config
            .learning_secs
            .saturating_mul(2)
            .saturating_mul(1_000_000);
        self.identities
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= stale_us);
    }
}

/// A destination's identity for baselining: the peer network bucketed to a /24
/// (v4) or /48 (v6), hashed. Bucketing collapses a CDN's many edge addresses
/// into one destination, so a service that answers from a rotating pool is
/// learned once rather than alerting forever.
fn dest_key(ip: IpAddr) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1], o[2]].hash(&mut h);
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[..6].hash(&mut h);
        }
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::log_types::{FiveTuple, IdentitySummary};
    use ufw_shared::policy_types::{Protocol, Zone};

    const SECOND: u64 = 1_000_000;

    /// An allowed, perimeter-crossing egress flow from `app` to `dst`, at
    /// `at_secs`. Time is injected through the event, never read from a clock,
    /// so the warm-up and window logic is deterministic.
    fn allow(app: &str, dst: &str, at_secs: u64) -> LogEvent {
        let mut e = LogEvent::new(
            at_secs * SECOND,
            "host-a",
            Decision::Allow,
            42,
            FiveTuple {
                protocol: Protocol::Tcp,
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 40000,
                dst_ip: dst.parse().unwrap(),
                dst_port: 443,
            },
        );
        e.direction = Direction::Outbound;
        e.remote_zone = Zone::External;
        e.perimeter_crossing = true;
        e.identity = Some(IdentitySummary {
            pid: 1,
            path: app.into(),
            sha256_hex: None,
            signer: None,
            trust: None,
        });
        e
    }

    /// A short learning window and small baseline so tests reach "established"
    /// quickly.
    fn engine() -> EgressBaseline {
        EgressBaseline::new(AnomalyConfig {
            learning_secs: 100,
            min_baseline: 3,
            realert_interval_secs: 0,
            ..Default::default()
        })
    }

    /// Learn `n` distinct destinations, ending at `end_secs`, so the baseline
    /// is both wide enough and old enough to be established.
    fn establish(e: &mut EgressBaseline, app: &str) {
        for i in 0..5u32 {
            let dst = format!("198.51.{}.10", i);
            e.observe(&allow(app, &dst, 10 + i as u64));
        }
    }

    #[test]
    fn a_novel_destination_after_the_baseline_is_established_alerts() {
        let mut e = engine();
        establish(&mut e, "/opt/app");
        // 200s in: past the 100s learning window, baseline of 5 > min 3.
        let a = e
            .observe(&allow("/opt/app", "203.0.113.9", 200))
            .expect("a new external destination should alert");
        assert_eq!(a.dst.to_string(), "203.0.113.9");
        assert_eq!(a.dst_port, 443);
        assert!(a.baseline_size >= 3);
        assert_eq!(e.alerts_raised(), 1);
    }

    #[test]
    fn a_destination_already_in_the_baseline_does_not_alert() {
        let mut e = engine();
        establish(&mut e, "/opt/app");
        // 198.51.2.10 was learned during warm-up; reaching it again is routine.
        assert!(e.observe(&allow("/opt/app", "198.51.2.10", 200)).is_none());
        assert_eq!(e.alerts_raised(), 0);
    }

    #[test]
    fn destinations_seen_during_warm_up_never_alert() {
        let mut e = engine();
        // Every one of these is inside the 100s learning window.
        for i in 0..20u32 {
            let dst = format!("203.0.{}.{}", i / 256, i % 256);
            assert!(
                e.observe(&allow("/opt/app", &dst, 10 + i as u64)).is_none(),
                "nothing learned during warm-up is an anomaly"
            );
        }
        assert_eq!(e.alerts_raised(), 0);
    }

    #[test]
    fn a_new_destination_within_the_first_few_still_does_not_alert() {
        // Past the time window but baseline still <= min_baseline.
        let mut e = EgressBaseline::new(AnomalyConfig {
            learning_secs: 10,
            min_baseline: 5,
            realert_interval_secs: 0,
            ..Default::default()
        });
        // Two destinations, both after the time window: baseline is 2, under 5.
        assert!(e.observe(&allow("/opt/app", "203.0.113.1", 100)).is_none());
        assert!(e.observe(&allow("/opt/app", "203.0.113.2", 110)).is_none());
        assert_eq!(e.alerts_raised(), 0);
    }

    #[test]
    fn denied_internal_and_inbound_flows_are_ignored() {
        let mut e = engine();
        establish(&mut e, "/opt/app");

        let mut denied = allow("/opt/app", "203.0.113.9", 200);
        denied.decision = Decision::Deny;
        assert!(e.observe(&denied).is_none());

        let mut internal = allow("/opt/app", "203.0.113.9", 201);
        internal.perimeter_crossing = false;
        assert!(e.observe(&internal).is_none());

        let mut inbound = allow("/opt/app", "203.0.113.9", 202);
        inbound.direction = Direction::Inbound;
        assert!(e.observe(&inbound).is_none());

        assert_eq!(e.alerts_raised(), 0, "none of these are novel egress");
    }

    #[test]
    fn an_alert_event_does_not_feed_the_detector() {
        let mut e = engine();
        establish(&mut e, "/opt/app");
        let a = e.observe(&allow("/opt/app", "203.0.113.9", 200)).unwrap();
        let event = a.to_event("host-a", 1);
        // Feeding the alert back must not itself be treated as egress.
        assert!(e.observe(&event).is_none());
    }

    #[test]
    fn re_alerting_is_rate_limited_per_identity() {
        let mut e = EgressBaseline::new(AnomalyConfig {
            learning_secs: 100,
            min_baseline: 3,
            realert_interval_secs: 60,
            ..Default::default()
        });
        establish(&mut e, "/opt/app");
        // Distinct /24s, so each is a genuinely distinct destination.
        assert!(e.observe(&allow("/opt/app", "203.0.113.1", 200)).is_some());
        // A second novel destination inside the re-alert interval stays quiet.
        assert!(e.observe(&allow("/opt/app", "203.0.114.1", 210)).is_none());
        assert_eq!(e.alerts_raised(), 1);
        // Past the interval, it fires again.
        assert!(e.observe(&allow("/opt/app", "203.0.115.1", 300)).is_some());
        assert_eq!(e.alerts_raised(), 2);
    }

    #[test]
    fn a_cdn_pool_bucketed_to_a_prefix_is_one_destination() {
        let mut e = engine();
        establish(&mut e, "/opt/app");
        // Same /24, different hosts: one destination after the baseline.
        assert!(e.observe(&allow("/opt/app", "203.0.113.10", 200)).is_some());
        assert!(
            e.observe(&allow("/opt/app", "203.0.113.20", 210)).is_none(),
            "the same /24 is the same destination"
        );
    }

    #[test]
    fn the_identity_table_stays_bounded() {
        let mut e = EgressBaseline::new(AnomalyConfig {
            max_identities: 32,
            ..Default::default()
        });
        for i in 0..500u32 {
            let app = format!("/proc/{i}/exe");
            e.observe(&allow(&app, "203.0.113.9", 10 + i as u64));
        }
        assert!(
            e.tracked_identities() <= 32,
            "grew to {}",
            e.tracked_identities()
        );
    }

    #[test]
    fn destinations_per_identity_stay_bounded() {
        let mut e = EgressBaseline::new(AnomalyConfig {
            learning_secs: 0,
            min_baseline: 0,
            max_dests_per_identity: 8,
            realert_interval_secs: 0,
            ..Default::default()
        });
        for i in 0..100u32 {
            let dst = format!("198.51.{}.{}", i / 256, i % 256);
            e.observe(&allow("/opt/app", &dst, 10 + i as u64));
        }
        let state = e.identities.values().next().unwrap();
        assert!(state.order.len() <= 8, "grew to {}", state.order.len());
        assert!(state.known.len() <= 8);
    }

    #[test]
    fn expiring_clears_stale_identities() {
        let mut e = engine();
        e.observe(&allow("/opt/app", "203.0.113.9", 10));
        assert_eq!(e.tracked_identities(), 1);
        // Well past 2× the learning window.
        e.expire(1_000_000 * SECOND);
        assert_eq!(e.tracked_identities(), 0);
    }

    #[test]
    fn an_anomaly_renders_as_an_alert_log_event() {
        let mut e = engine();
        establish(&mut e, "/opt/dropper");
        let a = e
            .observe(&allow("/opt/dropper", "203.0.113.9", 200))
            .unwrap();
        let event = a.to_event("host-a", 7);
        let text = event.to_json();
        let v = ufw_shared::json::parse(&text).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("alert"));
        let tags: Vec<_> = v
            .get("tags")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        assert!(tags.contains(&"anomaly"));
        let message = v.get("message").unwrap().as_str().unwrap();
        assert!(message.contains("203.0.113.9"));
        assert!(message.contains("new external destination"));
    }
}
