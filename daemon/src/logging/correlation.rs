//! Cross-host event correlation.
//!
//! One host blocking one connection is a log line. The same application
//! identity being blocked reaching the same destination on twelve hosts inside
//! five minutes is an incident — and no single host can see it, because each
//! one only observes its own line.
//!
//! This engine runs in the daemon so that a *single* host still gets the
//! benefit (repeated attempts from one process are just as interesting), and
//! runs identically in a central aggregator fed by every daemon's SIEM stream.
//! The correlation key is deliberately host-independent: it is
//! `application | destination | port | decision`, which is what
//! [`LogEvent::correlation_key`] produces.
//!
//! # Why a sliding window and not a counter
//!
//! A plain counter cannot distinguish "twelve attempts in five minutes" from
//! "twelve attempts over a week". The window keeps timestamps and expires
//! them, so the threshold means what it says. The cost is memory proportional
//! to events-per-window, which is bounded by capping tracked keys and by
//! capping observations per key.

use std::collections::{HashMap, VecDeque};

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::Decision;

/// Configuration for the correlation engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationConfig {
    /// How far back an observation counts.
    pub window_secs: u64,
    /// Observations within the window that constitute a pattern.
    pub threshold: usize,
    /// Distinct keys tracked. Beyond this, the least recently seen is dropped.
    pub max_keys: usize,
    /// Observations retained per key. A key that has already crossed the
    /// threshold does not need an unbounded history to say so again.
    pub max_observations_per_key: usize,
    /// Minimum gap between alerts for the same key, so one persistent pattern
    /// produces a manageable number of alerts rather than one per event.
    pub realert_interval_secs: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        CorrelationConfig {
            window_secs: 300,
            threshold: 3,
            max_keys: 4096,
            max_observations_per_key: 64,
            realert_interval_secs: 300,
        }
    }
}

/// One observation: when, and from where.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    timestamp_us: u64,
    host_id: String,
}

#[derive(Debug, Default)]
struct KeyState {
    observations: VecDeque<Observation>,
    last_alert_us: u64,
    last_seen_us: u64,
    /// Kept for the alert message, which is more useful naming the rule than
    /// repeating the opaque key.
    rule_name: String,
}

/// A pattern the engine recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    pub key: String,
    /// Observations inside the window when the alert fired.
    pub count: usize,
    /// Distinct hosts involved. More than one is what turns a noisy process
    /// into a fleet-wide signal.
    pub hosts: Vec<String>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub rule_name: String,
    pub decision: Decision,
}

impl Correlation {
    pub fn span_secs(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us) / 1_000_000
    }

    /// Render as a log event so a correlation travels down the same sinks as
    /// everything else, rather than needing its own delivery path.
    pub fn to_event(&self, host_id: &str, sequence: u64) -> LogEvent {
        let mut event = LogEvent::new(
            self.last_seen_us,
            host_id,
            self.decision,
            ufw_shared::constants::RULE_ID_DEFAULT,
            Default::default(),
        );
        event.sequence = sequence;
        event.kind = EventKind::Alert;
        // Multi-host patterns are the reason this engine exists; single-host
        // repetition is worth knowing but is not the same thing.
        event.severity = if self.hosts.len() > 1 {
            Severity::Warning
        } else {
            Severity::Notice
        };
        event.rule_name = self.rule_name.clone();
        event.message = Some(format!(
            "correlated pattern: {} events matching `{}` across {} host(s) in {}s",
            self.count,
            self.key,
            self.hosts.len(),
            self.span_secs().max(1)
        ));
        event.tags = vec!["correlation".into()];
        event
    }
}

/// Sliding-window correlation over log events.
#[derive(Debug)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
    keys: HashMap<String, KeyState>,
    alerts_raised: u64,
}

impl CorrelationEngine {
    pub fn new(config: CorrelationConfig) -> Self {
        CorrelationEngine {
            config,
            keys: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.keys.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// Feed an event. Returns a correlation when this event completes a
    /// pattern.
    pub fn observe(&mut self, event: &LogEvent) -> Option<Correlation> {
        // Only denials correlate. A hundred hosts successfully reaching an
        // update server is a working policy, not a pattern worth paging on.
        if event.decision != Decision::Deny {
            return None;
        }
        // A correlation of correlations would feed on its own output.
        if event.kind == EventKind::Alert {
            return None;
        }

        let key = event.correlation_key();
        let now = event.timestamp_us;
        let window_us = self.config.window_secs.saturating_mul(1_000_000);

        self.evict_if_needed(now);

        let max_obs = self.config.max_observations_per_key;
        let state = self.keys.entry(key.clone()).or_default();
        state.last_seen_us = now;
        if !event.rule_name.is_empty() {
            state.rule_name = event.rule_name.clone();
        }
        state.observations.push_back(Observation {
            timestamp_us: now,
            host_id: event.host_id.clone(),
        });

        // Expire anything that fell out of the window, then bound what is
        // left. Both are needed: the window bounds time, the cap bounds a
        // burst inside one window.
        while state
            .observations
            .front()
            .is_some_and(|o| now.saturating_sub(o.timestamp_us) > window_us)
        {
            state.observations.pop_front();
        }
        while state.observations.len() > max_obs {
            state.observations.pop_front();
        }

        if state.observations.len() < self.config.threshold {
            return None;
        }

        let realert_us = self.config.realert_interval_secs.saturating_mul(1_000_000);
        if state.last_alert_us != 0 && now.saturating_sub(state.last_alert_us) < realert_us {
            return None;
        }
        state.last_alert_us = now;

        let mut hosts: Vec<String> = state
            .observations
            .iter()
            .map(|o| o.host_id.clone())
            .collect();
        hosts.sort();
        hosts.dedup();

        let correlation = Correlation {
            key,
            count: state.observations.len(),
            hosts,
            first_seen_us: state
                .observations
                .front()
                .map(|o| o.timestamp_us)
                .unwrap_or(now),
            last_seen_us: now,
            rule_name: state.rule_name.clone(),
            decision: event.decision,
        };
        self.alerts_raised += 1;
        Some(correlation)
    }

    /// Drop the least-recently-seen keys when the table is full.
    fn evict_if_needed(&mut self, now: u64) {
        if self.keys.len() < self.config.max_keys {
            return;
        }
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        self.keys
            .retain(|_, s| now.saturating_sub(s.last_seen_us) <= window_us);

        while self.keys.len() >= self.config.max_keys {
            let Some(oldest) = self
                .keys
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.keys.remove(&oldest);
        }
    }

    /// Drop state older than the window. Called on a timer so a quiet daemon
    /// does not hold a day-old table.
    pub fn expire(&mut self, now_us: u64) {
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        self.keys
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= window_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::log_types::{FiveTuple, IdentitySummary};
    use ufw_shared::policy_types::Protocol;

    const SECOND: u64 = 1_000_000;

    fn deny(host: &str, app: &str, dst: &str, at_secs: u64) -> LogEvent {
        let mut e = LogEvent::new(
            at_secs * SECOND,
            host,
            Decision::Deny,
            42,
            FiveTuple {
                protocol: Protocol::Tcp,
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 40000,
                dst_ip: dst.parse().unwrap(),
                dst_port: 443,
            },
        );
        e.rule_name = "deny-unsigned-egress".into();
        e.identity = Some(IdentitySummary {
            pid: 1,
            path: app.into(),
            sha256_hex: None,
            signer: None,
            trust: None,
        });
        e
    }

    fn engine() -> CorrelationEngine {
        CorrelationEngine::new(CorrelationConfig {
            window_secs: 300,
            threshold: 3,
            ..Default::default()
        })
    }

    #[test]
    fn a_pattern_across_hosts_is_correlated() {
        let mut e = engine();
        assert!(e.observe(&deny("host-a", "/tmp/x", "8.8.8.8", 100)).is_none());
        assert!(e.observe(&deny("host-b", "/tmp/x", "8.8.8.8", 110)).is_none());
        let c = e
            .observe(&deny("host-c", "/tmp/x", "8.8.8.8", 120))
            .expect("threshold reached");

        assert_eq!(c.count, 3);
        assert_eq!(c.hosts, vec!["host-a", "host-b", "host-c"]);
        assert_eq!(c.span_secs(), 20);
        assert_eq!(c.rule_name, "deny-unsigned-egress");
        assert_eq!(e.alerts_raised(), 1);
    }

    #[test]
    fn events_outside_the_window_do_not_accumulate() {
        let mut e = engine();
        e.observe(&deny("a", "/tmp/x", "8.8.8.8", 0));
        e.observe(&deny("b", "/tmp/x", "8.8.8.8", 100));
        // 400s later the first two have aged out, so this is observation 1.
        assert!(
            e.observe(&deny("c", "/tmp/x", "8.8.8.8", 500)).is_none(),
            "the window must actually expire observations"
        );
    }

    #[test]
    fn different_destinations_do_not_correlate_with_each_other() {
        let mut e = engine();
        e.observe(&deny("a", "/tmp/x", "8.8.8.8", 10));
        e.observe(&deny("a", "/tmp/x", "1.1.1.1", 11));
        assert!(e.observe(&deny("a", "/tmp/x", "9.9.9.9", 12)).is_none());
        assert_eq!(e.tracked_keys(), 3);
    }

    #[test]
    fn allowed_flows_are_not_correlated() {
        let mut e = engine();
        for i in 0..10 {
            let mut event = deny("a", "/tmp/x", "8.8.8.8", i);
            event.decision = Decision::Allow;
            assert!(e.observe(&event).is_none());
        }
        assert_eq!(e.tracked_keys(), 0);
    }

    #[test]
    fn a_correlation_does_not_feed_itself() {
        let mut e = engine();
        let c = Correlation {
            key: "k".into(),
            count: 3,
            hosts: vec!["a".into()],
            first_seen_us: 0,
            last_seen_us: SECOND,
            rule_name: "r".into(),
            decision: Decision::Deny,
        };
        let event = c.to_event("a", 1);
        assert!(e.observe(&event).is_none());
    }

    #[test]
    fn re_alerting_is_rate_limited() {
        let mut e = CorrelationEngine::new(CorrelationConfig {
            window_secs: 300,
            threshold: 3,
            realert_interval_secs: 60,
            ..Default::default()
        });
        for i in 0..3 {
            e.observe(&deny("a", "/tmp/x", "8.8.8.8", i));
        }
        assert_eq!(e.alerts_raised(), 1);

        // More of the same inside the re-alert interval stays quiet...
        for i in 3..20 {
            e.observe(&deny("a", "/tmp/x", "8.8.8.8", i));
        }
        assert_eq!(e.alerts_raised(), 1);

        // ...and fires again once the interval passes.
        assert!(e.observe(&deny("a", "/tmp/x", "8.8.8.8", 200)).is_some());
        assert_eq!(e.alerts_raised(), 2);
    }

    #[test]
    fn the_key_table_stays_bounded() {
        let mut e = CorrelationEngine::new(CorrelationConfig {
            window_secs: 300,
            threshold: 3,
            max_keys: 32,
            ..Default::default()
        });
        for i in 0..500u32 {
            let dst = format!("198.51.{}.{}", i / 256, i % 256);
            e.observe(&deny("a", "/tmp/x", &dst, 10 + i as u64));
        }
        assert!(e.tracked_keys() <= 32, "grew to {}", e.tracked_keys());
    }

    #[test]
    fn observations_per_key_stay_bounded() {
        let mut e = CorrelationEngine::new(CorrelationConfig {
            window_secs: 3600,
            threshold: 3,
            max_observations_per_key: 8,
            realert_interval_secs: 0,
            ..Default::default()
        });
        for i in 0..100 {
            e.observe(&deny("a", "/tmp/x", "8.8.8.8", 10 + i));
        }
        let state = e.keys.values().next().unwrap();
        assert!(state.observations.len() <= 8);
    }

    #[test]
    fn a_multi_host_pattern_is_more_severe_than_a_single_host_one() {
        let single = Correlation {
            key: "k".into(),
            count: 3,
            hosts: vec!["a".into()],
            first_seen_us: 0,
            last_seen_us: SECOND,
            rule_name: "r".into(),
            decision: Decision::Deny,
        };
        let fleet = Correlation {
            hosts: vec!["a".into(), "b".into(), "c".into()],
            ..single.clone()
        };
        assert_eq!(single.to_event("a", 1).severity, Severity::Notice);
        assert_eq!(fleet.to_event("a", 1).severity, Severity::Warning);
    }

    #[test]
    fn expiring_clears_stale_state() {
        let mut e = engine();
        e.observe(&deny("a", "/tmp/x", "8.8.8.8", 10));
        assert_eq!(e.tracked_keys(), 1);
        e.expire(10_000 * SECOND);
        assert_eq!(e.tracked_keys(), 0);
    }

    #[test]
    fn a_correlation_renders_as_a_log_event_with_context() {
        let mut e = engine();
        e.observe(&deny("host-a", "/tmp/dropper", "8.8.8.8", 100));
        e.observe(&deny("host-b", "/tmp/dropper", "8.8.8.8", 110));
        let c = e
            .observe(&deny("host-c", "/tmp/dropper", "8.8.8.8", 120))
            .unwrap();
        let event = c.to_event("aggregator", 7);
        let text = event.to_json();
        let v = ufw_shared::json::parse(&text).unwrap();
        assert_eq!(v.get("kind").unwrap().as_str(), Some("alert"));
        let message = v.get("message").unwrap().as_str().unwrap();
        assert!(message.contains("3 events"));
        assert!(message.contains("3 host(s)"));
    }
}
