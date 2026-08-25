//! Beaconing / command-and-control periodicity detector.
//!
//! Implants call home on a schedule — every 30s, every 5 minutes, every hour —
//! because an operator needs a predictable check-in to push commands. That
//! regularity is the tell. Any single callback is an ordinary allowed egress
//! flow; it is the *rhythm* across many of them that betrays a C2 channel, and a
//! per-flow allow/deny decision can never see a rhythm.
//!
//! This detector keeps, per `(identity, destination)`, the recent inter-arrival
//! gaps between outbound connections and fires when they are **both numerous and
//! regular** — a low coefficient of variation (`stddev / mean`) over enough
//! samples, with a mean interval in a plausible beacon band. Random human
//! traffic has a high coefficient of variation and never trips it.
//!
//! Honest scope: legitimately periodic clients (NTP, update pollers, monitoring
//! heartbeats to an external collector) are *also* regular, so this raises an
//! alert to be triaged and whitelisted, not a block. It is tuned to need real
//! regularity (default CV ≤ 0.12 over ≥ 8 samples), which most chatty apps do
//! not exhibit. It plugs into the logging pipeline like [`super::anomaly`].

use std::collections::{HashMap, VecDeque};

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::{Decision, Direction};

/// Tuning for the beacon detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconConfig {
    /// Inter-arrival gaps kept per endpoint (the analysis window, in samples).
    pub history: usize,
    /// Minimum gaps before regularity is judged.
    pub min_samples: usize,
    /// Coefficient of variation (stddev/mean) at/below which the cadence counts
    /// as regular, in thousandths (120 = 0.12).
    pub max_cv_milli: u64,
    /// Plausible beacon interval band, in seconds. Outside it — sub-second
    /// chatter or multi-day gaps — is not treated as beaconing.
    pub min_interval_secs: u64,
    pub max_interval_secs: u64,
    /// Endpoints tracked. Beyond this, the least-recently-seen is dropped.
    pub max_endpoints: usize,
    /// Minimum gap between alerts for the same endpoint.
    pub realert_interval_secs: u64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        BeaconConfig {
            history: 32,
            min_samples: 8,
            max_cv_milli: 120, // 0.12
            min_interval_secs: 2,
            max_interval_secs: 6 * 3600,
            max_endpoints: 8192,
            realert_interval_secs: 900,
        }
    }
}

/// A detected periodic callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconAlert {
    pub identity: String,
    pub dst: std::net::IpAddr,
    pub dst_port: u16,
    /// Mean inter-arrival interval, in seconds.
    pub interval_secs: u64,
    /// Coefficient of variation over the window, in thousandths (lower = more
    /// regular).
    pub cv_milli: u64,
    /// How many callbacks the cadence is based on.
    pub samples: usize,
    ts_us: u64,
}

impl BeaconAlert {
    pub fn to_event(&self, host_id: &str, sequence: u64) -> LogEvent {
        let mut event = LogEvent::new(
            self.ts_us,
            host_id,
            Decision::Allow,
            ufw_shared::constants::RULE_ID_DEFAULT,
            Default::default(),
        );
        event.sequence = sequence;
        event.kind = EventKind::Alert;
        event.severity = Severity::Warning;
        event.message = Some(format!(
            "beaconing: `{}` called {}:{} {} times at a regular ~{}s interval (cv {:.2}) \
             — the cadence of a command-and-control check-in",
            self.identity,
            self.dst,
            self.dst_port,
            self.samples,
            self.interval_secs,
            self.cv_milli as f64 / 1000.0,
        ));
        event.tags = vec!["beacon".into(), "c2".into()];
        event
    }
}

#[derive(Debug, Default)]
struct EndpointState {
    last_us: u64,
    gaps: VecDeque<u64>,
    last_seen_us: u64,
    last_alert_us: u64,
}

/// Per-(identity, destination) callback-cadence detector.
#[derive(Debug)]
pub struct BeaconDetector {
    config: BeaconConfig,
    endpoints: HashMap<String, EndpointState>,
    alerts_raised: u64,
}

/// Mean and standard deviation of a gap window (in the gaps' own units).
fn mean_std(gaps: &VecDeque<u64>) -> (f64, f64) {
    let n = gaps.len() as f64;
    if n == 0.0 {
        return (0.0, 0.0);
    }
    let mean = gaps.iter().map(|&g| g as f64).sum::<f64>() / n;
    let var = gaps
        .iter()
        .map(|&g| {
            let d = g as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    (mean, var.sqrt())
}

impl BeaconDetector {
    pub fn new(config: BeaconConfig) -> Self {
        BeaconDetector {
            config,
            endpoints: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_endpoints(&self) -> usize {
        self.endpoints.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// Feed an event. Returns a [`BeaconAlert`] once an endpoint's callbacks are
    /// numerous and regular enough to be a beacon. Outbound, permitted,
    /// perimeter-crossing flows with an identity only — the same gates the
    /// egress baseline uses, because a beacon is an app calling *out*.
    pub fn observe(&mut self, event: &LogEvent) -> Option<BeaconAlert> {
        if event.kind != EventKind::FlowDecision
            || event.decision != Decision::Allow
            || event.direction != Direction::Outbound
            || !event.perimeter_crossing
        {
            return None;
        }
        let identity = event.identity.as_ref()?;
        let id_key = identity
            .sha256_hex
            .clone()
            .unwrap_or_else(|| identity.path.clone());
        if id_key.is_empty() {
            return None;
        }

        let dst = event.five_tuple.dst_ip;
        let dst_port = event.five_tuple.dst_port;
        let now = event.timestamp_us;
        // The endpoint is the (identity, destination-host, port) tuple.
        let key = format!("{id_key}|{dst}|{dst_port}");

        self.evict_if_needed(now);

        let cfg = self.config.clone();
        let state = self.endpoints.entry(key).or_default();
        state.last_seen_us = now;

        // First sighting: record the anchor, no gap yet.
        if state.last_us == 0 {
            state.last_us = now;
            return None;
        }
        let gap = now.saturating_sub(state.last_us);
        state.last_us = now;
        if gap == 0 {
            return None; // same-instant duplicate; not a cadence sample
        }
        state.gaps.push_back(gap);
        while state.gaps.len() > cfg.history {
            state.gaps.pop_front();
        }

        if state.gaps.len() < cfg.min_samples {
            return None;
        }
        if state.last_alert_us != 0
            && now.saturating_sub(state.last_alert_us)
                < cfg.realert_interval_secs.saturating_mul(1_000_000)
        {
            return None;
        }

        let (mean_us, std_us) = mean_std(&state.gaps);
        if mean_us <= 0.0 {
            return None;
        }
        let cv_milli = (std_us / mean_us * 1000.0).round() as u64;
        let mean_secs = (mean_us / 1_000_000.0).round() as u64;

        let regular = cv_milli <= cfg.max_cv_milli;
        let in_band = mean_secs >= cfg.min_interval_secs && mean_secs <= cfg.max_interval_secs;
        if regular && in_band {
            state.last_alert_us = now;
            let samples = state.gaps.len() + 1; // gaps + the anchor callback
            self.alerts_raised += 1;
            return Some(BeaconAlert {
                identity: id_key,
                dst,
                dst_port,
                interval_secs: mean_secs,
                cv_milli,
                samples,
                ts_us: now,
            });
        }
        None
    }

    pub fn expire(&mut self, now_us: u64) {
        // A stale endpoint is one silent for longer than the whole history could
        // span at the max interval — well beyond any live beacon.
        let ttl_us = self
            .config
            .max_interval_secs
            .saturating_mul(self.config.history as u64)
            .saturating_mul(1_000_000)
            .max(3600 * 1_000_000);
        self.endpoints
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= ttl_us);
    }

    fn evict_if_needed(&mut self, now_us: u64) {
        if self.endpoints.len() < self.config.max_endpoints {
            return;
        }
        self.expire(now_us);
        while self.endpoints.len() >= self.config.max_endpoints {
            if let Some(victim) = self
                .endpoints
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| k.clone())
            {
                self.endpoints.remove(&victim);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::log_types::{FiveTuple, IdentitySummary};
    use ufw_shared::policy_types::{Protocol, Zone};

    const SEC: u64 = 1_000_000;

    fn callback(app: &str, dst: &str, at_secs: u64) -> LogEvent {
        let mut e = LogEvent::new(
            at_secs * SEC,
            "host",
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

    fn detector() -> BeaconDetector {
        BeaconDetector::new(BeaconConfig::default())
    }

    #[test]
    fn a_regular_callback_is_a_beacon() {
        let mut d = detector();
        let mut fired = None;
        // Every 60s, ten times.
        for i in 0..10u64 {
            fired = d.observe(&callback("/opt/implant", "203.0.113.5", i * 60));
        }
        let a = fired.expect("a steady 60s cadence is a beacon");
        assert_eq!(a.interval_secs, 60);
        assert!(a.cv_milli <= 120);
        assert!(a.samples >= 8);
    }

    #[test]
    fn jittery_human_traffic_does_not_beacon() {
        let mut d = detector();
        // Irregular gaps (3,47,8,120,15,...) — high coefficient of variation.
        let times = [0u64, 3, 50, 58, 178, 193, 400, 409, 800, 1300];
        let mut any = None;
        for t in times {
            any = d.observe(&callback("/usr/bin/browser", "203.0.113.9", t));
        }
        assert!(
            any.is_none(),
            "irregular traffic must not be called a beacon"
        );
    }

    #[test]
    fn too_few_callbacks_do_not_beacon() {
        let mut d = detector();
        let mut any = None;
        for i in 0..5u64 {
            any = d.observe(&callback("/opt/x", "203.0.113.5", i * 60));
        }
        assert!(any.is_none(), "under min_samples must not fire");
    }

    #[test]
    fn sub_second_chatter_is_out_of_band() {
        let mut d = BeaconDetector::new(BeaconConfig {
            min_interval_secs: 2,
            ..Default::default()
        });
        // Perfectly regular but 100ms apart — a busy RPC loop, not a beacon.
        let mut any = None;
        for i in 0..12u64 {
            let e = callback("/opt/rpc", "203.0.113.5", 0);
            // hand-set microsecond timestamps 100ms apart
            let mut e = e;
            e.timestamp_us = i * 100_000;
            any = d.observe(&e);
        }
        assert!(any.is_none(), "a 0.1s interval is below the beacon band");
    }

    #[test]
    fn inbound_and_identityless_flows_are_ignored() {
        let mut d = detector();
        let mut e = callback("/opt/x", "203.0.113.5", 10);
        e.direction = Direction::Inbound;
        assert!(d.observe(&e).is_none());
        let mut e2 = callback("/opt/x", "203.0.113.5", 20);
        e2.identity = None;
        assert!(d.observe(&e2).is_none());
        assert_eq!(d.tracked_endpoints(), 0);
    }
}
