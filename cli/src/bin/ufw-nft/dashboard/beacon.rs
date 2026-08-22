//! Beaconing detection — spot command-and-control callbacks by their rhythm.
//!
//! Malware that phones home does so on a timer: a connection to the same
//! destination every N seconds, give or take a little jitter. That regularity
//! is the signal. This groups egress events by destination and flags any
//! destination whose inter-arrival times are tightly clustered around a period
//! — a low coefficient of variation over enough samples.
//!
//! Scope, stated honestly: it runs over the egress events this console can see
//! — the ones the firewall logged (denied or alerted). Beaconing to a
//! destination the policy *allows* is not in that log, so full coverage needs
//! the daemon's egress-anomaly flow feed, which sees every outbound flow. The
//! maths here is the detector; wiring it to that feed is the daemon's job. The
//! algorithm is pure and unit-tested so it is correct wherever the samples come
//! from.

use std::collections::BTreeMap;

use super::events::Event;

/// Need at least this many callbacks to call something a rhythm.
const MIN_SAMPLES: usize = 6;
/// Coefficient of variation (stddev/mean) below this is "regular".
const MAX_CV: f64 = 0.25;
/// Plausible beacon periods: sub-second is noise, over a day is not a beacon.
const MIN_PERIOD_SECS: f64 = 1.0;
const MAX_PERIOD_SECS: f64 = 24.0 * 3600.0;

pub struct Beacon {
    pub dst: String,
    pub samples: usize,
    /// Mean period between callbacks, seconds.
    pub period_secs: f64,
    /// Jitter: coefficient of variation (0 = perfectly regular).
    pub cv: f64,
    pub first_ts: f64,
    pub last_ts: f64,
}

/// Detect beaconing destinations in `events`. Pure — no I/O.
pub fn detect(events: &[Event]) -> Vec<Beacon> {
    // Group outbound event timestamps by destination.
    let mut by_dst: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    for e in events {
        if e.dir == "out" && !e.dst.is_empty() && e.ts > 0.0 {
            by_dst.entry(e.dst.as_str()).or_default().push(e.ts);
        }
    }

    let mut out = Vec::new();
    for (dst, mut ts) in by_dst {
        if ts.len() < MIN_SAMPLES {
            continue;
        }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let first = ts[0];
        let last = ts[ts.len() - 1];
        // Inter-arrival deltas.
        let deltas: Vec<f64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
        let n = deltas.len() as f64;
        let mean = deltas.iter().sum::<f64>() / n;
        if !(MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&mean) {
            continue;
        }
        let var = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / n;
        let cv = var.sqrt() / mean;
        if cv <= MAX_CV {
            out.push(Beacon {
                dst: dst.to_string(),
                samples: ts.len(),
                period_secs: mean,
                cv,
                first_ts: first,
                last_ts: last,
            });
        }
    }
    // Most regular (lowest jitter) first.
    out.sort_by(|a, b| a.cv.partial_cmp(&b.cv).unwrap_or(std::cmp::Ordering::Equal));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out_ev(dst: &str, ts: f64) -> Event {
        Event {
            ts,
            action: "alert".into(),
            rule: None,
            dir: "out".into(),
            iface: "eth0".into(),
            src: "10.0.0.5".into(),
            dst: dst.into(),
            proto: "TCP".into(),
            spt: Some(40000),
            dpt: Some(443),
            len: None,
            ttl: None,
            flags: vec![],
            icmp_type: None,
        }
    }

    #[test]
    fn detects_a_regular_beacon() {
        // Every 60s with tiny jitter.
        let mut events = Vec::new();
        let jit = [0.0, 0.5, -0.3, 0.2, -0.1, 0.4, -0.2, 0.1];
        for (i, j) in jit.iter().enumerate() {
            events.push(out_ev("198.51.100.7", 1000.0 + i as f64 * 60.0 + j));
        }
        let b = detect(&events);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].dst, "198.51.100.7");
        assert!((b[0].period_secs - 60.0).abs() < 1.0);
        assert!(b[0].cv < MAX_CV);
    }

    #[test]
    fn ignores_irregular_traffic() {
        // Human-ish bursty timing: wildly varying gaps.
        let gaps = [1.0, 47.0, 3.0, 120.0, 5.0, 200.0, 2.0];
        let mut t = 1000.0;
        let mut events = vec![out_ev("203.0.113.9", t)];
        for g in gaps {
            t += g;
            events.push(out_ev("203.0.113.9", t));
        }
        assert!(detect(&events).is_empty());
    }

    #[test]
    fn ignores_too_few_samples() {
        let events = vec![
            out_ev("1.2.3.4", 1000.0),
            out_ev("1.2.3.4", 1060.0),
            out_ev("1.2.3.4", 1120.0),
        ];
        assert!(detect(&events).is_empty());
    }

    #[test]
    fn inbound_traffic_is_not_beaconing() {
        // Same regular rhythm but inbound — not a callback.
        let mut events = Vec::new();
        for i in 0..8 {
            let mut e = out_ev("198.51.100.7", 1000.0 + i as f64 * 30.0);
            e.dir = "in".into();
            events.push(e);
        }
        assert!(detect(&events).is_empty());
    }
}
