//! Port-scan and network-sweep detector.
//!
//! A new defence layer alongside the egress baseline and the deny-correlation
//! engine. Where the baseline watches *what a host reaches out to* and
//! correlation watches *what got denied*, this watches the **shape of
//! reconnaissance**: one source touching many ports on a host (a vertical port
//! scan) or the same port across many hosts (a horizontal sweep) inside a short
//! window. Both are the first move of almost every intrusion, and both are
//! invisible to a per-flow allow/deny decision — each individual connection is
//! unremarkable; it is the *fan-out* that is the attack.
//!
//! It plugs into the logging pipeline exactly like [`super::anomaly`]: fed
//! `LogEvent`s, it returns a [`ScanAlert`] that renders to an `Alert` event and
//! travels the same sinks. State is bounded (a source cap with LRU eviction and
//! a per-source sliding window), so a flood of spoofed sources cannot grow it
//! without limit.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::Decision;

/// Tuning for the scan detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortScanConfig {
    /// Sliding window over which fan-out is counted.
    pub window_secs: u64,
    /// Distinct ports on a single host, within the window, that mean a vertical
    /// port scan.
    pub distinct_ports: usize,
    /// Distinct hosts on a single port, within the window, that mean a
    /// horizontal sweep.
    pub distinct_hosts: usize,
    /// Sources tracked. Beyond this, the least-recently-seen is dropped.
    pub max_sources: usize,
    /// Distinct (host, port) probes retained per source. A hard ceiling so one
    /// source sweeping a huge address range (e.g. a whole /8 on one port) cannot
    /// grow its window without bound — age-out alone is paced by the attacker.
    /// Far above any detection threshold, so it never affects a verdict.
    pub max_probes_per_source: usize,
    /// Minimum gap between alerts for the same source.
    pub realert_interval_secs: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        PortScanConfig {
            window_secs: 60,
            distinct_ports: 20,
            distinct_hosts: 15,
            max_sources: 4096,
            max_probes_per_source: 1024,
            realert_interval_secs: 120,
        }
    }
}

/// Which fan-out shape fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// Many ports on one host — a port scan.
    VerticalPorts,
    /// One port across many hosts — a service sweep.
    HorizontalHosts,
}

impl ScanKind {
    fn label(self) -> &'static str {
        match self {
            ScanKind::VerticalPorts => "port-scan",
            ScanKind::HorizontalHosts => "network-sweep",
        }
    }
}

/// A detected scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanAlert {
    pub src: IpAddr,
    pub kind: ScanKind,
    /// The fan-out count that crossed the threshold (ports, or hosts).
    pub distinct: usize,
    /// The host being port-scanned (vertical) or the port being swept
    /// (horizontal).
    pub target_host: Option<IpAddr>,
    pub target_port: Option<u16>,
    pub window_secs: u64,
    ts_us: u64,
}

impl ScanAlert {
    /// Render as a log event so it travels the same sinks as everything else.
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
        event.message = Some(match self.kind {
            ScanKind::VerticalPorts => format!(
                "port scan: {} probed {} distinct ports on {} within {}s",
                self.src,
                self.distinct,
                self.target_host
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "a host".into()),
                self.window_secs,
            ),
            ScanKind::HorizontalHosts => format!(
                "network sweep: {} probed port {} across {} distinct hosts within {}s",
                self.src,
                self.target_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
                self.distinct,
                self.window_secs,
            ),
        });
        event.tags = vec!["scan".into(), self.kind.label().into()];
        event
    }
}

/// One observed connection attempt, kept only while inside the window.
#[derive(Debug)]
struct Probe {
    ts_us: u64,
    dst_ip: IpAddr,
    dst_port: u16,
}

#[derive(Debug, Default)]
struct SourceState {
    /// Insertion-ordered probes within the window (oldest at the front).
    probes: VecDeque<Probe>,
    /// Membership so a repeated (host, port) is counted once per window.
    seen: HashSet<(IpAddr, u16)>,
    last_seen_us: u64,
    last_alert_us: u64,
}

/// Per-source sliding-window fan-out detector.
#[derive(Debug)]
pub struct PortScanDetector {
    config: PortScanConfig,
    sources: HashMap<IpAddr, SourceState>,
    alerts_raised: u64,
}

impl PortScanDetector {
    pub fn new(config: PortScanConfig) -> Self {
        PortScanDetector {
            config,
            sources: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// The largest per-source probe window currently retained. Bounded by
    /// `max_probes_per_source`; exposed so the cap can be asserted and metered.
    pub fn max_probes_held(&self) -> usize {
        self.sources
            .values()
            .map(|s| s.probes.len())
            .max()
            .unwrap_or(0)
    }

    /// Feed an event. Returns a [`ScanAlert`] when a source's fan-out crosses a
    /// threshold. Only connection observations (flow decisions) count — the
    /// detector's own alerts and enrichment events never feed back into it.
    pub fn observe(&mut self, event: &LogEvent) -> Option<ScanAlert> {
        if event.kind != EventKind::FlowDecision {
            return None;
        }
        let src = event.five_tuple.src_ip;
        let dst_ip = event.five_tuple.dst_ip;
        let dst_port = event.five_tuple.dst_port;
        let now = event.timestamp_us;
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        let realert_us = self.config.realert_interval_secs.saturating_mul(1_000_000);

        self.evict_if_needed(now);

        let distinct_ports = self.config.distinct_ports;
        let distinct_hosts = self.config.distinct_hosts;
        let max_probes = self
            .config
            .max_probes_per_source
            .max(distinct_ports.max(distinct_hosts));

        let state = self.sources.entry(src).or_default();
        state.last_seen_us = now;

        // Drop probes that have aged out of the window.
        while let Some(front) = state.probes.front() {
            if now.saturating_sub(front.ts_us) > window_us {
                let old = state.probes.pop_front().unwrap();
                state.seen.remove(&(old.dst_ip, old.dst_port));
            } else {
                break;
            }
        }

        // A repeated target within the window adds no new information — the
        // fan-out only grows when a *new* (host, port) appears, which is also
        // the only moment a threshold can be newly crossed.
        if !state.seen.insert((dst_ip, dst_port)) {
            return None;
        }
        state.probes.push_back(Probe {
            ts_us: now,
            dst_ip,
            dst_port,
        });
        // Hard per-source cap: drop the oldest probes (and their `seen` entries)
        // so a single high-fan-out source can never grow this window past the
        // ceiling. Each (host, port) is unique in `probes`, so removing the
        // popped pair from `seen` keeps the two in step.
        while state.probes.len() > max_probes {
            if let Some(old) = state.probes.pop_front() {
                state.seen.remove(&(old.dst_ip, old.dst_port));
            } else {
                break;
            }
        }

        // Throttle: one alert per source per realert interval.
        if state.last_alert_us != 0 && now.saturating_sub(state.last_alert_us) < realert_us {
            return None;
        }

        // Vertical: many distinct ports on the host we just probed.
        let ports_on_host = state
            .probes
            .iter()
            .filter(|p| p.dst_ip == dst_ip)
            .map(|p| p.dst_port)
            .collect::<HashSet<_>>()
            .len();
        if ports_on_host >= distinct_ports {
            state.last_alert_us = now;
            self.alerts_raised += 1;
            return Some(ScanAlert {
                src,
                kind: ScanKind::VerticalPorts,
                distinct: ports_on_host,
                target_host: Some(dst_ip),
                target_port: None,
                window_secs: self.config.window_secs,
                ts_us: now,
            });
        }

        // Horizontal: many distinct hosts on the port we just probed.
        let hosts_on_port = state
            .probes
            .iter()
            .filter(|p| p.dst_port == dst_port)
            .map(|p| p.dst_ip)
            .collect::<HashSet<_>>()
            .len();
        if hosts_on_port >= distinct_hosts {
            state.last_alert_us = now;
            self.alerts_raised += 1;
            return Some(ScanAlert {
                src,
                kind: ScanKind::HorizontalHosts,
                distinct: hosts_on_port,
                target_host: None,
                target_port: Some(dst_port),
                window_secs: self.config.window_secs,
                ts_us: now,
            });
        }

        None
    }

    /// Drop sources whose last activity is older than the window — called on a
    /// timer by the owner, and opportunistically when the source cap is hit.
    pub fn expire(&mut self, now_us: u64) {
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        self.sources
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= window_us);
    }

    /// Enforce the source cap by evicting the least-recently-seen source.
    fn evict_if_needed(&mut self, now_us: u64) {
        if self.sources.len() < self.config.max_sources {
            return;
        }
        self.expire(now_us);
        while self.sources.len() >= self.config.max_sources {
            if let Some(victim) = self
                .sources
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| *k)
            {
                self.sources.remove(&victim);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::log_types::FiveTuple;
    use ufw_shared::policy_types::Protocol;

    const SEC: u64 = 1_000_000;

    fn probe(src: &str, dst: &str, port: u16, at_secs: u64) -> LogEvent {
        LogEvent::new(
            at_secs * SEC,
            "host",
            Decision::Allow,
            42,
            FiveTuple {
                protocol: Protocol::Tcp,
                src_ip: src.parse().unwrap(),
                src_port: 40000,
                dst_ip: dst.parse().unwrap(),
                dst_port: port,
            },
        )
    }

    fn detector() -> PortScanDetector {
        PortScanDetector::new(PortScanConfig {
            window_secs: 60,
            distinct_ports: 20,
            distinct_hosts: 15,
            max_sources: 1024,
            max_probes_per_source: 1024,
            realert_interval_secs: 120,
        })
    }

    #[test]
    fn vertical_port_scan_fires() {
        let mut d = detector();
        let mut fired = None;
        for port in 1..=20u16 {
            fired = d.observe(&probe("10.0.0.9", "10.0.0.1", port, 10));
        }
        let a = fired.expect("20 ports on one host is a port scan");
        assert_eq!(a.kind, ScanKind::VerticalPorts);
        assert_eq!(a.target_host, Some("10.0.0.1".parse().unwrap()));
        assert!(a.distinct >= 20);
    }

    #[test]
    fn horizontal_sweep_fires() {
        let mut d = detector();
        let mut fired = None;
        for host in 1..=15u8 {
            let dst = format!("10.0.0.{host}");
            fired = d.observe(&probe("10.0.0.9", &dst, 22, 10));
        }
        let a = fired.expect("port 22 across 15 hosts is a sweep");
        assert_eq!(a.kind, ScanKind::HorizontalHosts);
        assert_eq!(a.target_port, Some(22));
        assert!(a.distinct >= 15);
    }

    #[test]
    fn ordinary_traffic_does_not_fire() {
        let mut d = detector();
        // A busy client: a handful of ports on a couple of hosts, repeated.
        for _ in 0..50 {
            assert!(d.observe(&probe("10.0.0.9", "10.0.0.1", 443, 10)).is_none());
            assert!(d.observe(&probe("10.0.0.9", "10.0.0.1", 80, 11)).is_none());
            assert!(d.observe(&probe("10.0.0.9", "10.0.0.2", 443, 12)).is_none());
        }
        assert_eq!(d.alerts_raised(), 0);
    }

    #[test]
    fn a_scan_spread_beyond_the_window_does_not_fire() {
        let mut d = detector();
        // One port per 10s: 20 ports take 200s, well past the 60s window, so at
        // most ~6 are ever in-window together.
        let mut any = None;
        for port in 1..=20u16 {
            any = d.observe(&probe("10.0.0.9", "10.0.0.1", port, (port as u64) * 10));
        }
        assert!(
            any.is_none(),
            "a slow scan must not trip the fast-window gate"
        );
    }

    #[test]
    fn alert_is_throttled_per_source() {
        let mut d = detector();
        for port in 1..=20u16 {
            d.observe(&probe("10.0.0.9", "10.0.0.1", port, 10));
        }
        // More new ports immediately after: still within the realert interval.
        let again = d.observe(&probe("10.0.0.9", "10.0.0.1", 21, 11));
        assert!(
            again.is_none(),
            "a second alert must wait out the realert interval"
        );
        assert_eq!(d.alerts_raised(), 1);
    }

    #[test]
    fn per_source_state_is_bounded_under_a_huge_sweep() {
        // One source sweeping thousands of distinct hosts on one port, all
        // inside the window, must not grow its per-source window past the cap —
        // the OOM this fix prevents. Detection still fires (it did long ago).
        let mut d = PortScanDetector::new(PortScanConfig {
            window_secs: 3600,
            distinct_ports: 20,
            distinct_hosts: 15,
            max_sources: 16,
            max_probes_per_source: 64,
            realert_interval_secs: 1,
        });
        for h in 0..5000u32 {
            let dst = std::net::Ipv4Addr::from(0x0a00_0000 | (h & 0x00ff_ffff)).to_string();
            let _ = d.observe(&probe("203.0.113.9", &dst, 22, 10));
        }
        assert!(
            d.max_probes_held() <= 64,
            "per-source window exceeded the cap: {}",
            d.max_probes_held()
        );
        assert!(d.alerts_raised() >= 1, "a 5000-host sweep is still a sweep");
    }

    #[test]
    fn non_flow_events_are_ignored() {
        let mut d = detector();
        let mut e = probe("10.0.0.9", "10.0.0.1", 1, 10);
        e.kind = EventKind::Alert;
        assert!(d.observe(&e).is_none());
        assert_eq!(d.tracked_sources(), 0);
    }
}
