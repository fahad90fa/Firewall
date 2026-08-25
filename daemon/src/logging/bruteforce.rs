//! Credential brute-force / connection-flood detector.
//!
//! A firewall does not see whether a login succeeded — that is application state.
//! What it *does* see is the network signature of a brute-force or
//! credential-stuffing run: one source opening many connections to the same
//! authentication service in a short window. A human logs into SSH once, maybe
//! retries twice; a stuffing tool opens dozens or hundreds of sessions a minute
//! against port 22, 3389, or a web login. That connection *rate* to an auth
//! service is the tell.
//!
//! The detector counts connections per `(source, destination, port)` over a
//! sliding window, and only for ports that host authentication by default
//! (SSH/RDP/FTP/SMB/database/mail/LDAP/VNC) so ordinary chatty services do not
//! trip it. It is direction-agnostic: it catches both an attacker hammering this
//! host's SSH and this host — if compromised — hammering someone else's. Plugs
//! into the logging pipeline like [`super::anomaly`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::Decision;

/// Tuning for the brute-force detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruteForceConfig {
    /// Sliding window over which connection attempts are counted.
    pub window_secs: u64,
    /// Connections to one auth service, from one source, within the window that
    /// mean a brute-force run.
    pub attempt_threshold: usize,
    /// Ports treated as authentication services. A connection to any other port
    /// is ignored, keeping false positives off chatty non-auth services.
    pub auth_ports: HashSet<u16>,
    /// (source, dest, port) triples tracked. Beyond this, the least-recently-seen
    /// is dropped.
    pub max_targets: usize,
    /// Minimum gap between alerts for the same triple.
    pub realert_interval_secs: u64,
}

/// SSH, telnet, FTP(+data), SMTP(+submission), POP3, IMAP, RDP, SMB, LDAP(+S),
/// MSSQL, MySQL, PostgreSQL, VNC — the services credential attacks target.
pub fn default_auth_ports() -> HashSet<u16> {
    [
        22, 23, 21, 20, 25, 587, 110, 143, 3389, 445, 389, 636, 1433, 3306, 5432, 5900, 5901,
    ]
    .into_iter()
    .collect()
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        BruteForceConfig {
            window_secs: 60,
            attempt_threshold: 25,
            auth_ports: default_auth_ports(),
            max_targets: 8192,
            realert_interval_secs: 300,
        }
    }
}

/// A detected brute-force run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruteForceAlert {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// Connections observed in the window.
    pub attempts: usize,
    pub window_secs: u64,
    ts_us: u64,
}

impl BruteForceAlert {
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
            "brute-force: {} opened {} connections to {}:{} within {}s — the rate of a \
             credential-stuffing or password-guessing run",
            self.src, self.attempts, self.dst, self.dst_port, self.window_secs,
        ));
        event.tags = vec!["brute-force".into(), "credential-attack".into()];
        event
    }
}

#[derive(Debug, Default)]
struct TargetState {
    times: VecDeque<u64>,
    last_seen_us: u64,
    last_alert_us: u64,
}

/// Per-(source, dest, port) connection-rate detector for auth services.
#[derive(Debug)]
pub struct BruteForceDetector {
    config: BruteForceConfig,
    targets: HashMap<(IpAddr, IpAddr, u16), TargetState>,
    alerts_raised: u64,
}

impl BruteForceDetector {
    pub fn new(config: BruteForceConfig) -> Self {
        BruteForceDetector {
            config,
            targets: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_targets(&self) -> usize {
        self.targets.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// Feed an event. Returns a [`BruteForceAlert`] when the connection count to
    /// one auth service crosses the threshold within the window.
    pub fn observe(&mut self, event: &LogEvent) -> Option<BruteForceAlert> {
        if event.kind != EventKind::FlowDecision {
            return None;
        }
        let dst_port = event.five_tuple.dst_port;
        if !self.config.auth_ports.contains(&dst_port) {
            return None;
        }
        let src = event.five_tuple.src_ip;
        let dst = event.five_tuple.dst_ip;
        let now = event.timestamp_us;
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        let realert_us = self.config.realert_interval_secs.saturating_mul(1_000_000);

        self.evict_if_needed(now);

        let threshold = self.config.attempt_threshold;
        let state = self.targets.entry((src, dst, dst_port)).or_default();
        state.last_seen_us = now;

        // Age out attempts older than the window.
        while let Some(&front) = state.times.front() {
            if now.saturating_sub(front) > window_us {
                state.times.pop_front();
            } else {
                break;
            }
        }
        state.times.push_back(now);

        if state.times.len() >= threshold
            && (state.last_alert_us == 0 || now.saturating_sub(state.last_alert_us) >= realert_us)
        {
            state.last_alert_us = now;
            let attempts = state.times.len();
            self.alerts_raised += 1;
            return Some(BruteForceAlert {
                src,
                dst,
                dst_port,
                attempts,
                window_secs: self.config.window_secs,
                ts_us: now,
            });
        }
        None
    }

    pub fn expire(&mut self, now_us: u64) {
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        self.targets
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= window_us);
    }

    fn evict_if_needed(&mut self, now_us: u64) {
        if self.targets.len() < self.config.max_targets {
            return;
        }
        self.expire(now_us);
        while self.targets.len() >= self.config.max_targets {
            if let Some(victim) = self
                .targets
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| *k)
            {
                self.targets.remove(&victim);
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

    fn conn(src: &str, dst: &str, port: u16, at_ms: u64) -> LogEvent {
        let mut e = LogEvent::new(
            at_ms * 1000,
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
        );
        e.kind = EventKind::FlowDecision;
        e
    }

    fn detector() -> BruteForceDetector {
        BruteForceDetector::new(BruteForceConfig::default())
    }

    #[test]
    fn ssh_brute_force_fires() {
        let mut d = detector();
        let mut fired = None;
        // 25 SSH connections in ~5s.
        for i in 0..25u64 {
            fired = d.observe(&conn("198.51.100.7", "10.0.0.1", 22, i * 200));
        }
        let a = fired.expect("25 SSH connections in a window is a brute-force run");
        assert_eq!(a.dst_port, 22);
        assert!(a.attempts >= 25);
    }

    #[test]
    fn a_non_auth_port_is_ignored() {
        let mut d = detector();
        // 100 hits on port 443 — a busy web client, not an auth attack.
        for i in 0..100u64 {
            assert!(d
                .observe(&conn("198.51.100.7", "10.0.0.1", 443, i * 50))
                .is_none());
        }
        assert_eq!(d.alerts_raised(), 0);
    }

    #[test]
    fn a_few_logins_do_not_fire() {
        let mut d = detector();
        let mut any = None;
        for i in 0..4u64 {
            any = d.observe(&conn("10.0.0.5", "10.0.0.1", 22, i * 1000));
        }
        assert!(any.is_none(), "a handful of SSH logins is normal");
    }

    #[test]
    fn attempts_spread_beyond_the_window_do_not_fire() {
        let mut d = detector();
        // One attempt every 5s: at most ~12 ever in a 60s window, below 25.
        let mut any = None;
        for i in 0..25u64 {
            any = d.observe(&conn("198.51.100.7", "10.0.0.1", 3389, i * 5000));
        }
        assert!(
            any.is_none(),
            "a slow trickle must not trip the fast-window gate"
        );
    }

    #[test]
    fn alert_is_throttled_per_target() {
        let mut d = detector();
        for i in 0..25u64 {
            d.observe(&conn("198.51.100.7", "10.0.0.1", 22, i * 100));
        }
        // More attempts right after the first alert, still inside realert.
        let again = d.observe(&conn("198.51.100.7", "10.0.0.1", 22, 3000));
        assert!(again.is_none());
        assert_eq!(d.alerts_raised(), 1);
    }

    #[test]
    fn distinct_sources_are_tracked_separately() {
        let mut d = detector();
        // Two attackers, each below threshold, must not pool into one alert.
        for i in 0..15u64 {
            d.observe(&conn("198.51.100.7", "10.0.0.1", 22, i * 100));
            d.observe(&conn("198.51.100.8", "10.0.0.1", 22, i * 100 + 50));
        }
        assert_eq!(d.alerts_raised(), 0);
        assert_eq!(d.tracked_targets(), 2);
        let _ = SEC;
    }
}
