//! Self-monitoring: the firewall watching itself.
//!
//! A firewall can fail in a way that leaves it *looking* healthy — the process
//! is up, the port answers — while the thing it exists to do has quietly
//! stopped. The log worker thread dies and no detector sees another packet. The
//! SIEM sink starts erroring and every alert since is lost. The event queue
//! saturates and telemetry is silently dropped. The policy on disk drifts from
//! the one being enforced. None of these crash the daemon, so none of them is
//! caught by "is the process running"; each is a blind spot precisely because
//! it is invisible from outside.
//!
//! This module turns those into alerts. It is, like [`crate::watchdog`] and
//! [`crate::failsafe`], a **pure decision engine** — [`SelfMonitor::check`] takes
//! a [`Snapshot`] of counters the daemon already keeps and returns the
//! [`HealthAlert`]s that are newly true, with no I/O and no clock of its own. The
//! caller feeds it a snapshot on a timer and logs whatever comes back. That is
//! what makes "the SIEM sink has been failing for five minutes" a unit test
//! rather than something you discover during an incident.
//!
//! De-duplication is built in: an alert fires when a condition first appears and
//! then not again until a re-alert interval passes, so a persistent fault is a
//! steady heartbeat, not a per-tick flood — and a condition that clears and
//! returns alerts again, because a fault that recurs is news.

use ufw_shared::log_types::Severity;

/// A point-in-time reading of the daemon's own health counters.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    /// Wall-clock microseconds, injected so the monitor never reads a clock.
    pub now_us: u64,
    /// Is the logging/detector worker thread alive? If not, nothing is being
    /// classified — the detectors are stale by definition.
    pub log_worker_running: bool,
    /// Cumulative sink write errors (a failing SIEM/file sink).
    pub sink_errors_total: u64,
    /// Cumulative events dropped because the queue was full (lost telemetry).
    pub dropped_total: u64,
    /// Whether the daemon is supervising a kernel connection it currently has.
    pub kernel_connected: bool,
    /// Whether the daemon expects a kernel connection (so a disconnect is a
    /// fault, not a deliberately module-less run).
    pub supervised: bool,
    /// The ruleset hash the daemon believes it installed, and the one actually
    /// present on disk. When both are known and differ, the enforced policy has
    /// drifted from the source of truth. `None` skips the check for this tick.
    pub policy_installed_hash: Option<[u8; 32]>,
    pub policy_on_disk_hash: Option<[u8; 32]>,
}

/// What kind of self-health problem an alert reports. Distinct kinds so
/// de-duplication is per-condition — a failing sink does not suppress a policy
/// drift alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthKind {
    /// The log/detector worker thread is not running.
    DetectorsStalled,
    /// The event sink is failing to write.
    SinkFailing,
    /// Events are being dropped because the queue is saturated.
    TelemetryDropped,
    /// The kernel path is expected but currently down.
    KernelUnreachable,
    /// The enforced policy differs from the one on disk.
    PolicyDrift,
}

impl HealthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthKind::DetectorsStalled => "detectors-stalled",
            HealthKind::SinkFailing => "sink-failing",
            HealthKind::TelemetryDropped => "telemetry-dropped",
            HealthKind::KernelUnreachable => "kernel-unreachable",
            HealthKind::PolicyDrift => "policy-drift",
        }
    }

    fn severity(self) -> Severity {
        match self {
            // The detectors being down and the enforced policy drifting are the
            // two that mean the firewall is not doing what it claims.
            HealthKind::DetectorsStalled | HealthKind::PolicyDrift => Severity::Critical,
            HealthKind::KernelUnreachable => Severity::Critical,
            HealthKind::SinkFailing | HealthKind::TelemetryDropped => Severity::Warning,
        }
    }
}

/// One self-health alert, ready to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthAlert {
    pub kind: HealthKind,
    pub severity: Severity,
    pub detail: String,
}

/// The number of distinct conditions, for the small fixed-size dedup table.
const KINDS: usize = 5;

fn kind_index(k: HealthKind) -> usize {
    match k {
        HealthKind::DetectorsStalled => 0,
        HealthKind::SinkFailing => 1,
        HealthKind::TelemetryDropped => 2,
        HealthKind::KernelUnreachable => 3,
        HealthKind::PolicyDrift => 4,
    }
}

/// Holds the state a stateless [`evaluate`] cannot: the previous counters (to
/// turn cumulative totals into "rose since last check") and the last time each
/// condition was alerted (to de-duplicate).
pub struct SelfMonitor {
    prev_sink_errors: u64,
    prev_dropped: u64,
    have_prev: bool,
    last_alert_us: [u64; KINDS],
    active: [bool; KINDS],
    realert_us: u64,
}

impl SelfMonitor {
    /// `realert_secs` is how long a persistent condition waits before alerting
    /// again — the heartbeat cadence for an unresolved fault.
    pub fn new(realert_secs: u64) -> Self {
        SelfMonitor {
            prev_sink_errors: 0,
            prev_dropped: 0,
            have_prev: false,
            last_alert_us: [0; KINDS],
            active: [false; KINDS],
            realert_us: realert_secs.saturating_mul(1_000_000),
        }
    }

    /// Evaluate the snapshot and return only the alerts that should be emitted
    /// now — newly-true conditions, and still-true conditions past the re-alert
    /// interval. A condition that has cleared resets, so its next occurrence
    /// alerts immediately.
    pub fn check(&mut self, snap: &Snapshot) -> Vec<HealthAlert> {
        // Delta-based conditions need a previous reading; the first call
        // establishes the baseline and reports nothing counter-derived.
        let sink_delta = if self.have_prev {
            snap.sink_errors_total.saturating_sub(self.prev_sink_errors)
        } else {
            0
        };
        let dropped_delta = if self.have_prev {
            snap.dropped_total.saturating_sub(self.prev_dropped)
        } else {
            0
        };
        self.prev_sink_errors = snap.sink_errors_total;
        self.prev_dropped = snap.dropped_total;
        self.have_prev = true;

        let mut candidates: Vec<HealthAlert> = Vec::new();
        let mut currently = [false; KINDS];

        if !snap.log_worker_running {
            currently[kind_index(HealthKind::DetectorsStalled)] = true;
            candidates.push(alert(
                HealthKind::DetectorsStalled,
                "the logging/detector worker is not running — no traffic is being classified",
            ));
        }
        if sink_delta > 0 {
            currently[kind_index(HealthKind::SinkFailing)] = true;
            candidates.push(alert(
                HealthKind::SinkFailing,
                format!("the event sink failed to write {sink_delta} time(s) since the last check"),
            ));
        }
        if dropped_delta > 0 {
            currently[kind_index(HealthKind::TelemetryDropped)] = true;
            candidates.push(alert(
                HealthKind::TelemetryDropped,
                format!("{dropped_delta} event(s) dropped on a full queue since the last check"),
            ));
        }
        if snap.supervised && !snap.kernel_connected {
            currently[kind_index(HealthKind::KernelUnreachable)] = true;
            candidates.push(alert(
                HealthKind::KernelUnreachable,
                "the kernel enforcement path is expected but currently unreachable",
            ));
        }
        if let (Some(installed), Some(on_disk)) =
            (snap.policy_installed_hash, snap.policy_on_disk_hash)
        {
            if installed != on_disk {
                currently[kind_index(HealthKind::PolicyDrift)] = true;
                candidates.push(alert(
                    HealthKind::PolicyDrift,
                    "the enforced policy differs from the one on disk — a reload was missed or the \
                     ruleset was changed out of band",
                ));
            }
        }

        // Apply de-duplication: emit a candidate if its condition just became
        // true, or if it has stayed true past the re-alert interval. Reset the
        // ledger for any condition that is no longer true.
        let mut out = Vec::new();
        for c in candidates {
            let i = kind_index(c.kind);
            let newly = !self.active[i];
            let stale = snap.now_us.saturating_sub(self.last_alert_us[i]) >= self.realert_us;
            if newly || stale {
                self.last_alert_us[i] = snap.now_us;
                out.push(c);
            }
        }
        self.active = currently;
        out
    }
}

fn alert(kind: HealthKind, detail: impl Into<String>) -> HealthAlert {
    HealthAlert {
        kind,
        severity: kind.severity(),
        detail: detail.into(),
    }
}

/// Stateless evaluation of a snapshot, without de-duplication — every condition
/// that is currently true. Used by the status surface to report the live set,
/// where the caller wants "what is wrong now", not "what is new".
pub fn evaluate(snap: &Snapshot) -> Vec<HealthAlert> {
    let mut out = Vec::new();
    if !snap.log_worker_running {
        out.push(alert(
            HealthKind::DetectorsStalled,
            "the detector worker is not running",
        ));
    }
    if snap.supervised && !snap.kernel_connected {
        out.push(alert(
            HealthKind::KernelUnreachable,
            "the kernel path is unreachable",
        ));
    }
    if let (Some(a), Some(b)) = (snap.policy_installed_hash, snap.policy_on_disk_hash) {
        if a != b {
            out.push(alert(
                HealthKind::PolicyDrift,
                "the enforced policy differs from disk",
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(now_us: u64) -> Snapshot {
        Snapshot {
            now_us,
            log_worker_running: true,
            sink_errors_total: 0,
            dropped_total: 0,
            kernel_connected: true,
            supervised: true,
            policy_installed_hash: Some([7u8; 32]),
            policy_on_disk_hash: Some([7u8; 32]),
        }
    }

    #[test]
    fn a_healthy_snapshot_raises_nothing() {
        let mut m = SelfMonitor::new(60);
        assert!(m.check(&healthy(1_000)).is_empty());
        assert!(m.check(&healthy(2_000)).is_empty());
    }

    #[test]
    fn a_stopped_worker_is_a_critical_detector_alert() {
        let mut m = SelfMonitor::new(60);
        let mut s = healthy(1_000);
        s.log_worker_running = false;
        let alerts = m.check(&s);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, HealthKind::DetectorsStalled);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn a_rising_sink_error_count_fires_once_then_deduplicates() {
        let mut m = SelfMonitor::new(60);
        // Baseline (no prior reading -> no counter-derived alert).
        assert!(m.check(&healthy(1_000)).is_empty());
        // Sink errors rose: fire.
        let mut s = healthy(2_000);
        s.sink_errors_total = 3;
        let a = m.check(&s);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, HealthKind::SinkFailing);
        // Still failing a moment later, before the re-alert window: silent.
        let mut s2 = healthy(3_000);
        s2.sink_errors_total = 5;
        assert!(m.check(&s2).is_empty());
        // Past the re-alert window with continued errors: heartbeat again.
        let mut s3 = healthy(2_000 + 60_000_000 + 1);
        s3.sink_errors_total = 9;
        assert_eq!(m.check(&s3).len(), 1);
    }

    #[test]
    fn dropped_events_are_a_warning() {
        let mut m = SelfMonitor::new(60);
        assert!(m.check(&healthy(1_000)).is_empty());
        let mut s = healthy(2_000);
        s.dropped_total = 12;
        let a = m.check(&s);
        assert_eq!(a[0].kind, HealthKind::TelemetryDropped);
        assert_eq!(a[0].severity, Severity::Warning);
    }

    #[test]
    fn policy_drift_is_detected_when_hashes_differ() {
        let mut m = SelfMonitor::new(60);
        let mut s = healthy(1_000);
        s.policy_on_disk_hash = Some([9u8; 32]);
        let a = m.check(&s);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, HealthKind::PolicyDrift);
    }

    #[test]
    fn an_unknown_disk_hash_skips_the_drift_check() {
        let mut m = SelfMonitor::new(60);
        let mut s = healthy(1_000);
        s.policy_on_disk_hash = None; // couldn't read disk this tick
        assert!(m.check(&s).is_empty());
    }

    #[test]
    fn a_module_less_run_does_not_alert_on_the_kernel() {
        let mut m = SelfMonitor::new(60);
        let mut s = healthy(1_000);
        s.supervised = false;
        s.kernel_connected = false;
        // Not supervising a kernel: a missing module is a deliberate config, not
        // a fault.
        assert!(m.check(&s).is_empty());
    }

    #[test]
    fn a_cleared_condition_alerts_again_when_it_returns() {
        let mut m = SelfMonitor::new(3600);
        let mut down = healthy(1_000);
        down.log_worker_running = false;
        assert_eq!(m.check(&down).len(), 1); // fires
        assert!(m.check(&healthy(2_000)).is_empty()); // recovered, silent
        let mut down2 = healthy(3_000);
        down2.log_worker_running = false;
        // Returned within the re-alert window, but it *cleared* in between, so
        // it is a new occurrence and alerts immediately.
        assert_eq!(m.check(&down2).len(), 1);
    }
}
