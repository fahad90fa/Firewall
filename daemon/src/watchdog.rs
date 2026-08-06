//! Fail-safe supervision of the enforcement data path.
//!
//! # The failure this exists to bound
//!
//! Every other safety property in this project is about producing the *right*
//! verdict. This one is about a different question, and on a server it is the
//! more important of the two: what happens when the data path itself faults —
//! the kernel module panics and is reaped, the control channel drops, the
//! daemon's connection to ring 0 dies. A firewall that answers a fault by
//! restarting as fast as it can will, on a machine that is failing to come up
//! cleanly, spin: reconnect, fault, reconnect, fault, at whatever rate the
//! loop allows. That is a CPU fire on a good day and, on a headless server, a
//! box you can no longer reach — because the thing thrashing is the thing that
//! decides whether your SSH session's packets are allowed.
//!
//! The single governing goal here is therefore: **a data-path fault must never
//! cost an operator remote access to the host.** Losing enforcement is a
//! degraded state you can see and fix remotely; losing the ability to *reach*
//! the host to fix it is the one outcome from which there is no remote path
//! back. Everything below trades enforcement continuity for recoverability the
//! moment the data path proves it cannot run stably — because an unreachable
//! server can neither be secured nor repaired, so keeping it reachable strictly
//! dominates.
//!
//! # Shape
//!
//! This is a pure decision engine. It performs no I/O, spawns no threads and
//! never sleeps; it is handed the current time and returns what the caller
//! should do. That is what makes crash-loop behaviour — which is otherwise a
//! thing you can only observe by actually crash-looping a kernel for a while —
//! a unit test. The main loop owns the clock, the sleeping and the reconnect;
//! the watchdog owns only the policy for *how long* and *when to stop trying at
//! speed and get loud instead*.
//!
//! ```text
//!   Nominal ──fault──▶ Recovering(attempt) ──fault×N in window──▶ SafeMode
//!      ▲                     │                                        │
//!      └────────── healthy for a stable window ◀──────────────────────┘
//! ```
//!
//! The escalation ladder mirrors what a service manager does across process
//! restarts (`systemd`'s `StartLimitBurst`/`StartLimitIntervalSec`), pulled
//! in-process so the decision can see health that never crosses a process
//! boundary — a channel that drops and re-establishes without the daemon
//! exiting — and so the response can be *enter a defined safe posture* rather
//! than only *give up and stay down*.

use std::time::Duration;

/// Where the supervisor currently sits on the escalation ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    /// The data path is up and has been stable.
    Nominal,
    /// A fault occurred and the daemon is retrying with backoff. `attempt` is
    /// the number of faults seen inside the current window, so it both drives
    /// the backoff and is the value compared against the crash-loop threshold.
    Recovering { attempt: u32 },
    /// Too many faults inside the window: the data path has proven it cannot
    /// run stably. The daemon stops retrying at speed, holds whatever the kernel
    /// module last enforced, and gets loud so an operator intervenes while the
    /// host is still reachable.
    SafeMode,
}

impl SupervisorState {
    pub fn as_str(self) -> &'static str {
        match self {
            SupervisorState::Nominal => "nominal",
            SupervisorState::Recovering { .. } => "recovering",
            SupervisorState::SafeMode => "safe-mode",
        }
    }

    pub fn is_safe_mode(self) -> bool {
        matches!(self, SupervisorState::SafeMode)
    }
}

/// What the caller should do in response to a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResponse {
    /// Wait `delay`, then attempt to re-establish the data path. `attempt`
    /// counts faults in the current window, for logging.
    Backoff { attempt: u32, delay: Duration },
    /// The crash-loop threshold tripped on this fault. Enter safe mode: stop
    /// fast retries, keep the last-installed kernel policy resident, alert at
    /// the highest severity. `faults` is how many landed inside the window.
    EnterSafeMode { faults: u32 },
    /// Already in safe mode. Keep a slow heartbeat — a reconnect attempt at the
    /// safe cadence, so the host can still self-heal if the underlying fault
    /// clears — without hammering.
    HoldSafe { delay: Duration },
}

impl FaultResponse {
    /// The delay the caller should wait before its next action, whichever
    /// branch this is.
    pub fn delay(self) -> Duration {
        match self {
            FaultResponse::Backoff { delay, .. } => delay,
            FaultResponse::EnterSafeMode { .. } => Duration::ZERO,
            FaultResponse::HoldSafe { delay } => delay,
        }
    }
}

/// Tunables. Defaults are deliberately conservative for a server: quick to
/// retry a one-off blip, quick to *stop* retrying a genuine loop, and slow to
/// trust a recovered path enough to leave safe mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogConfig {
    /// Faults within `window` that trip safe mode. The Nth fault is the one
    /// that trips it, so this is a count of tolerated fast restarts + 1.
    pub max_faults: u32,
    /// Sliding window over which faults are counted. Faults older than this are
    /// forgotten, so an occasional blip once an hour never accumulates into a
    /// crash-loop verdict.
    pub window: Duration,
    /// First backoff delay. Doubles each subsequent attempt within a window.
    pub backoff_initial: Duration,
    /// Ceiling on the backoff, so a long-lived Recovering state settles to a
    /// steady retry cadence rather than growing without bound.
    pub backoff_max: Duration,
    /// Cadence of reconnect attempts once in safe mode. Slower than
    /// `backoff_max`: safe mode means the path is presumed broken, so retries
    /// are a background hope, not the main plan.
    pub safe_retry: Duration,
    /// How long the path must stay healthy before a Recovering supervisor is
    /// declared Nominal and its fault ledger cleared.
    pub recovery_stable: Duration,
    /// How long the path must stay healthy before *safe mode* is left. Longer
    /// than `recovery_stable` on purpose: leaving safe mode re-arms fast
    /// retries, so it takes real evidence of stability to avoid flapping
    /// straight back into a failing path.
    pub safe_stable: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        WatchdogConfig {
            max_faults: 5,
            window: Duration::from_secs(60),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            safe_retry: Duration::from_secs(300),
            recovery_stable: Duration::from_secs(10),
            safe_stable: Duration::from_secs(300),
        }
    }
}

impl WatchdogConfig {
    /// Clamp the tunables into a range that stays coherent regardless of what a
    /// config file asked for. The relationships matter more than the absolute
    /// values: a `backoff_max` below `backoff_initial`, or a `safe_stable`
    /// below `recovery_stable`, would invert the ladder.
    pub fn sanitized(mut self) -> Self {
        self.max_faults = self.max_faults.max(1);
        self.window = self.window.max(Duration::from_secs(1));
        self.backoff_initial = self.backoff_initial.max(Duration::from_millis(50));
        self.backoff_max = self.backoff_max.max(self.backoff_initial);
        self.safe_retry = self.safe_retry.max(self.backoff_max);
        self.recovery_stable = self.recovery_stable.max(Duration::from_secs(1));
        self.safe_stable = self.safe_stable.max(self.recovery_stable);
        self
    }
}

/// A bounded record of recent fault times, in microseconds since the epoch.
///
/// Bounded because an unbounded one would be a slow memory leak keyed on
/// exactly the event — repeated faults — this component exists to survive. Once
/// `max_faults` faults are in the window the verdict is already safe mode, so
/// keeping more than that many timestamps buys nothing.
#[derive(Debug, Clone)]
struct FaultLedger {
    times: Vec<u64>,
    capacity: usize,
}

impl FaultLedger {
    fn new(capacity: usize) -> Self {
        FaultLedger {
            times: Vec::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    /// Drop faults older than the window ending at `now`.
    fn prune(&mut self, now: u64, window_us: u64) {
        let cutoff = now.saturating_sub(window_us);
        self.times.retain(|&t| t >= cutoff);
    }

    /// Record a fault and return how many are now in the ledger.
    fn record(&mut self, now: u64) -> u32 {
        if self.times.len() >= self.capacity {
            // Keep the most recent: they are what a crash-loop verdict rests on.
            self.times.remove(0);
        }
        self.times.push(now);
        self.times.len() as u32
    }

    fn clear(&mut self) {
        self.times.clear();
    }

    fn len(&self) -> u32 {
        self.times.len() as u32
    }
}

/// The supervisor. One per daemon; fed every data-path health transition.
#[derive(Debug, Clone)]
pub struct Watchdog {
    config: WatchdogConfig,
    state: SupervisorState,
    ledger: FaultLedger,
    /// Time of the most recent fault, used to measure the healthy stretch that
    /// justifies leaving Recovering or SafeMode.
    last_fault_us: u64,
    /// Total faults ever seen, for reporting. Never pruned.
    total_faults: u64,
    /// Total times safe mode has been entered, for reporting.
    safe_mode_entries: u64,
}

impl Watchdog {
    pub fn new(config: WatchdogConfig) -> Self {
        let config = config.sanitized();
        let capacity = config.max_faults as usize;
        Watchdog {
            config,
            state: SupervisorState::Nominal,
            ledger: FaultLedger::new(capacity),
            last_fault_us: 0,
            total_faults: 0,
            safe_mode_entries: 0,
        }
    }

    pub fn state(&self) -> SupervisorState {
        self.state
    }

    pub fn total_faults(&self) -> u64 {
        self.total_faults
    }

    pub fn safe_mode_entries(&self) -> u64 {
        self.safe_mode_entries
    }

    /// The number of faults currently counted inside the window.
    pub fn faults_in_window(&self) -> u32 {
        self.ledger.len()
    }

    /// Record a data-path fault at time `now` (microseconds since the epoch)
    /// and decide the response.
    pub fn on_fault(&mut self, now: u64) -> FaultResponse {
        self.total_faults = self.total_faults.saturating_add(1);
        self.last_fault_us = now;

        // Once in safe mode a fault is expected — the path is presumed broken —
        // so it neither escalates further nor resets anything. It just paces the
        // next slow retry.
        if self.state == SupervisorState::SafeMode {
            return FaultResponse::HoldSafe {
                delay: self.config.safe_retry,
            };
        }

        let window_us = duration_us(self.config.window);
        self.ledger.prune(now, window_us);
        let attempt = self.ledger.record(now);

        if attempt >= self.config.max_faults {
            self.state = SupervisorState::SafeMode;
            self.safe_mode_entries = self.safe_mode_entries.saturating_add(1);
            return FaultResponse::EnterSafeMode { faults: attempt };
        }

        self.state = SupervisorState::Recovering { attempt };
        FaultResponse::Backoff {
            attempt,
            delay: self.backoff_for(attempt),
        }
    }

    /// Record that the data path is healthy at time `now`. Returns `true` when
    /// this observation *restored* the supervisor to Nominal — the caller logs
    /// a recovery and re-arms normal operation — and `false` when the path is
    /// simply up (already Nominal) or not yet stable enough to trust.
    pub fn on_healthy(&mut self, now: u64) -> bool {
        match self.state {
            SupervisorState::Nominal => false,
            SupervisorState::Recovering { .. } => {
                if healthy_for(now, self.last_fault_us, self.config.recovery_stable) {
                    self.reset();
                    true
                } else {
                    false
                }
            }
            SupervisorState::SafeMode => {
                if healthy_for(now, self.last_fault_us, self.config.safe_stable) {
                    self.reset();
                    true
                } else {
                    false
                }
            }
        }
    }

    fn reset(&mut self) {
        self.state = SupervisorState::Nominal;
        self.ledger.clear();
    }

    /// Exponential backoff, `initial << (attempt - 1)`, capped at `backoff_max`
    /// and computed without overflow at any attempt count.
    fn backoff_for(&self, attempt: u32) -> Duration {
        let initial = duration_us(self.config.backoff_initial);
        let max = duration_us(self.config.backoff_max);
        // `attempt` is at least 1 here. Shift in u128 and saturate so a large
        // attempt can never wrap the multiply; then clamp to the ceiling.
        let shift = attempt.saturating_sub(1).min(63);
        let scaled = (initial as u128) << shift;
        let capped = scaled.min(max as u128) as u64;
        Duration::from_micros(capped)
    }
}

fn duration_us(d: Duration) -> u64 {
    d.as_micros().min(u64::MAX as u128) as u64
}

/// Has the path been healthy for at least `stable` since the last fault?
///
/// A clock that appears to move backwards (`now < last_fault_us`) is treated as
/// "not yet stable" rather than as a huge positive interval — the fail-safe
/// direction, since the cost of waiting one more window is nothing and the cost
/// of a spurious recovery is re-arming fast retries into a still-broken path.
fn healthy_for(now: u64, last_fault_us: u64, stable: Duration) -> bool {
    now.checked_sub(last_fault_us)
        .map(|elapsed| elapsed >= duration_us(stable))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000; // one second in microseconds

    fn cfg() -> WatchdogConfig {
        WatchdogConfig {
            max_faults: 3,
            window: Duration::from_secs(60),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(8),
            safe_retry: Duration::from_secs(300),
            recovery_stable: Duration::from_secs(10),
            safe_stable: Duration::from_secs(120),
        }
        .sanitized()
    }

    #[test]
    fn a_fresh_watchdog_is_nominal() {
        let w = Watchdog::new(cfg());
        assert_eq!(w.state(), SupervisorState::Nominal);
        assert_eq!(w.faults_in_window(), 0);
    }

    #[test]
    fn a_single_fault_backs_off_and_does_not_escalate() {
        let mut w = Watchdog::new(cfg());
        let r = w.on_fault(100 * S);
        assert_eq!(
            r,
            FaultResponse::Backoff {
                attempt: 1,
                delay: Duration::from_millis(500)
            }
        );
        assert!(matches!(w.state(), SupervisorState::Recovering { attempt: 1 }));
    }

    #[test]
    fn backoff_doubles_then_saturates_at_the_ceiling() {
        let mut w = Watchdog::new(
            WatchdogConfig {
                max_faults: 100, // don't trip safe mode; we're measuring backoff
                backoff_initial: Duration::from_millis(500),
                backoff_max: Duration::from_secs(8),
                window: Duration::from_secs(3600),
                ..cfg()
            }
            .sanitized(),
        );
        // 0.5s, 1s, 2s, 4s, 8s, then capped at 8s.
        let expect_ms = [500u64, 1000, 2000, 4000, 8000, 8000, 8000];
        for (i, ms) in expect_ms.iter().enumerate() {
            let r = w.on_fault((i as u64 + 1) * S);
            match r {
                FaultResponse::Backoff { delay, .. } => {
                    assert_eq!(delay, Duration::from_millis(*ms), "attempt {}", i + 1);
                }
                other => panic!("attempt {}: expected backoff, got {other:?}", i + 1),
            }
        }
    }

    #[test]
    fn the_nth_fault_in_the_window_trips_safe_mode() {
        let mut w = Watchdog::new(cfg()); // max_faults = 3
        assert!(matches!(w.on_fault(1 * S), FaultResponse::Backoff { .. }));
        assert!(matches!(w.on_fault(2 * S), FaultResponse::Backoff { .. }));
        let r = w.on_fault(3 * S);
        assert_eq!(r, FaultResponse::EnterSafeMode { faults: 3 });
        assert_eq!(w.state(), SupervisorState::SafeMode);
        assert_eq!(w.safe_mode_entries(), 1);
    }

    #[test]
    fn faults_spread_wider_than_the_window_never_trip_safe_mode() {
        let mut w = Watchdog::new(cfg()); // window 60s, max 3
        // One fault every 100s: the window only ever holds one at a time.
        for i in 0..10 {
            let r = w.on_fault(i * 100 * S);
            assert!(
                matches!(r, FaultResponse::Backoff { attempt: 1, .. }),
                "iteration {i}: {r:?}"
            );
        }
        assert_eq!(w.state(), SupervisorState::Recovering { attempt: 1 });
    }

    #[test]
    fn health_restores_nominal_only_after_the_stable_window() {
        let mut w = Watchdog::new(cfg()); // recovery_stable = 10s
        w.on_fault(100 * S);
        assert!(matches!(w.state(), SupervisorState::Recovering { .. }));

        // Too soon: 5s of health is not enough.
        assert!(!w.on_healthy(105 * S));
        assert!(matches!(w.state(), SupervisorState::Recovering { .. }));

        // 10s of health: restored.
        assert!(w.on_healthy(110 * S));
        assert_eq!(w.state(), SupervisorState::Nominal);
        assert_eq!(w.faults_in_window(), 0);
    }

    #[test]
    fn recovery_clears_the_ledger_so_the_next_loop_starts_fresh() {
        let mut w = Watchdog::new(cfg()); // max 3
        w.on_fault(1 * S);
        w.on_fault(2 * S);
        // Recover.
        assert!(w.on_healthy(2 * S + 20 * S));
        // Two more faults must not trip safe mode: the earlier two were cleared.
        assert!(matches!(w.on_fault(100 * S), FaultResponse::Backoff { attempt: 1, .. }));
        assert!(matches!(w.on_fault(101 * S), FaultResponse::Backoff { attempt: 2, .. }));
        assert_ne!(w.state(), SupervisorState::SafeMode);
    }

    #[test]
    fn safe_mode_holds_and_paces_slow_retries() {
        let mut w = Watchdog::new(cfg());
        w.on_fault(1 * S);
        w.on_fault(2 * S);
        w.on_fault(3 * S); // -> safe mode
        let r = w.on_fault(4 * S);
        assert_eq!(
            r,
            FaultResponse::HoldSafe {
                delay: Duration::from_secs(300)
            }
        );
        // Still safe mode; entries counter not double-incremented.
        assert_eq!(w.state(), SupervisorState::SafeMode);
        assert_eq!(w.safe_mode_entries(), 1);
    }

    #[test]
    fn leaving_safe_mode_needs_the_longer_stable_window() {
        let mut w = Watchdog::new(cfg()); // safe_stable = 120s
        w.on_fault(1 * S);
        w.on_fault(2 * S);
        w.on_fault(3 * S); // safe mode, last_fault at 3s

        // The recovery_stable window (10s) is NOT enough to leave safe mode.
        assert!(!w.on_healthy(3 * S + 10 * S));
        assert_eq!(w.state(), SupervisorState::SafeMode);

        // The full safe_stable window is.
        assert!(w.on_healthy(3 * S + 120 * S));
        assert_eq!(w.state(), SupervisorState::Nominal);
    }

    #[test]
    fn a_backwards_clock_never_spuriously_recovers() {
        let mut w = Watchdog::new(cfg());
        w.on_fault(1_000 * S);
        // now < last_fault: treated as not-yet-stable, not as a huge interval.
        assert!(!w.on_healthy(10 * S));
        assert!(matches!(w.state(), SupervisorState::Recovering { .. }));
    }

    #[test]
    fn healthy_while_nominal_is_a_no_op() {
        let mut w = Watchdog::new(cfg());
        assert!(!w.on_healthy(5 * S));
        assert_eq!(w.state(), SupervisorState::Nominal);
    }

    #[test]
    fn the_ledger_is_bounded_under_a_sustained_loop() {
        // A watchdog that never leaves safe mode must not grow memory while a
        // machine crash-loops for a week.
        let mut w = Watchdog::new(cfg());
        for i in 0..1_000_000u64 {
            w.on_fault(i);
        }
        // Ledger capacity is max_faults; it never exceeds that.
        assert!(w.faults_in_window() <= cfg().max_faults);
        assert_eq!(w.state(), SupervisorState::SafeMode);
        assert_eq!(w.total_faults(), 1_000_000);
    }

    #[test]
    fn sanitizer_keeps_the_ladder_coherent() {
        // A perverse config: backoff_max below initial, safe_stable below
        // recovery_stable, zero max_faults.
        let c = WatchdogConfig {
            max_faults: 0,
            window: Duration::from_millis(1),
            backoff_initial: Duration::from_secs(10),
            backoff_max: Duration::from_secs(1),
            safe_retry: Duration::from_millis(1),
            recovery_stable: Duration::from_secs(100),
            safe_stable: Duration::from_secs(1),
        }
        .sanitized();
        assert!(c.max_faults >= 1);
        assert!(c.backoff_max >= c.backoff_initial);
        assert!(c.safe_retry >= c.backoff_max);
        assert!(c.safe_stable >= c.recovery_stable);
    }
}
