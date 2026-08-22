//! Staged rollout orchestration — the *sender* side of fleet distribution.
//!
//! [`crate::fleet`] holds the receive side: a host authenticates a signed
//! bundle, decides its own canary membership, and rolls back on a health
//! regression. What was missing for a rollout *at scale* is the thing that
//! drives the fleet through it — a distribution point that does not push a new
//! policy to a thousand hosts at once, but widens the blast radius one gated
//! wave at a time and stops the instant a wave looks wrong.
//!
//! # Why staged, and why a decision engine
//!
//! One host taking a bad policy is an incident; a thousand taking it in the
//! same minute is an outage. The property that turns the second back into the
//! first is that the mechanism widens gradually and *watches what it already
//! did before doing more*. So a rollout is a sequence of waves — 1%, 10%, 50%,
//! 100% — and the controller advances to the next only when the current one has
//! both **converged** (enough of its cohort reports the new revision) and stayed
//! **healthy** (its denial rate did not blow past baseline, judged by
//! [`crate::fleet::RolloutMonitor`]'s rate-based test). A wave that degrades
//! aborts the rollout where it stands: the bad policy reached at most that
//! wave's cohort, never the fleet.
//!
//! Like the watchdog and the rollback monitor, this is a **pure decision
//! engine**: handed the current time and a report of what the current wave is
//! doing, it returns what the distribution point should do next. It performs no
//! I/O and sends nothing itself — [`cohort`] tells the caller *which* members a
//! wave targets, and the caller signs the bundle at that percentage and hands
//! the cohort to [`crate::fleet_client::distribute`], the existing fan-out
//! transport. That is what makes "does a staged rollout over a thousand hosts
//! converge when healthy, and halt inside the canary when not" a deterministic
//! unit test rather than a thing you can only learn by rolling out to a thousand
//! hosts.
//!
//! # What it is not
//!
//! It is not the transport, and it is not a substitute for runtime hours. The
//! controller decides *whether and how far* to widen; carrying the bytes is
//! [`crate::fleet_client::distribute`], which already exists. And a rollout
//! that is correct in simulation over synthetic hosts still has to be exercised
//! against real ones under real traffic before anyone should trust it with a
//! production fleet — that is the wall-clock gate `production_readiness.md`
//! names, and no commit closes it.

use std::time::Duration;

use crate::fleet::{in_canary, Health};

/// A wave's cohort size, as a percentage of the fleet. Ascending, ending at 100.
type Percent = u8;

/// The plan a rollout follows: a revision, the widening schedule, and the gates
/// each wave must clear before the next begins.
#[derive(Debug, Clone)]
pub struct RolloutPlan {
    pub revision: u64,
    /// Ascending cohort percentages, ending at 100. `[1, 10, 50, 100]` is the
    /// canonical shape: a tiny canary, then order-of-magnitude widenings.
    waves: Vec<Percent>,
    /// How long a wave must hold before it is eligible to advance, even once
    /// converged — the settling window that keeps a rollout from racing past a
    /// regression that has not shown up yet.
    min_soak: Duration,
    /// Fraction of a wave's cohort (percent) that must report the new revision
    /// before the wave counts as converged. 90 by default: a rollout should not
    /// stall forever on a couple of hosts that are down for unrelated reasons.
    converge_ratio: u8,
}

impl RolloutPlan {
    /// Build and validate a plan. The waves must be non-empty, strictly
    /// ascending, within 1..=100, and end at 100 — a rollout that never reaches
    /// the whole fleet is a misconfiguration, not a rollout.
    pub fn new(revision: u64, waves: Vec<Percent>, min_soak: Duration) -> Result<Self, String> {
        if waves.is_empty() {
            return Err("a rollout plan needs at least one wave".into());
        }
        if waves.iter().any(|&p| p == 0 || p > 100) {
            return Err("every wave must be in 1..=100".into());
        }
        if waves.windows(2).any(|w| w[1] <= w[0]) {
            return Err("waves must be strictly ascending".into());
        }
        if *waves.last().unwrap() != 100 {
            return Err("the final wave must be 100% — a rollout reaches the whole fleet".into());
        }
        Ok(RolloutPlan {
            revision,
            waves,
            min_soak,
            converge_ratio: 90,
        })
    }

    /// Override the convergence ratio (percent of a cohort that must report in).
    pub fn with_converge_ratio(mut self, ratio: u8) -> Self {
        self.converge_ratio = ratio.min(100);
        self
    }

    pub fn waves(&self) -> &[Percent] {
        &self.waves
    }
}

/// What the distribution point observes about the wave currently in flight.
#[derive(Debug, Clone)]
pub struct WaveReport {
    /// How many members are in this wave's cohort.
    pub cohort_size: usize,
    /// How many of them report running the plan's revision (or newer).
    pub converged: usize,
    /// The cohort's health, from the same rate-based test a host uses to decide
    /// its own rollback ([`crate::fleet::RolloutMonitor::assess`]).
    pub health: Health,
}

impl WaveReport {
    fn is_converged(&self, ratio: u8) -> bool {
        if self.cohort_size == 0 {
            // An empty cohort (e.g. a 1% wave over a tiny fleet) has nothing to
            // wait for; treat it as converged so the rollout can proceed.
            return true;
        }
        self.converged as u64 * 100 >= self.cohort_size as u64 * ratio as u64
    }
}

/// What the distribution point should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolloutStep {
    /// Keep the current wave as-is: still soaking, or not enough of the cohort
    /// has reported the new revision yet.
    Hold { reason: &'static str },
    /// The current wave cleared its gates. Widen to `to_percent`: re-sign the
    /// bundle at the new canary percentage and distribute to the new cohort.
    Advance { to_percent: Percent },
    /// The final (100%) wave converged and stayed healthy. Done.
    Complete,
    /// A wave's health degraded. Stop widening; the bad policy reached at most
    /// this wave's cohort. The caller triggers rollback on the affected hosts.
    Abort { reason: &'static str },
}

/// Where a rollout currently sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolloutStatus {
    Rolling,
    Complete,
    Aborted,
}

/// Drives one plan across the fleet, one gated wave at a time.
#[derive(Debug, Clone)]
pub struct RolloutController {
    plan: RolloutPlan,
    wave_idx: usize,
    wave_started: Duration,
    status: RolloutStatus,
}

impl RolloutController {
    /// Begin at the first (smallest) wave, timestamped `now`.
    pub fn start(plan: RolloutPlan, now: Duration) -> Self {
        RolloutController {
            plan,
            wave_idx: 0,
            wave_started: now,
            status: RolloutStatus::Rolling,
        }
    }

    pub fn status(&self) -> RolloutStatus {
        self.status
    }

    /// The percentage of the wave currently in flight.
    pub fn current_percent(&self) -> Percent {
        self.plan.waves[self.wave_idx]
    }

    /// The members this wave targets: those in the canary bucket for the current
    /// percentage at this revision. Stable within a rollout and monotonic across
    /// waves (a host in the 10% cohort is always in the 50% cohort), so a host
    /// never leaves a wave it already took.
    pub fn cohort<'a>(&self, members: &'a [String]) -> Vec<&'a str> {
        cohort(members, self.plan.revision, self.current_percent())
    }

    /// Feed the controller a report of the current wave and get the next step.
    /// Mutating: on `Advance` it moves to the next wave and resets the soak
    /// clock; on `Complete`/`Abort` it latches the terminal status. Idempotent
    /// once terminal.
    pub fn on_report(&mut self, now: Duration, report: WaveReport) -> RolloutStep {
        match self.status {
            RolloutStatus::Complete => return RolloutStep::Complete,
            RolloutStatus::Aborted => {
                return RolloutStep::Abort {
                    reason: "rollout already aborted",
                }
            }
            RolloutStatus::Rolling => {}
        }

        // Health first: a degrading wave aborts the rollout wherever it is,
        // before any question of widening. This is the blast-radius bound.
        if let Health::Degraded { .. } = report.health {
            self.status = RolloutStatus::Aborted;
            return RolloutStep::Abort {
                reason: "wave health degraded past the rollback threshold",
            };
        }

        // The settling window: even a converged wave must hold long enough for a
        // slow regression to surface.
        if now.saturating_sub(self.wave_started) < self.plan.min_soak {
            return RolloutStep::Hold { reason: "soaking" };
        }

        // Enough of the cohort must actually be running the new revision.
        if !report.is_converged(self.plan.converge_ratio) {
            return RolloutStep::Hold {
                reason: "awaiting convergence",
            };
        }

        // Converged, healthy, soaked. If this was the whole fleet, we are done;
        // otherwise widen to the next wave.
        if self.current_percent() == 100 {
            self.status = RolloutStatus::Complete;
            RolloutStep::Complete
        } else {
            self.wave_idx += 1;
            self.wave_started = now;
            RolloutStep::Advance {
                to_percent: self.current_percent(),
            }
        }
    }
}

/// The members in the canary bucket for `percent` at `revision` — the cohort a
/// wave targets. A free function so the caller can size a wave without a
/// controller (e.g. to preview a plan).
pub fn cohort(members: &[String], revision: u64, percent: Percent) -> Vec<&str> {
    members
        .iter()
        .filter(|m| in_canary(m, revision, percent))
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::HealthWindow;

    const REV: u64 = 42;

    fn healthy() -> Health {
        Health::Healthy {
            before: 10,
            after: 12,
        }
    }
    fn degraded() -> Health {
        Health::Degraded {
            before: 10,
            after: 80,
            multiplier: 4,
        }
    }

    fn plan() -> RolloutPlan {
        RolloutPlan::new(REV, vec![1, 10, 50, 100], Duration::from_secs(30)).unwrap()
    }

    #[test]
    fn a_plan_must_be_ascending_and_reach_the_whole_fleet() {
        assert!(RolloutPlan::new(1, vec![], Duration::ZERO).is_err());
        assert!(RolloutPlan::new(1, vec![10, 10, 100], Duration::ZERO).is_err()); // not strict
        assert!(RolloutPlan::new(1, vec![50, 10, 100], Duration::ZERO).is_err()); // descending
        assert!(RolloutPlan::new(1, vec![1, 10, 50], Duration::ZERO).is_err()); // never reaches 100
        assert!(RolloutPlan::new(1, vec![0, 100], Duration::ZERO).is_err()); // 0% wave
        assert!(RolloutPlan::new(1, vec![1, 10, 50, 100], Duration::ZERO).is_ok());
    }

    #[test]
    fn a_healthy_wave_holds_until_soaked_then_advances() {
        let mut c = RolloutController::start(plan(), Duration::from_secs(0));
        assert_eq!(c.current_percent(), 1);
        let converged = WaveReport {
            cohort_size: 10,
            converged: 10,
            health: healthy(),
        };
        // Converged and healthy, but the soak window has not elapsed.
        assert_eq!(
            c.on_report(Duration::from_secs(5), converged.clone()),
            RolloutStep::Hold { reason: "soaking" }
        );
        // Past the soak window: advance to the next wave.
        assert_eq!(
            c.on_report(Duration::from_secs(31), converged),
            RolloutStep::Advance { to_percent: 10 }
        );
        assert_eq!(c.current_percent(), 10);
    }

    #[test]
    fn a_wave_that_has_not_converged_holds() {
        let mut c = RolloutController::start(plan(), Duration::ZERO);
        let half = WaveReport {
            cohort_size: 10,
            converged: 5, // 50% < 90% ratio
            health: healthy(),
        };
        assert_eq!(
            c.on_report(Duration::from_secs(60), half),
            RolloutStep::Hold {
                reason: "awaiting convergence"
            }
        );
    }

    #[test]
    fn a_degraded_wave_aborts_immediately_and_latches() {
        let mut c = RolloutController::start(plan(), Duration::ZERO);
        let bad = WaveReport {
            cohort_size: 10,
            converged: 10,
            health: degraded(),
        };
        assert_eq!(
            c.on_report(Duration::from_secs(60), bad),
            RolloutStep::Abort {
                reason: "wave health degraded past the rollback threshold"
            }
        );
        assert_eq!(c.status(), RolloutStatus::Aborted);
        // Latched: further reports stay aborted regardless of health.
        let good = WaveReport {
            cohort_size: 10,
            converged: 10,
            health: healthy(),
        };
        assert!(matches!(
            c.on_report(Duration::from_secs(120), good),
            RolloutStep::Abort { .. }
        ));
    }

    #[test]
    fn health_is_checked_before_soak_and_convergence() {
        // A wave that is both un-soaked and un-converged but *degraded* must
        // still abort — a regression does not get to hide behind "too early".
        let mut c = RolloutController::start(plan(), Duration::ZERO);
        let bad = WaveReport {
            cohort_size: 100,
            converged: 1,
            health: degraded(),
        };
        assert!(matches!(
            c.on_report(Duration::from_secs(1), bad),
            RolloutStep::Abort { .. }
        ));
    }

    #[test]
    fn the_cohort_of_a_wave_is_a_subset_of_the_next() {
        // Monotonicity: a host in the 10% cohort is in the 50% cohort too, so a
        // host never leaves a wave it already took as the rollout widens.
        let members: Vec<String> = (0..2000).map(|i| format!("host-{i}")).collect();
        let c10 = cohort(&members, REV, 10);
        let c50 = cohort(&members, REV, 50);
        let s10: std::collections::BTreeSet<_> = c10.iter().collect();
        let s50: std::collections::BTreeSet<_> = c50.iter().collect();
        assert!(
            s10.is_subset(&s50),
            "10% cohort must be within the 50% cohort"
        );
        // And the sizes are roughly the requested fractions.
        assert!((c10.len() as i64 - 200).abs() < 120);
        assert!((c50.len() as i64 - 1000).abs() < 200);
    }

    /// Convergence-computed health from a synthetic cohort denial rate, so the
    /// scale simulation exercises the same rate-based judgement a real host uses.
    fn health_from_rate(denials: u64, allows: u64) -> Health {
        use crate::fleet::RolloutMonitor;
        let baseline = HealthWindow {
            denials: 10,
            allows: 990,
        };
        let mut m = RolloutMonitor::new(baseline, Duration::ZERO);
        for _ in 0..denials {
            m.record(true);
        }
        for _ in 0..allows {
            m.record(false);
        }
        m.assess(Duration::from_secs(600))
    }

    /// The headline proof: a staged rollout over a thousand hosts converges
    /// wave-by-wave when the policy is healthy, and never pushes past the
    /// current wave's cohort.
    #[test]
    fn a_thousand_host_rollout_converges_wave_by_wave_when_healthy() {
        let members: Vec<String> = (0..1000).map(|i| format!("host-{i}")).collect();
        let mut c = RolloutController::start(plan(), Duration::ZERO);

        let mut now = Duration::from_secs(0);
        let mut widest_cohort = 0usize;
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 100, "rollout should converge in a handful of waves");
            let cohort_members = c.cohort(&members);
            widest_cohort = widest_cohort.max(cohort_members.len());
            // Every host in the cohort has reported the new revision (healthy
            // fleet), and the cohort's denial rate matches baseline.
            let report = WaveReport {
                cohort_size: cohort_members.len(),
                converged: cohort_members.len(),
                health: health_from_rate(12, 988), // ~baseline
            };
            now += Duration::from_secs(31); // past the soak window each round
            match c.on_report(now, report) {
                RolloutStep::Advance { to_percent } => {
                    // Never widen beyond 100, and always to the next planned wave.
                    assert!(to_percent <= 100);
                }
                RolloutStep::Complete => break,
                other => panic!("healthy rollout should advance/complete, got {other:?}"),
            }
        }
        assert_eq!(c.status(), RolloutStatus::Complete);
        // The final wave was the whole fleet.
        assert_eq!(widest_cohort, members.len());
    }

    /// The safety proof: when a wave degrades, the rollout aborts and the bad
    /// policy reached at most that wave's cohort — a bounded blast radius, not
    /// the fleet.
    #[test]
    fn a_regression_at_the_second_wave_is_contained_to_that_cohort() {
        let members: Vec<String> = (0..1000).map(|i| format!("host-{i}")).collect();
        let mut c = RolloutController::start(plan(), Duration::ZERO);
        let mut now = Duration::from_secs(0);

        // Wave 0 (1%): healthy, advance to 10%.
        now += Duration::from_secs(31);
        let w0 = c.cohort(&members).len();
        assert!(matches!(
            c.on_report(
                now,
                WaveReport {
                    cohort_size: w0,
                    converged: w0,
                    health: health_from_rate(12, 988),
                }
            ),
            RolloutStep::Advance { to_percent: 10 }
        ));

        // Wave 1 (10%): the policy turns out to be bad — denials quadruple.
        now += Duration::from_secs(31);
        let w1 = c.cohort(&members).len();
        let step = c.on_report(
            now,
            WaveReport {
                cohort_size: w1,
                converged: w1,
                health: health_from_rate(400, 600), // ~40% denial vs 1% baseline
            },
        );
        assert!(matches!(step, RolloutStep::Abort { .. }));
        assert_eq!(c.status(), RolloutStatus::Aborted);

        // The blast radius: the widest cohort ever targeted was the 10% wave,
        // which is far short of the fleet. A one-shot push would have hit 1000.
        assert!(
            w1 < members.len() / 2,
            "a contained regression must not have reached half the fleet ({w1} of {})",
            members.len()
        );
    }

    #[test]
    fn an_empty_canary_cohort_does_not_stall_the_rollout() {
        // A 1% wave over a 10-host fleet can select zero hosts; the rollout must
        // still make progress rather than waiting forever for an empty cohort.
        let members: Vec<String> = (0..10).map(|i| format!("h-{i}")).collect();
        let mut c = RolloutController::start(plan(), Duration::ZERO);
        let cohort_members = c.cohort(&members);
        let report = WaveReport {
            cohort_size: cohort_members.len(),
            converged: cohort_members.len(),
            health: healthy(),
        };
        let step = c.on_report(Duration::from_secs(31), report);
        assert!(matches!(
            step,
            RolloutStep::Advance { .. } | RolloutStep::Complete
        ));
    }
}
