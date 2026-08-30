//! The enforcement posture when the kernel path is *not* available.
//!
//! # The gap this closes
//!
//! [`crate::watchdog`] governs a data path that faults *after* it was working —
//! it holds the last-installed policy resident and gets loud, so a crash-loop
//! never costs enforcement or reachability. It says nothing about the other
//! case: the daemon comes up (or is left running with
//! `require_kernel_module = false`) and the kernel module is simply *not there*.
//! Nothing is resident to hold. On Linux that means the host has no firewall at
//! all — every packet flows, unfiltered — and until now that outcome was silent
//! and unchosen: `require_kernel_module = false` just printed "continuing
//! without enforcement" and left the box wide open.
//!
//! A firewall must make that a *decision*, taken in advance, in writing. That is
//! [`FailMode`]:
//!
//!   * **`closed`** (the default) — if policy enforcement cannot run, the host
//!     must not sit unprotected. The daemon installs an emergency barrier that
//!     drops traffic by default, *keeping the operator's way in* (loopback,
//!     already-established flows, and the named management ports) so fail-closed
//!     never means locked-out. Confidentiality over connectivity.
//!
//!   * **`open`** — availability over confidentiality. The daemon leaves the
//!     host reachable and unfiltered, and says so at the highest severity. The
//!     right choice only when a blocked host is worse than an exposed one — a
//!     bastion whose reachability is the whole point, a lab.
//!
//! Neither is universally correct, which is exactly why it is a setting and not
//! a hardcoded assumption. What is not acceptable is the previous behaviour:
//! failing open by default, quietly.
//!
//! # Shape
//!
//! Like the watchdog, the decision is a pure function — [`posture`] maps
//! `(FailMode, PathHealth)` to an [`EnforcementPosture`] with no I/O — so the
//! table of "what happens when the path is in state X under mode Y" is a unit
//! test, not something you learn by pulling a kernel module in production. The
//! barrier itself is emitted as text by [`fail_closed_ruleset`] and checked by
//! loading it into a real kernel in the conformance suite.

use std::fmt::Write as _;

/// The operator's declared preference for what happens when policy enforcement
/// cannot run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// Drop traffic by default (keeping management access) when enforcement is
    /// unavailable. The secure default: an unprotected host is the worse
    /// outcome for the data on it.
    #[default]
    Closed,
    /// Leave the host reachable and unfiltered when enforcement is unavailable,
    /// loudly. Availability over confidentiality.
    Open,
}

impl FailMode {
    pub fn parse(s: &str) -> Option<FailMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "closed" | "fail-closed" | "fail_closed" => Some(FailMode::Closed),
            "open" | "fail-open" | "fail_open" => Some(FailMode::Open),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FailMode::Closed => "closed",
            FailMode::Open => "open",
        }
    }
}

/// The state of the enforcement data path, as the daemon sees it at a decision
/// point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHealth {
    /// The kernel module answered the handshake; policy is being enforced in
    /// ring 0.
    Established,
    /// The path faulted but the last-installed policy is still resident in the
    /// kernel (the watchdog's domain). Enforcement continues on that policy.
    LostButResident,
    /// No enforcement is resident: the module never loaded, or a fault left
    /// nothing behind. This is the case [`FailMode`] decides.
    Unavailable,
}

/// What the daemon should do about enforcement, given the mode and the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementPosture {
    /// Enforce the loaded policy in the kernel — the nominal path.
    Enforce,
    /// Keep enforcing the last policy the kernel still holds; do not disturb it.
    HoldLast,
    /// Enforcement is unavailable and the mode is `closed`: install the
    /// emergency default-deny barrier so the host is not left open.
    FailClosedBarrier,
    /// Enforcement is unavailable and the mode is `open`: leave the host
    /// reachable and unfiltered, and alert.
    FailOpenUnprotected,
}

impl EnforcementPosture {
    pub fn as_str(self) -> &'static str {
        match self {
            EnforcementPosture::Enforce => "enforce",
            EnforcementPosture::HoldLast => "hold-last",
            EnforcementPosture::FailClosedBarrier => "fail-closed-barrier",
            EnforcementPosture::FailOpenUnprotected => "fail-open-unprotected",
        }
    }

    /// Whether this posture leaves the host without policy protection. The two
    /// unprotected-or-degraded postures are the ones worth alerting on.
    pub fn is_degraded(self) -> bool {
        !matches!(self, EnforcementPosture::Enforce)
    }
}

/// The whole decision, as a pure function of the mode and the path's health.
///
/// The `FailMode` only bites when the path is [`PathHealth::Unavailable`]: while
/// the kernel is enforcing something — nominal or a held-last policy — there is
/// nothing to fail over to, and the mode is irrelevant.
pub fn posture(mode: FailMode, health: PathHealth) -> EnforcementPosture {
    match health {
        PathHealth::Established => EnforcementPosture::Enforce,
        PathHealth::LostButResident => EnforcementPosture::HoldLast,
        PathHealth::Unavailable => match mode {
            FailMode::Closed => EnforcementPosture::FailClosedBarrier,
            FailMode::Open => EnforcementPosture::FailOpenUnprotected,
        },
    }
}

/// The nftables identifier for the emergency barrier table. Distinct from the
/// compiler's `ufw` table so installing or tearing down the barrier never
/// touches a real policy that may also be present.
pub const FAIL_CLOSED_TABLE: &str = "ufw_failsafe";

/// The emergency fail-closed ruleset, as loadable nftables text.
///
/// This is what "fail closed without locking the operator out" actually means,
/// spelled out:
///
///   * **default-deny** on input and output — the barrier's whole purpose;
///   * **loopback stays up** — the console binds `127.0.0.1`, and half of the
///     daemon's own plumbing is loopback;
///   * **established/related survives** — the SSH session the operator is
///     reading this alert over is an established flow; dropping it would be the
///     lockout this design exists to avoid;
///   * **new connections to the named management ports are admitted** — so the
///     operator can still open a *fresh* session to repair the host, which
///     `established` alone would not allow.
///
/// It sits at a hook priority ahead of the compiler's table so that if both are
/// somehow present, the barrier is not the thing that decides — it is a floor,
/// not a replacement. Everything not named here is dropped: lateral movement,
/// exfil, and inbound scanning all stop while enforcement is down.
pub fn fail_closed_ruleset(mgmt_ports: &[u16]) -> String {
    // De-duplicate and sort for a stable, reviewable ruleset; always keep 22
    // (SSH) so a headless server is never sealed away from its operator.
    let mut ports: Vec<u16> = mgmt_ports.to_vec();
    if !ports.contains(&22) {
        ports.push(22);
    }
    ports.sort_unstable();
    ports.dedup();
    let port_set = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut s = String::new();
    let _ = write!(
        s,
        "#!/usr/sbin/nft -f\n\
         # Unified Firewall EMERGENCY FAIL-CLOSED barrier.\n\
         # Installed because policy enforcement is unavailable and fail_mode = closed.\n\
         # It drops traffic by default while preserving operator access (loopback,\n\
         # established flows, and the management ports below). Remove it once the\n\
         # kernel enforcement path is restored: nft delete table inet {table}\n\
         table inet {table} {{\n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority -300; policy drop;\n\
         \x20       iif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       tcp dport {{ {ports} }} accept\n\
         \x20   }}\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority -300; policy drop;\n\
         \x20       oif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       tcp sport {{ {ports} }} accept\n\
         \x20   }}\n\
         }}\n",
        table = FAIL_CLOSED_TABLE,
        ports = port_set,
    );
    s
}

/// Install the emergency barrier by loading [`fail_closed_ruleset`] with `nft`.
///
/// Best-effort and loud: the daemon reaches here only when enforcement is
/// already down, so a failure to install the barrier is itself a
/// highest-severity event the caller must surface, not swallow. Returns the
/// error text on any failure (no `nft`, not privileged, a load error) so the
/// caller can log exactly why the host could not be sealed.
pub fn install_fail_closed_barrier(mgmt_ports: &[u16]) -> Result<(), String> {
    let ruleset = fail_closed_ruleset(mgmt_ports);
    let path = std::env::temp_dir().join(format!(
        "ufw-failsafe-{}-{}.nft",
        std::process::id(),
        ufw_shared::now_us()
    ));
    std::fs::write(&path, &ruleset).map_err(|e| format!("writing the barrier ruleset: {e}"))?;
    let out = std::process::Command::new("nft")
        .arg("-f")
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "nft rejected the barrier: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("could not run nft to install the barrier: {e}")),
    }
}

/// Remove the emergency barrier, once the enforcement path is restored.
pub fn remove_fail_closed_barrier() -> Result<(), String> {
    let out = std::process::Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(FAIL_CLOSED_TABLE)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        // A missing table is success: the barrier is already gone.
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("No such file") || err.contains("does not exist") {
                Ok(())
            } else {
                Err(format!("nft could not delete the barrier: {}", err.trim()))
            }
        }
        Err(e) => Err(format!("could not run nft to remove the barrier: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the decision table, as fault injection ---------------------------
    //
    // "Inject a fault" here is "hand the decision a PathHealth"; the point is
    // that the posture for every (mode, health) pair is pinned, so a change to
    // the fail-over behaviour is a diff to this table, never a surprise in
    // production.

    #[test]
    fn an_established_path_always_enforces_regardless_of_mode() {
        assert_eq!(
            posture(FailMode::Closed, PathHealth::Established),
            EnforcementPosture::Enforce
        );
        assert_eq!(
            posture(FailMode::Open, PathHealth::Established),
            EnforcementPosture::Enforce
        );
    }

    #[test]
    fn a_resident_but_faulted_path_holds_last_regardless_of_mode() {
        // The watchdog's job; the mode does not override a policy the kernel is
        // still enforcing.
        assert_eq!(
            posture(FailMode::Closed, PathHealth::LostButResident),
            EnforcementPosture::HoldLast
        );
        assert_eq!(
            posture(FailMode::Open, PathHealth::LostButResident),
            EnforcementPosture::HoldLast
        );
    }

    #[test]
    fn an_unavailable_path_is_where_the_mode_decides() {
        assert_eq!(
            posture(FailMode::Closed, PathHealth::Unavailable),
            EnforcementPosture::FailClosedBarrier
        );
        assert_eq!(
            posture(FailMode::Open, PathHealth::Unavailable),
            EnforcementPosture::FailOpenUnprotected
        );
    }

    #[test]
    fn every_posture_but_enforce_is_degraded() {
        assert!(!EnforcementPosture::Enforce.is_degraded());
        assert!(EnforcementPosture::HoldLast.is_degraded());
        assert!(EnforcementPosture::FailClosedBarrier.is_degraded());
        assert!(EnforcementPosture::FailOpenUnprotected.is_degraded());
    }

    #[test]
    fn fail_mode_parses_and_defaults_closed() {
        assert_eq!(FailMode::default(), FailMode::Closed);
        assert_eq!(FailMode::parse("closed"), Some(FailMode::Closed));
        assert_eq!(FailMode::parse("Fail-Open"), Some(FailMode::Open));
        assert_eq!(FailMode::parse("open"), Some(FailMode::Open));
        assert_eq!(FailMode::parse("sideways"), None);
    }

    // --- the barrier ruleset ---------------------------------------------

    #[test]
    fn the_barrier_is_default_deny_on_both_hooks() {
        let r = fail_closed_ruleset(&[9443]);
        assert_eq!(
            r.matches("policy drop;").count(),
            2,
            "both input and output must default-deny"
        );
        assert!(r.contains("table inet ufw_failsafe"));
    }

    #[test]
    fn the_barrier_keeps_the_operator_in() {
        let r = fail_closed_ruleset(&[9443]);
        // Loopback, established, and the management ports (plus SSH, always).
        assert!(r.contains("iif \"lo\" accept"));
        assert!(r.contains("ct state established,related accept"));
        assert!(r.contains("dport { 22, 9443 }"), "ports: {r}");
    }

    #[test]
    fn ssh_is_kept_even_when_not_named() {
        // A caller that forgets to pass 22 must not seal a headless box away.
        let r = fail_closed_ruleset(&[]);
        assert!(r.contains("dport { 22 }"));
    }
}
