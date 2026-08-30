//! Fleet operation: signed bundles, canary rollout, automatic rollback.
//!
//! One host taking a bad policy is an incident. A thousand hosts taking it in
//! the same minute is an outage, and the thing that makes it an outage rather
//! than an incident is that the mechanism which distributed it is the same
//! mechanism you would use to undo it.
//!
//! Three properties, in the order they matter.
//!
//! # A policy arrives signed, or it does not arrive
//!
//! The channel that carries policy decides what the machine may talk to. TLS
//! authenticates the *connection*; it says nothing about whether the bytes
//! were what the operator approved, and a compromised distribution server
//! terminates TLS legitimately. So the bundle carries its own authentication,
//! verified against a key configured out of band.
//!
//! Two layers, and which one this build has. The default build authenticates a
//! bundle with **HMAC-SHA256**, and its limitation is stated plainly: a shared
//! secret means every host holds the key, so any host could forge a bundle every
//! other host would accept. It is the zero-dependency floor — hand-rolled
//! Ed25519 in a security product would be worse than a keyed hash whose weakness
//! is documented. A **`--features tls`** build, which already pulls a vetted
//! crypto library, adds the layer that closes that gap: a configured Ed25519
//! public key ([`Verifier::with_ed25519_pubkey`], from `api.fleet_ed25519_pubkey`)
//! makes a detached signature *required*, verified with `ring`. The private key
//! lives only with the fleet signer, so a host can verify a bundle without being
//! able to mint one — the property a shared secret cannot give.
//!
//! # A policy reaches a canary before it reaches the fleet
//!
//! A bundle names the fraction of hosts that should take it first. Membership
//! is decided by hashing the host id against the bundle revision, so it is
//! stable for a given rollout — a host does not flap in and out — and
//! different for the next one, so the same hosts are not always the ones that
//! find the breakage.
//!
//! # A policy that makes things worse is undone without asking
//!
//! Rollback triggers on a *rate*, not a count. "More than fifty denials" fires
//! on a busy host running a correct policy; "the denial rate is four times
//! what it was before this policy installed" fires on a policy that broke
//! something, on any host, at any scale.
//!
//! The baseline is taken before the install and the comparison starts after a
//! settling window, because the first seconds after a policy change are noisy
//! by construction: connections that were established under the old rules
//! close and retry under the new ones.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use ufw_shared::hash;

/// A policy bundle as it travels between a distribution point and a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Monotonic across the fleet. A host refuses to move backwards, so a
    /// replayed older bundle cannot roll a fixed host back onto a broken
    /// policy.
    pub revision: u64,
    /// The policy source, not the compiled form: the host compiles it itself
    /// and therefore validates it itself. Shipping compiled rules would mean
    /// trusting the distribution point's compiler version to match.
    pub source: String,
    /// Percentage of the fleet that should take this bundle before the rest.
    /// 100 means everyone at once, which is sometimes correct — a rule that
    /// blocks an active intrusion should not wait for a canary.
    pub canary_percent: u8,
    /// How long a canary host holds the bundle before the rest of the fleet
    /// is eligible. Zero disables the wait, not the canary.
    pub canary_seconds: u64,
    /// HMAC-SHA256 over the fields above, keyed by the fleet secret.
    pub mac: [u8; 32],
    /// Optional detached Ed25519 signature (raw 64 bytes) over the same signed
    /// input the MAC covers. Empty on the default build; on a `--features tls`
    /// build a configured public key makes it required and verified. Unlike the
    /// shared HMAC secret — which every host holds, so every host could forge a
    /// bundle — the Ed25519 private key lives only with the fleet signer, so a
    /// host can verify a bundle without being able to mint one.
    pub sig_ed25519: Vec<u8>,
}

/// What went wrong with a bundle. Every variant names something the operator
/// can act on, because "invalid bundle" is a message that generates a support
/// ticket rather than a fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The MAC did not verify. Either the bytes changed in transit or this
    /// host has the wrong fleet key.
    NotAuthentic,
    /// The bundle is older than what is installed.
    Stale { offered: u64, installed: u64 },
    /// `canary_percent` above 100.
    BadCanary(u8),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::NotAuthentic => write!(
                f,
                "bundle failed authentication: either it was modified in transit or this \
                 host is configured with a different fleet key"
            ),
            BundleError::Stale { offered, installed } => write!(
                f,
                "bundle revision {offered} is older than the installed {installed}; \
                 refusing to move backwards"
            ),
            BundleError::BadCanary(p) => {
                write!(f, "canary_percent {p} is above 100")
            }
        }
    }
}

impl std::error::Error for BundleError {}

/// The bytes a bundle's MAC covers.
///
/// Length-prefixed rather than concatenated. `revision=1, source="ab"` and
/// `revision=1, source="a" + "b"` must not produce the same input, or two
/// different bundles share a MAC and the signature stops distinguishing them.
fn signing_input(revision: u64, source: &str, canary_percent: u8, canary_seconds: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(source.len() + 32);
    out.extend_from_slice(b"ufw-bundle-v1");
    out.extend_from_slice(&revision.to_le_bytes());
    out.extend_from_slice(&(source.len() as u64).to_le_bytes());
    out.extend_from_slice(source.as_bytes());
    out.push(canary_percent);
    out.extend_from_slice(&canary_seconds.to_le_bytes());
    out
}

/// Authenticates bundles against the fleet key, and — on a `tls` build with a
/// public key configured — against a detached Ed25519 signature.
#[derive(Clone)]
pub struct Verifier {
    key: Vec<u8>,
    /// The fleet signer's Ed25519 public key (raw 32 bytes). `None` means the
    /// host verifies the HMAC only, the zero-dependency default.
    ed25519_pubkey: Option<Vec<u8>>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key. A debug line in a log is a key in a log.
        f.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl Verifier {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Verifier {
            key: key.into(),
            ed25519_pubkey: None,
        }
    }

    /// Require, in addition to the HMAC, a valid Ed25519 signature against this
    /// public key. Only enforced on a `--features tls` build; on the default
    /// build the key is stored but there is no verifier to check it, and the
    /// daemon refuses to advertise a guarantee it cannot keep (it logs that the
    /// public key was configured on a non-tls binary).
    pub fn with_ed25519_pubkey(mut self, pubkey: impl Into<Vec<u8>>) -> Self {
        self.ed25519_pubkey = Some(pubkey.into());
        self
    }

    /// Whether a public key is configured (whether or not this binary can check
    /// it) — so the daemon can warn when one is set on a non-tls build.
    pub fn has_ed25519_pubkey(&self) -> bool {
        self.ed25519_pubkey.is_some()
    }

    pub fn sign(&self, bundle: &mut Bundle) {
        bundle.mac = hash::hmac_sha256(
            &self.key,
            &signing_input(
                bundle.revision,
                &bundle.source,
                bundle.canary_percent,
                bundle.canary_seconds,
            ),
        );
    }

    /// Verify a bundle against this host's installed revision.
    pub fn accept(&self, bundle: &Bundle, installed: u64) -> Result<(), BundleError> {
        if bundle.canary_percent > 100 {
            return Err(BundleError::BadCanary(bundle.canary_percent));
        }
        let expected = hash::hmac_sha256(
            &self.key,
            &signing_input(
                bundle.revision,
                &bundle.source,
                bundle.canary_percent,
                bundle.canary_seconds,
            ),
        );
        // Constant time. A comparison that returns early leaks how many
        // leading bytes were right, which is enough to forge a MAC one byte at
        // a time given enough attempts — and a distribution point is exactly
        // somewhere an attacker can retry.
        if !constant_time_eq(&expected, &bundle.mac) {
            return Err(BundleError::NotAuthentic);
        }
        // The public-key layer, when this binary can check it and a key is set.
        // A shared HMAC secret proves the bundle came from *someone in the
        // fleet*; the Ed25519 signature proves it came from *the signer*, which
        // no host — however compromised — can impersonate without the private
        // key. On a non-tls build the field is ignored (see with_ed25519_pubkey).
        #[cfg(feature = "tls")]
        if let Some(pubkey) = &self.ed25519_pubkey {
            let msg = signing_input(
                bundle.revision,
                &bundle.source,
                bundle.canary_percent,
                bundle.canary_seconds,
            );
            if bundle.sig_ed25519.is_empty() || !verify_ed25519(pubkey, &msg, &bundle.sig_ed25519) {
                return Err(BundleError::NotAuthentic);
            }
        }
        if bundle.revision <= installed && installed != 0 {
            return Err(BundleError::Stale {
                offered: bundle.revision,
                installed,
            });
        }
        Ok(())
    }
}

/// Verify a detached Ed25519 signature over `msg` with a raw 32-byte public key.
#[cfg(feature = "tls")]
pub fn verify_ed25519(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey);
    pk.verify(msg, sig).is_ok()
}

/// Sign a bundle with an Ed25519 private key (PKCS#8), filling in `sig_ed25519`.
/// For a fleet signing tool — the daemon only ever verifies — so it lives behind
/// the same `tls` flag and is not part of the default trusted computing base.
#[cfg(feature = "tls")]
pub fn sign_ed25519(pkcs8: &[u8], bundle: &mut Bundle) -> Result<(), String> {
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| "not a valid Ed25519 PKCS#8 key".to_string())?;
    let msg = signing_input(
        bundle.revision,
        &bundle.source,
        bundle.canary_percent,
        bundle.canary_seconds,
    );
    bundle.sig_ed25519 = key.sign(&msg).as_ref().to_vec();
    Ok(())
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Whether this host is in the canary group for a bundle.
///
/// Derived from `sha256(host_id ‖ revision)` rather than from a counter or a
/// random draw, which gives two properties that matter:
///
///   - **Stable within a rollout.** A host that is in the canary stays in it
///     across daemon restarts, so it does not install, revert on restart, and
///     install again.
///   - **Different between rollouts.** The same hosts are not always the ones
///     that find the breakage, which they would be if membership were derived
///     from the host id alone.
pub fn in_canary(host_id: &str, revision: u64, percent: u8) -> bool {
    if percent >= 100 {
        return true;
    }
    if percent == 0 {
        return false;
    }
    let mut input = host_id.as_bytes().to_vec();
    input.extend_from_slice(&revision.to_le_bytes());
    let digest = hash::sha256(&input);
    let bucket = u16::from_le_bytes([digest[0], digest[1]]) % 100;
    bucket < percent as u16
}

/// A fleet member's last-known state, as this control point sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetMember {
    pub host_id: String,
    /// The revision the member last reported running.
    pub revision: u64,
    /// Whether the member is a canary for the current target rollout.
    pub in_canary: bool,
    pub last_seen_us: u64,
}

/// An in-memory roster of the hosts a control point has heard from.
///
/// This is the single-process model of a fleet: a daemon acting as the
/// distribution point holds the members that have checked in, the revision each
/// reports, and whether each is a canary for the current rollout. A genuine
/// cross-host deployment adds a transport on top — but the trust decisions
/// (authenticate a bundle with [`Verifier`], place a host in a canary with
/// [`in_canary`]) are the same either way and already live in this module. The
/// registry is what makes them reachable: enumerate members, set a rollout
/// target, and report convergence.
#[derive(Debug, Clone, Default)]
pub struct FleetRegistry {
    members: BTreeMap<String, FleetMember>,
    target_revision: u64,
    target_canary_percent: u8,
}

impl FleetRegistry {
    /// Record a member's heartbeat, recomputing its canary membership against
    /// the current target.
    pub fn record(&mut self, host_id: &str, revision: u64, now_us: u64) {
        let in_canary = self.target_revision != 0
            && in_canary(host_id, self.target_revision, self.target_canary_percent);
        self.members.insert(
            host_id.to_string(),
            FleetMember {
                host_id: host_id.to_string(),
                revision,
                in_canary,
                last_seen_us: now_us,
            },
        );
    }

    /// Set the rollout the control point is currently distributing.
    pub fn set_target(&mut self, revision: u64, canary_percent: u8) {
        self.target_revision = revision;
        self.target_canary_percent = canary_percent;
    }

    pub fn target_revision(&self) -> u64 {
        self.target_revision
    }

    pub fn target_canary_percent(&self) -> u8 {
        self.target_canary_percent
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn members(&self) -> impl Iterator<Item = &FleetMember> {
        self.members.values()
    }

    /// Members reporting the target revision or newer — the rollout's progress.
    pub fn converged(&self) -> usize {
        if self.target_revision == 0 {
            return 0;
        }
        self.members
            .values()
            .filter(|m| m.revision >= self.target_revision)
            .count()
    }
}

/// What a rollback decision is made from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthWindow {
    pub denials: u64,
    pub allows: u64,
}

impl HealthWindow {
    /// Denials per thousand decisions. A rate, so a busy host and a quiet one
    /// are comparable — a count is not, and a threshold on a count is a
    /// threshold that is wrong on every host but the one it was tuned on.
    pub fn denial_rate(self) -> u64 {
        let total = self.denials + self.allows;
        if total == 0 {
            return 0;
        }
        self.denials * 1000 / total
    }
}

/// Why a rollback fired, or did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Not enough decisions since the install to judge. Rolling back on three
    /// denials would revert every policy on an idle host.
    TooEarly {
        decisions: u64,
        needed: u64,
    },
    Healthy {
        before: u64,
        after: u64,
    },
    /// The denial rate rose past the multiplier. The numbers are carried so
    /// the log line says what happened rather than that something did.
    Degraded {
        before: u64,
        after: u64,
        multiplier: u64,
    },
}

/// Watches a policy after it installs and decides whether to keep it.
#[derive(Debug, Clone)]
pub struct RolloutMonitor {
    baseline: HealthWindow,
    since_install: HealthWindow,
    installed_at: Duration,
    settle: Duration,
    min_decisions: u64,
    multiplier: u64,
    /// Revisions this host has run, newest last, so a rollback has somewhere
    /// to go. Bounded: a host that reloads every minute must not accumulate a
    /// week of policy in memory.
    history: VecDeque<u64>,
}

impl RolloutMonitor {
    /// `multiplier` is how many times the baseline denial rate counts as
    /// degraded. Four is the default: a policy that quadruples denials broke
    /// something, and normal variation does not.
    pub fn new(baseline: HealthWindow, installed_at: Duration) -> Self {
        RolloutMonitor {
            baseline,
            since_install: HealthWindow {
                denials: 0,
                allows: 0,
            },
            installed_at,
            settle: Duration::from_secs(30),
            min_decisions: 100,
            multiplier: 4,
            history: VecDeque::new(),
        }
    }

    pub fn with_thresholds(mut self, multiplier: u64, min_decisions: u64) -> Self {
        self.multiplier = multiplier.max(1);
        self.min_decisions = min_decisions;
        self
    }

    pub fn record(&mut self, decision_was_denial: bool) {
        if decision_was_denial {
            self.since_install.denials += 1;
        } else {
            self.since_install.allows += 1;
        }
    }

    pub fn remember(&mut self, revision: u64) {
        self.history.push_back(revision);
        while self.history.len() > 16 {
            self.history.pop_front();
        }
    }

    /// The revision to roll back to, if there is one.
    pub fn previous(&self) -> Option<u64> {
        if self.history.len() < 2 {
            return None;
        }
        self.history.get(self.history.len() - 2).copied()
    }

    pub fn assess(&self, now: Duration) -> Health {
        // The first seconds after a policy change are noisy by construction:
        // connections established under the old rules close and retry under
        // the new ones. Judging then would roll back correct policies.
        if now.saturating_sub(self.installed_at) < self.settle {
            return Health::TooEarly {
                decisions: self.since_install.denials + self.since_install.allows,
                needed: self.min_decisions,
            };
        }
        let decisions = self.since_install.denials + self.since_install.allows;
        if decisions < self.min_decisions {
            return Health::TooEarly {
                decisions,
                needed: self.min_decisions,
            };
        }

        let before = self.baseline.denial_rate();
        let after = self.since_install.denial_rate();

        // A host with no baseline denials has nothing to multiply. Comparing
        // against zero would make any denial at all a rollback, so the
        // comparison falls back to an absolute majority: more than half of
        // everything denied is broken by any reading.
        let threshold = if before == 0 {
            500
        } else {
            before * self.multiplier
        };
        if after > threshold {
            return Health::Degraded {
                before,
                after,
                multiplier: self.multiplier,
            };
        }
        Health::Healthy { before, after }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(revision: u64, source: &str) -> Bundle {
        Bundle {
            revision,
            source: source.to_string(),
            canary_percent: 10,
            canary_seconds: 300,
            mac: [0; 32],
            sig_ed25519: Vec::new(),
        }
    }

    #[test]
    fn a_signed_bundle_verifies_and_a_modified_one_does_not() {
        let v = Verifier::new(b"fleet-secret".to_vec());
        let mut b = bundle(2, "version: 1\nrules: []\n");
        v.sign(&mut b);
        assert_eq!(v.accept(&b, 1), Ok(()));

        // One byte of policy. The whole point of signing the source rather
        // than the connection.
        b.source.push(' ');
        assert_eq!(v.accept(&b, 1), Err(BundleError::NotAuthentic));
    }

    #[test]
    fn the_canary_fields_are_covered_by_the_signature() {
        // Otherwise a distribution point could take a bundle approved for 1%
        // of the fleet and deliver it to all of it, without touching a byte of
        // policy — which is the failure that turns an incident into an outage.
        let v = Verifier::new(b"k".to_vec());
        let mut b = bundle(2, "policy");
        v.sign(&mut b);
        b.canary_percent = 100;
        assert_eq!(v.accept(&b, 1), Err(BundleError::NotAuthentic));
    }

    #[test]
    fn a_bundle_signed_with_another_key_is_refused() {
        let mut b = bundle(2, "policy");
        Verifier::new(b"theirs".to_vec()).sign(&mut b);
        assert_eq!(
            Verifier::new(b"ours".to_vec()).accept(&b, 1),
            Err(BundleError::NotAuthentic)
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn an_ed25519_signed_bundle_verifies_and_forgery_without_the_key_fails() {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        // The fleet signer's keypair. The private key never leaves the signer;
        // the host is configured with only the public half.
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pubkey = keypair.public_key().as_ref().to_vec();

        // HMAC key is shared across the fleet; the verifier also requires the
        // public-key signature.
        let hmac = b"a-32-byte-fleet-secret-key-000000".to_vec();
        let verifier = Verifier::new(hmac.clone()).with_ed25519_pubkey(pubkey.clone());

        let mut b = bundle(2, "version: 1\nrules: []\n");
        Verifier::new(hmac.clone()).sign(&mut b); // HMAC
        sign_ed25519(pkcs8.as_ref(), &mut b).unwrap(); // Ed25519
        assert_eq!(
            verifier.accept(&b, 1),
            Ok(()),
            "a fully-signed bundle verifies"
        );

        // A host with the HMAC secret but not the private key can produce a
        // valid MAC — but cannot produce a valid signature, so the bundle is
        // rejected. This is the whole point over a shared secret.
        let mut forged = bundle(3, "version: 1\nrules: []\n  # attacker's policy");
        Verifier::new(hmac.clone()).sign(&mut forged); // valid MAC, no signature
        assert_eq!(
            verifier.accept(&forged, 1),
            Err(BundleError::NotAuthentic),
            "a bundle with a valid MAC but no signature must be refused when a key is required"
        );

        // Tampering after signing breaks the signature.
        let mut tampered = b.clone();
        tampered.source.push(' ');
        Verifier::new(hmac).sign(&mut tampered); // re-MAC the tampered bytes
        assert_eq!(
            verifier.accept(&tampered, 1),
            Err(BundleError::NotAuthentic),
            "the Ed25519 signature no longer covers the tampered source"
        );
    }

    #[test]
    fn a_replayed_older_bundle_cannot_roll_a_fixed_host_back() {
        // The attack this stops: capture the bundle from before the fix, hand
        // it back to a host that has already taken the fix. It is authentic —
        // it was signed — so only the revision check stops it.
        let v = Verifier::new(b"k".to_vec());
        let mut old = bundle(5, "the broken policy");
        v.sign(&mut old);
        assert_eq!(
            v.accept(&old, 9),
            Err(BundleError::Stale {
                offered: 5,
                installed: 9
            })
        );
    }

    #[test]
    fn the_length_prefix_stops_two_bundles_sharing_a_signature() {
        // Without it, (revision, "ab") and (revision, "a") + a shifted field
        // hash the same input. A signature that does not distinguish two
        // bundles is not distinguishing anything.
        let a = signing_input(1, "ab", 0, 0);
        let b = signing_input(1, "a", 0x62, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn canary_membership_is_stable_within_a_rollout() {
        // A host that flapped in and out would install, revert on restart, and
        // install again.
        for host in ["a", "b", "host-42", "prod-web-01"] {
            let first = in_canary(host, 7, 25);
            for _ in 0..10 {
                assert_eq!(in_canary(host, 7, 25), first);
            }
        }
    }

    #[test]
    fn canary_membership_changes_between_rollouts() {
        // Otherwise the same hosts always find the breakage, which is unfair
        // and, worse, means the rest of the fleet is never exercised early.
        let hosts: Vec<String> = (0..200).map(|i| format!("host-{i}")).collect();
        let first: Vec<bool> = hosts.iter().map(|h| in_canary(h, 1, 25)).collect();
        let second: Vec<bool> = hosts.iter().map(|h| in_canary(h, 2, 25)).collect();
        assert_ne!(first, second);
    }

    #[test]
    fn the_canary_fraction_is_roughly_what_was_asked_for() {
        let hosts: Vec<String> = (0..2000).map(|i| format!("host-{i}")).collect();
        for percent in [1u8, 10, 25, 50] {
            let n = hosts.iter().filter(|h| in_canary(h, 3, percent)).count();
            let expected = 2000 * percent as usize / 100;
            let slack = expected / 2 + 20;
            assert!(
                n.abs_diff(expected) <= slack,
                "{percent}% selected {n} of 2000, expected about {expected}"
            );
        }
    }

    #[test]
    fn a_hundred_percent_canary_includes_everyone_and_zero_nobody() {
        // A rule blocking an active intrusion should not wait for a canary,
        // and a bundle staged for later should reach nobody yet.
        assert!(in_canary("anything", 1, 100));
        assert!(!in_canary("anything", 1, 0));
    }

    #[test]
    fn rollback_does_not_fire_before_the_settling_window() {
        // The seconds after a policy change are noisy by construction.
        let baseline = HealthWindow {
            denials: 10,
            allows: 990,
        };
        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(100));
        for _ in 0..1000 {
            m.record(true);
        }
        assert!(matches!(
            m.assess(Duration::from_secs(110)),
            Health::TooEarly { .. }
        ));
    }

    #[test]
    fn rollback_does_not_fire_on_an_idle_host() {
        // Three denials on a host that made three decisions is not evidence.
        let baseline = HealthWindow {
            denials: 1,
            allows: 999,
        };
        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(0));
        for _ in 0..3 {
            m.record(true);
        }
        assert!(matches!(
            m.assess(Duration::from_secs(600)),
            Health::TooEarly { .. }
        ));
    }

    #[test]
    fn a_policy_that_quadruples_denials_is_rolled_back() {
        let baseline = HealthWindow {
            denials: 10,
            allows: 990,
        }; // 10 per mille
        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(0));
        for i in 0..1000 {
            m.record(i % 10 == 0); // 100 per mille
        }
        match m.assess(Duration::from_secs(600)) {
            Health::Degraded { before, after, .. } => {
                assert_eq!(before, 10);
                assert_eq!(after, 100);
            }
            other => panic!("expected degraded, got {other:?}"),
        }
    }

    #[test]
    fn a_busy_host_running_a_correct_policy_is_not_rolled_back() {
        // The count-based version of this check fires here, which is why it
        // is rate-based: 500 denials looks alarming and is the same rate as
        // the baseline.
        let baseline = HealthWindow {
            denials: 500,
            allows: 500,
        };
        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(0));
        for i in 0..10_000 {
            m.record(i % 2 == 0);
        }
        assert!(matches!(
            m.assess(Duration::from_secs(600)),
            Health::Healthy { .. }
        ));
    }

    #[test]
    fn a_host_with_no_baseline_denials_needs_a_majority_to_roll_back() {
        // Multiplying zero gives zero, and a threshold of zero rolls back on
        // the first denial a correct policy makes.
        let baseline = HealthWindow {
            denials: 0,
            allows: 1000,
        };
        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(0));
        for i in 0..1000 {
            m.record(i % 4 == 0); // 250 per mille, below the 500 floor
        }
        assert!(matches!(
            m.assess(Duration::from_secs(600)),
            Health::Healthy { .. }
        ));

        let mut m = RolloutMonitor::new(baseline, Duration::from_secs(0));
        for _ in 0..1000 {
            m.record(true);
        }
        assert!(matches!(
            m.assess(Duration::from_secs(600)),
            Health::Degraded { .. }
        ));
    }

    #[test]
    fn rollback_has_somewhere_to_go_or_reports_that_it_does_not() {
        let mut m = RolloutMonitor::new(
            HealthWindow {
                denials: 0,
                allows: 0,
            },
            Duration::ZERO,
        );
        assert_eq!(m.previous(), None, "the first policy has no predecessor");
        m.remember(1);
        assert_eq!(m.previous(), None);
        m.remember(2);
        assert_eq!(m.previous(), Some(1));
        m.remember(3);
        assert_eq!(m.previous(), Some(2));
    }

    #[test]
    fn the_revision_history_is_bounded() {
        // A host reloading every minute must not accumulate a week of policy.
        let mut m = RolloutMonitor::new(
            HealthWindow {
                denials: 0,
                allows: 0,
            },
            Duration::ZERO,
        );
        for r in 0..1000 {
            m.remember(r);
        }
        assert_eq!(m.previous(), Some(998));
        assert!(m.history.len() <= 16);
    }

    #[test]
    fn the_registry_records_members_and_reports_convergence() {
        let mut reg = FleetRegistry::default();
        reg.set_target(7, 100);
        reg.record("host-a", 7, 1000);
        reg.record("host-b", 6, 1001); // still on the old revision
        reg.record("host-a", 7, 2000); // a second heartbeat updates, not dupes

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.converged(), 1, "only host-a reports the target");
        let a = reg.members().find(|m| m.host_id == "host-a").unwrap();
        assert_eq!(a.last_seen_us, 2000);
        assert!(a.in_canary, "a 100% canary includes everyone");
    }

    #[test]
    fn canary_membership_is_recomputed_against_the_target() {
        let mut reg = FleetRegistry::default();
        // No target set yet: nobody is a canary.
        reg.record("host-a", 1, 10);
        assert!(!reg.members().next().unwrap().in_canary);

        // A 0% canary excludes everyone; a member re-recorded reflects it.
        reg.set_target(3, 0);
        reg.record("host-a", 1, 20);
        assert!(!reg.members().next().unwrap().in_canary);
        assert_eq!(reg.converged(), 0);
    }
}
