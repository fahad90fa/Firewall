//! In-memory policy database, revision tracking, and incremental diffs.
//!
//! The store owns the one authoritative answer to "what is installed right
//! now?" and computes the minimal change needed to get from there to a newly
//! compiled policy.
//!
//! # Why the diff matters
//!
//! Reinstalling a whole rule set on every edit means tearing filters down and
//! putting them back. Between those two operations there is a window with a
//! partial rule set installed — a gap in a firewall, opened by an
//! administrator fixing a typo. Sending only the difference means the kernel
//! module can apply it under one lock with no such window.
//!
//! The diff is only meaningful because rule ids are derived from rule *names*
//! rather than positions (see `ufw_shared::hash::derive_rule_id`). Inserting a
//! rule at the top of a policy therefore produces a one-rule delta, not a
//! whole-file rewrite.

use std::collections::{BTreeMap, VecDeque};

use ufw_shared::constants;
use ufw_shared::policy_types::{CompiledPolicy, CompiledRule};
use ufw_shared::protocol::PolicyDelta;

/// A policy that was active at some point, kept for rollback and audit.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRevision {
    pub policy: CompiledPolicy,
    /// When this revision became active (microseconds since epoch).
    pub activated_at_us: u64,
    /// Where it came from: a file path, `"api"`, or `"rollback"`.
    pub origin: String,
}

impl PolicyRevision {
    pub fn revision(&self) -> u64 {
        self.policy.revision
    }
}

/// The daemon's policy database.
#[derive(Debug)]
pub struct PolicyStore {
    active: Option<PolicyRevision>,
    /// Most recent first, bounded by [`constants::POLICY_HISTORY_DEPTH`].
    history: VecDeque<PolicyRevision>,
    next_revision: u64,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStore {
    pub fn new() -> Self {
        PolicyStore {
            active: None,
            history: VecDeque::new(),
            // Revisions start at 1 so that 0 unambiguously means "no policy
            // installed" in a `HelloAck`.
            next_revision: 1,
        }
    }

    pub fn active(&self) -> Option<&PolicyRevision> {
        self.active.as_ref()
    }

    pub fn active_policy(&self) -> Option<&CompiledPolicy> {
        self.active.as_ref().map(|r| &r.policy)
    }

    pub fn active_revision(&self) -> u64 {
        self.active.as_ref().map(|r| r.revision()).unwrap_or(0)
    }

    pub fn history(&self) -> impl Iterator<Item = &PolicyRevision> {
        self.history.iter()
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Find a stored revision by number, including the active one.
    pub fn revision(&self, revision: u64) -> Option<&PolicyRevision> {
        if let Some(a) = &self.active {
            if a.revision() == revision {
                return Some(a);
            }
        }
        self.history.iter().find(|r| r.revision() == revision)
    }

    /// Stage a newly compiled policy, assigning it the next revision number.
    ///
    /// Returns the delta to send to the kernel module, or `None` when the new
    /// policy is byte-identical to the active one — recompiling an unchanged
    /// file is the common case for a file watcher and must not churn the
    /// kernel.
    pub fn stage(
        &mut self,
        mut policy: CompiledPolicy,
        origin: impl Into<String>,
        now_us: u64,
    ) -> Option<StagedChange> {
        // Compare content rather than `ruleset_hash`: the latter covers the
        // revision number, so an unchanged file recompiled a second time would
        // look different and churn the kernel for nothing.
        if let Some(active) = &self.active {
            if active.policy.content_hash() == policy.content_hash() {
                return None;
            }
        }

        policy.revision = self.next_revision;
        self.next_revision += 1;
        // The revision is part of the encoded form, so the hash has to be
        // recomputed after assigning it.
        policy.finalize();

        let delta = match &self.active {
            Some(active) => diff(&active.policy, &policy),
            None => full_delta(&policy),
        };

        Some(StagedChange {
            revision: PolicyRevision {
                policy,
                activated_at_us: now_us,
                origin: origin.into(),
            },
            delta,
        })
    }

    /// Promote a staged change to active, retiring the previous policy into
    /// history. Called only after the kernel module acknowledged it.
    pub fn commit(&mut self, staged: StagedChange) {
        if let Some(previous) = self.active.take() {
            self.history.push_front(previous);
            while self.history.len() > constants::POLICY_HISTORY_DEPTH {
                self.history.pop_back();
            }
        }
        self.active = Some(staged.revision);
    }

    /// Build the change needed to return to an earlier revision.
    ///
    /// Rollback is a forward operation: it produces a *new* revision whose
    /// content matches the old one. Reusing the old revision number would make
    /// the kernel module's `base_revision` check meaningless and would leave
    /// two different moments in history sharing an identifier.
    pub fn prepare_rollback(&mut self, to: u64, now_us: u64) -> Result<StagedChange, RollbackError> {
        if self.active_revision() == to {
            return Err(RollbackError::AlreadyActive(to));
        }
        let target = self
            .revision(to)
            .ok_or(RollbackError::UnknownRevision(to))?
            .policy
            .clone();

        let mut restored = target;
        restored.revision = self.next_revision;
        self.next_revision += 1;
        restored.finalize();

        let delta = match &self.active {
            Some(active) => diff(&active.policy, &restored),
            None => full_delta(&restored),
        };

        Ok(StagedChange {
            revision: PolicyRevision {
                policy: restored,
                activated_at_us: now_us,
                origin: format!("rollback to revision {to}"),
            },
            delta,
        })
    }

    /// Drop every rule, leaving the module with only its default action.
    pub fn prepare_flush(&mut self, now_us: u64) -> Option<StagedChange> {
        let active = self.active.as_ref()?;
        let mut empty = CompiledPolicy::new(active.policy.name.clone(), active.policy.default_action);
        empty.network_profile = active.policy.network_profile.clone();
        empty.revision = self.next_revision;
        self.next_revision += 1;
        empty.finalize();

        let delta = diff(&active.policy, &empty);
        Some(StagedChange {
            revision: PolicyRevision {
                policy: empty,
                activated_at_us: now_us,
                origin: "flush".into(),
            },
            delta,
        })
    }
}

/// A policy change that has been computed but not yet acknowledged.
#[derive(Debug, Clone, PartialEq)]
pub struct StagedChange {
    pub revision: PolicyRevision,
    pub delta: PolicyDelta,
}

impl StagedChange {
    /// Whether the change is large enough that a full install is cheaper than
    /// a delta.
    ///
    /// The threshold is a fraction of the rule count rather than an absolute:
    /// on a 20-rule policy, replacing 15 rules is a rewrite; on a 20 000-rule
    /// policy, 15 changes is a rounding error.
    pub fn prefers_full_install(&self) -> bool {
        let total = self.revision.policy.rules.len().max(1);
        self.delta.change_count() * 2 >= total
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    UnknownRevision(u64),
    AlreadyActive(u64),
}

impl std::fmt::Display for RollbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollbackError::UnknownRevision(r) => {
                write!(f, "revision {r} is not in the retained history")
            }
            RollbackError::AlreadyActive(r) => write!(f, "revision {r} is already active"),
        }
    }
}

impl std::error::Error for RollbackError {}

/// Compute the minimal change from `old` to `new`.
pub fn diff(old: &CompiledPolicy, new: &CompiledPolicy) -> PolicyDelta {
    let old_by_id: BTreeMap<u32, &CompiledRule> = old.rules.iter().map(|r| (r.id, r)).collect();
    let new_by_id: BTreeMap<u32, &CompiledRule> = new.rules.iter().map(|r| (r.id, r)).collect();

    let mut added = Vec::new();
    let mut modified = Vec::new();
    for (id, rule) in &new_by_id {
        match old_by_id.get(id) {
            None => added.push((*rule).clone()),
            Some(previous) if previous != rule => modified.push((*rule).clone()),
            Some(_) => {}
        }
    }
    let removed: Vec<u32> = old_by_id
        .keys()
        .filter(|id| !new_by_id.contains_key(id))
        .copied()
        .collect();

    PolicyDelta {
        base_revision: old.revision,
        new_revision: new.revision,
        added,
        modified,
        removed,
        default_action: (old.default_action != new.default_action).then_some(new.default_action),
        result_hash: new.ruleset_hash,
    }
}

/// The delta that installs `policy` from nothing.
pub fn full_delta(policy: &CompiledPolicy) -> PolicyDelta {
    PolicyDelta {
        base_revision: 0,
        new_revision: policy.revision,
        added: policy.rules.clone(),
        modified: Vec::new(),
        removed: Vec::new(),
        default_action: Some(policy.default_action),
        result_hash: policy.ruleset_hash,
    }
}

/// Apply a delta to a policy, producing what the kernel module should now
/// hold.
///
/// The daemon uses this to check its own arithmetic: after applying its delta
/// to the old policy, the result must hash to the same value as the policy it
/// compiled. If it does not, the delta is wrong and the daemon sends a full
/// install rather than leaving the two sides disagreeing.
pub fn apply(base: &CompiledPolicy, delta: &PolicyDelta) -> CompiledPolicy {
    let mut out = base.clone();
    out.revision = delta.new_revision;
    if let Some(action) = delta.default_action {
        out.default_action = action;
    }
    out.rules.retain(|r| !delta.removed.contains(&r.id));
    for m in &delta.modified {
        if let Some(existing) = out.rules.iter_mut().find(|r| r.id == m.id) {
            *existing = m.clone();
        } else {
            out.rules.push(m.clone());
        }
    }
    for a in &delta.added {
        if !out.rules.iter().any(|r| r.id == a.id) {
            out.rules.push(a.clone());
        }
    }
    out.finalize();
    out
}

/// Human-readable summary of a delta, for the CLI and for the audit log.
pub fn describe(delta: &PolicyDelta, old: &CompiledPolicy) -> String {
    if delta.is_empty() {
        return "no changes".into();
    }
    let mut lines = Vec::new();
    if let Some(action) = delta.default_action {
        lines.push(format!(
            "  default action {} -> {}",
            old.default_action.as_str(),
            action.as_str()
        ));
    }
    for r in &delta.added {
        lines.push(format!("  + {} (priority {}, {})", r.name, r.priority, r.effective_action()));
    }
    for r in &delta.modified {
        let before = old.find(r.id);
        match before {
            Some(b) => lines.push(format!(
                "  ~ {} ({} -> {})",
                r.name,
                b.effective_action(),
                r.effective_action()
            )),
            None => lines.push(format!("  ~ {}", r.name)),
        }
    }
    for id in &delta.removed {
        let name = old.find(*id).map(|r| r.name.as_str()).unwrap_or("<unknown>");
        lines.push(format!("  - {name}"));
    }
    format!(
        "revision {} -> {} ({} change(s))\n{}",
        delta.base_revision,
        delta.new_revision,
        delta.change_count(),
        lines.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::policy_types::{
        Action, Decision, Layer, PortMatch, PortRange, Protocol,
    };

    fn rule(name: &str, priority: u16, action: Action) -> CompiledRule {
        let id = ufw_shared::hash::derive_rule_id("test", name);
        let mut r = CompiledRule::new(id, name, Layer::Packet, action);
        r.priority = priority;
        r.protocol = Protocol::Tcp;
        r
    }

    fn policy(rules: Vec<CompiledRule>, default_action: Decision) -> CompiledPolicy {
        let mut p = CompiledPolicy::new("test", default_action);
        p.rules = rules;
        p.finalize();
        p
    }

    #[test]
    fn first_install_is_a_full_delta() {
        let mut store = PolicyStore::new();
        let staged = store
            .stage(policy(vec![rule("a", 10, Action::Allow)], Decision::Deny), "file", 1)
            .expect("staged");
        assert_eq!(staged.revision.revision(), 1);
        assert_eq!(staged.delta.base_revision, 0);
        assert_eq!(staged.delta.added.len(), 1);
        assert_eq!(staged.delta.default_action, Some(Decision::Deny));
    }

    #[test]
    fn recompiling_an_unchanged_policy_stages_nothing() {
        let mut store = PolicyStore::new();
        let p = policy(vec![rule("a", 10, Action::Allow)], Decision::Deny);
        let staged = store.stage(p.clone(), "file", 1).unwrap();
        store.commit(staged);
        assert!(
            store.stage(p, "file", 2).is_none(),
            "an identical policy must not churn the kernel"
        );
    }

    #[test]
    fn inserting_a_rule_produces_a_one_rule_delta() {
        let mut store = PolicyStore::new();
        let first = store
            .stage(policy(vec![rule("b", 20, Action::Allow)], Decision::Deny), "file", 1)
            .unwrap();
        store.commit(first);

        let second = store
            .stage(
                policy(
                    vec![rule("a", 10, Action::Deny), rule("b", 20, Action::Allow)],
                    Decision::Deny,
                ),
                "file",
                2,
            )
            .unwrap();

        // Only the new rule moves, because ids come from names not positions.
        assert_eq!(second.delta.added.len(), 1);
        assert_eq!(second.delta.added[0].name, "a");
        assert!(second.delta.modified.is_empty());
        assert!(second.delta.removed.is_empty());
    }

    #[test]
    fn editing_a_rule_shows_up_as_modified() {
        let mut store = PolicyStore::new();
        let staged = store.stage(policy(vec![rule("a", 10, Action::Allow)], Decision::Deny), "f", 1).unwrap();
        store.commit(staged);

        let mut edited = rule("a", 10, Action::Allow);
        edited.dest_ports = PortMatch { ranges: vec![PortRange::single(443)], negate: false };
        let staged = store
            .stage(policy(vec![edited], Decision::Deny), "f", 2)
            .unwrap();
        assert_eq!(staged.delta.modified.len(), 1);
        assert!(staged.delta.added.is_empty());
    }

    #[test]
    fn removing_a_rule_shows_up_as_removed() {
        let mut store = PolicyStore::new();
        let staged = store.stage(
                        policy(
                            vec![rule("a", 10, Action::Allow), rule("b", 20, Action::Deny)],
                            Decision::Deny,
                        ),
                        "f",
                        1,
                    ).unwrap();
        store.commit(staged);
        let staged = store
            .stage(policy(vec![rule("a", 10, Action::Allow)], Decision::Deny), "f", 2)
            .unwrap();
        assert_eq!(staged.delta.removed.len(), 1);
    }

    #[test]
    fn applying_a_delta_reproduces_the_new_policy_exactly() {
        // This is the invariant the daemon checks at runtime before trusting
        // its own delta.
        let old = policy(
            vec![
                rule("keep", 10, Action::Allow),
                rule("edit", 20, Action::Allow),
                rule("drop", 30, Action::Deny),
            ],
            Decision::Deny,
        );
        let mut edited = rule("edit", 20, Action::Deny);
        edited.log = false;
        let mut new = policy(
            vec![rule("keep", 10, Action::Allow), edited, rule("add", 40, Action::Allow)],
            Decision::Allow,
        );
        new.revision = old.revision + 1;
        new.finalize();

        let delta = diff(&old, &new);
        let rebuilt = apply(&old, &delta);
        assert_eq!(rebuilt.ruleset_hash, new.ruleset_hash);
        assert_eq!(rebuilt.rules, new.rules);
        assert_eq!(rebuilt.default_action, Decision::Allow);
    }

    #[test]
    fn rollback_moves_forward_to_a_new_revision() {
        let mut store = PolicyStore::new();
        let staged = store.stage(policy(vec![rule("a", 10, Action::Allow)], Decision::Deny), "f", 1).unwrap();
        store.commit(staged);
        let staged = store.stage(policy(vec![rule("b", 10, Action::Deny)], Decision::Deny), "f", 2).unwrap();
        store.commit(staged);
        assert_eq!(store.active_revision(), 2);

        let staged = store.prepare_rollback(1, 3).expect("rollback");
        // A new revision number, with the old content.
        assert_eq!(staged.revision.revision(), 3);
        assert_eq!(staged.revision.policy.rules[0].name, "a");
        assert!(staged.revision.origin.contains("rollback"));
        store.commit(staged);
        assert_eq!(store.active_revision(), 3);
        assert_eq!(store.active_policy().unwrap().rules[0].name, "a");
    }

    #[test]
    fn rollback_to_an_unknown_or_current_revision_is_refused() {
        let mut store = PolicyStore::new();
        let staged = store.stage(policy(vec![rule("a", 10, Action::Allow)], Decision::Deny), "f", 1).unwrap();
        store.commit(staged);
        assert_eq!(
            store.prepare_rollback(99, 2),
            Err(RollbackError::UnknownRevision(99))
        );
        assert_eq!(
            store.prepare_rollback(1, 2),
            Err(RollbackError::AlreadyActive(1))
        );
    }

    #[test]
    fn history_is_bounded() {
        let mut store = PolicyStore::new();
        for i in 0..(constants::POLICY_HISTORY_DEPTH + 5) {
            let staged = store
                .stage(
                    policy(vec![rule(&format!("r{i}"), 10, Action::Allow)], Decision::Deny),
                    "f",
                    i as u64,
                )
                .unwrap();
            store.commit(staged);
        }
        assert_eq!(store.history_len(), constants::POLICY_HISTORY_DEPTH);
        // The oldest revisions fell off, so rolling back to them is refused
        // rather than silently doing something else.
        assert!(store.prepare_rollback(1, 999).is_err());
    }

    #[test]
    fn flush_removes_every_rule_but_keeps_the_default() {
        let mut store = PolicyStore::new();
        let staged = store.stage(
                        policy(
                            vec![rule("a", 10, Action::Allow), rule("b", 20, Action::Deny)],
                            Decision::Deny,
                        ),
                        "f",
                        1,
                    ).unwrap();
        store.commit(staged);
        let staged = store.prepare_flush(2).unwrap();
        assert_eq!(staged.delta.removed.len(), 2);
        assert!(staged.revision.policy.rules.is_empty());
        assert_eq!(staged.revision.policy.default_action, Decision::Deny);
    }

    #[test]
    fn a_large_change_prefers_a_full_install() {
        let old = policy(
            (0..10)
                .map(|i| rule(&format!("r{i}"), 10, Action::Allow))
                .collect(),
            Decision::Deny,
        );
        let new = policy(
            (10..20)
                .map(|i| rule(&format!("r{i}"), 10, Action::Allow))
                .collect(),
            Decision::Deny,
        );
        let staged = StagedChange {
            revision: PolicyRevision {
                policy: new.clone(),
                activated_at_us: 0,
                origin: "t".into(),
            },
            delta: diff(&old, &new),
        };
        assert!(staged.prefers_full_install());

        let small = policy(
            (0..10)
                .map(|i| rule(&format!("r{i}"), if i == 0 { 11 } else { 10 }, Action::Allow))
                .collect(),
            Decision::Deny,
        );
        let staged = StagedChange {
            revision: PolicyRevision {
                policy: small.clone(),
                activated_at_us: 0,
                origin: "t".into(),
            },
            delta: diff(&old, &small),
        };
        assert!(!staged.prefers_full_install());
    }

    #[test]
    fn describe_names_what_changed() {
        let old = policy(
            vec![rule("keep", 10, Action::Allow), rule("drop", 20, Action::Deny)],
            Decision::Deny,
        );
        let new = policy(
            vec![rule("keep", 10, Action::Allow), rule("add", 30, Action::Allow)],
            Decision::Allow,
        );
        let text = describe(&diff(&old, &new), &old);
        assert!(text.contains("+ add"));
        assert!(text.contains("- drop"));
        assert!(text.contains("default action deny -> allow"));
        assert!(!text.contains("keep"));
    }
}
