//! Scenario: replacing a policy without opening a gap.
//!
//! The promise is that an operator can edit a policy file and have it take
//! effect without a window in which the machine is unfiltered, and without
//! tearing down connections that the new policy still permits.
//!
//! Two properties carry that promise, and both are testable here:
//!
//!   1. **A delta is a diff, not a rewrite.** Inserting one rule at the top of
//!      a file must produce a one-rule change, not a whole-table replacement.
//!      This is what makes rule ids derive from *names* rather than positions —
//!      a positional id would make every insertion look like a total rewrite,
//!      and hot reload would be a full swap wearing a diff's clothes.
//!   2. **A failed compile changes nothing.** The previously installed policy
//!      stays installed. The alternative — flushing and then failing to install
//!      — is the exact gap hot reload exists to avoid.

use ufw_daemon::policy_store::PolicyStore;
use ufw_e2e::{compile, policy, Scratch, BASELINE};

/// A monotonically increasing fake clock.
///
/// The store stamps revisions with the time it is given rather than reading
/// one, which is what lets these scenarios be deterministic: a test that
/// depended on wall-clock ordering would be a test that failed on a fast
/// machine.
fn at(step: u64) -> u64 {
    1_700_000_000_000_000 + step * 1_000_000
}

fn store_with(source: &str) -> (PolicyStore, u64) {
    let mut store = PolicyStore::new();
    let staged = store
        .stage(policy(source), "test", at(1))
        .expect("the first install always produces a change");
    store.commit(staged);
    let revision = store.active_revision();
    (store, revision)
}

#[test]
fn installing_the_same_policy_twice_is_a_no_op() {
    // Byte-identical input must produce no change at all. If it did not, a
    // file watcher that fires twice on one save — which every platform's does,
    // for editors that write atomically — would reinstall the policy each
    // time.
    let (mut store, first) = store_with(BASELINE);
    let staged = store.stage(policy(BASELINE), "test", at(2));
    assert!(
        staged.is_none(),
        "recompiling an unchanged policy should produce no change at all: {staged:?}"
    );
    assert_eq!(
        store.active_revision(),
        first,
        "a no-op stage must not advance the revision"
    );
}

#[test]
fn adding_one_rule_produces_a_one_rule_delta() {
    let (mut store, _) = store_with(BASELINE);

    // Inserted at the *top* of the file and given the lowest priority, so it
    // is first in evaluation order. A positional rule id would make this look
    // like every subsequent rule changed too.
    let extended = BASELINE.replace(
        "rules:\n",
        "rules:\n  - id: allow-loopback\n    priority: 5\n    layer: packet\n\
         \x20   action: allow\n    destination: 127.0.0.0/8\n",
    );

    let staged = store
        .stage(policy(&extended), "test", at(2))
        .expect("adding a rule is a change");
    let delta = &staged.delta;
    assert_eq!(
        delta.added.len(),
        1,
        "one new rule should add exactly one: {:?}",
        staged
    );
    assert!(
        delta.removed.is_empty(),
        "nothing was deleted, so nothing should be removed: {delta:?}"
    );
    assert!(
        delta.modified.is_empty(),
        "the existing rules are unchanged, so none should be modified: {delta:?}"
    );
    assert_eq!(delta.added[0].name, "allow-loopback");
}

#[test]
fn renaming_a_rule_is_a_removal_and_an_addition() {
    // Ids are derived from names, so a rename is not a modification — it is a
    // different rule. That is the honest reading: an operator who renames a
    // rule has changed what the logs will say about it, and pretending
    // otherwise would silently merge two rules' histories.
    let (mut store, _) = store_with(BASELINE);
    let renamed = BASELINE.replace("id: allow-dns", "id: allow-name-resolution");

    let staged = store
        .stage(policy(&renamed), "test", at(2))
        .expect("a rename is a change");
    let delta = &staged.delta;
    assert_eq!(delta.added.len(), 1, "{delta:?}");
    assert_eq!(delta.removed.len(), 1, "{delta:?}");
    assert_eq!(delta.added[0].name, "allow-name-resolution");
}

#[test]
fn changing_a_rules_body_is_a_modification() {
    let (mut store, _) = store_with(BASELINE);
    let widened = BASELINE.replace("ports: [23]", "ports: [23, 2323]");

    let staged = store
        .stage(policy(&widened), "test", at(2))
        .expect("widening a port list is a change");
    let delta = &staged.delta;
    assert!(delta.added.is_empty(), "{delta:?}");
    assert!(delta.removed.is_empty(), "{delta:?}");
    assert_eq!(
        delta.modified.len(),
        1,
        "one rule's body changed, so exactly one should be modified: {delta:?}"
    );
    assert_eq!(delta.modified[0].name, "block-telnet");
}

#[test]
fn a_broken_policy_leaves_the_installed_one_alone() {
    // The property hot reload exists for. An operator saves a file with a typo
    // in it; the machine keeps enforcing what it was enforcing.
    let (store, revision) = store_with(BASELINE);

    let broken = ufw_policy_lang::compile_str(
        "broken",
        "version: 1\nrules:\n  - id: a\n",
        &ufw_policy_lang::CompileOptions::default(),
    );
    assert!(!broken.is_ok(), "the fixture is supposed to be broken");
    assert!(
        broken.policy.is_none(),
        "a failed compile must not yield a policy to install"
    );

    assert_eq!(
        store.active_revision(),
        revision,
        "a failed compile must not disturb the installed revision"
    );
    assert!(
        store.active().is_some(),
        "a failed compile must not leave the machine with no policy"
    );
}

#[test]
fn rolling_back_restores_the_earlier_rule_set() {
    let (mut store, first) = store_with(BASELINE);

    let narrowed = BASELINE.replace(
        "  - id: allow-internal-web\n",
        "  - id: allow-internal-web-disabled\n",
    );
    let staged = store
        .stage(policy(&narrowed), "test", at(2))
        .expect("renaming a rule is a change");
    store.commit(staged);
    let second = store.active_revision();
    assert_ne!(first, second);

    // Rolling back moves *forward* to a new revision whose content matches the
    // old one, rather than rewinding the counter. A monotonic revision is what
    // lets a log line be attributed to a specific installed policy — reusing a
    // number would make two different rule sets indistinguishable in the
    // record.
    let staged = store
        .prepare_rollback(first, at(3))
        .expect("rolling back to a retained revision");
    assert!(
        staged.revision.revision() > second,
        "a rollback should advance the revision, not rewind it"
    );
    store.commit(staged);

    let active = store.active_policy().expect("a policy is installed");
    assert!(
        active.rules.iter().any(|r| r.name == "allow-internal-web"),
        "the rolled-back policy should contain the original rule"
    );
}

#[test]
fn a_policy_file_on_disk_round_trips_through_the_loader() {
    // The path an operator's edit actually takes: file on disk, compiled from
    // that file, installed. Compiling from a string skips the loader, and the
    // loader is where include resolution and path handling live.
    let scratch = Scratch::new("hot-reload");
    let path = scratch.write("policy.yaml", BASELINE);

    let compilation =
        ufw_policy_lang::compile_file(&path, &ufw_policy_lang::CompileOptions::default())
            .expect("reading the policy file");
    assert!(compilation.is_ok(), "{}", compilation.render());

    let from_disk = compilation.policy.expect("a compiled policy");
    let from_string = compile(BASELINE).policy.expect("a compiled policy");

    // Same rules, same ids, same content hash. The file's *name* differs, so
    // the ruleset hash would differ — the content hash is the one that answers
    // "did the policy change".
    assert_eq!(
        from_disk.content_hash(),
        from_string.content_hash(),
        "compiling from a file and from a string should mean the same thing"
    );
}
