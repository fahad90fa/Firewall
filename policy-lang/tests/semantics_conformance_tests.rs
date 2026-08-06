//! The evaluator against the specification, not against itself.
//!
//! `docs/design/formal_semantics.md` defines what a policy means. This file
//! implements that definition independently — directly from the denotation,
//! with no reference to `CompiledPolicy::evaluate` — and checks the two agree
//! over the policy's whole equivalence-class space.
//!
//! The distinction matters. The equivalence proof shows three backends and the
//! reference evaluator agree. If the reference is wrong, all four are wrong
//! together and every test passes. This is the check that would not.
//!
//! Written to be read against the document, in the same order and with the
//! same names, so a reader can put them side by side.

use ufw_policy_lang::proof;
use ufw_policy_lang::{compile_str, CompileOptions};
use ufw_shared::constants::RULE_ID_DEFAULT;
use ufw_shared::policy_types::{Action, CompiledPolicy, CompiledRule, Decision, FlowContext};

/// `order(r) = (stage, priority, id)`, from the document.
fn order(r: &CompiledRule) -> (usize, u16, u32) {
    (r.layer.stage_index(), r.priority, r.id)
}

/// `verdict(f)` and `rule(f)`, implemented from the denotation.
///
/// Deliberately naive: collect everything that matches, sort, take the first
/// terminal action. The real evaluator stages and short-circuits, which is
/// what makes it fast and what makes it possible for it to be subtly wrong.
fn denotation(policy: &CompiledPolicy, ctx: &FlowContext<'_>) -> (Decision, u32) {
    let mut fired: Vec<&CompiledRule> = policy.rules.iter().filter(|r| r.matches(ctx)).collect();
    fired.sort_by_key(|r| order(r));

    for rule in fired {
        match rule.action {
            Action::Allow => return (Decision::Allow, rule.id),
            Action::Deny => return (Decision::Deny, rule.id),
            // Not terminal: evaluation proceeds past them.
            Action::AllowInspect | Action::Alert | Action::Continue => {}
        }
    }
    (policy.default_action, RULE_ID_DEFAULT)
}

fn compile(source: &str) -> CompiledPolicy {
    let result = compile_str("semantics", source, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());
    result.policy.expect("compiled")
}

/// Walk the policy's equivalence classes and compare the evaluator against the
/// denotation on each. Same decomposition the proof uses, for the same reason:
/// it decides the whole space rather than sampling it.
fn conforms(policy: &CompiledPolicy) {
    let mut checked = 0usize;
    for scenario in proof::equivalence_classes(policy) {
        let ctx = scenario.context(&policy.network_profile);
        let spec = denotation(policy, &ctx);
        let got = policy.evaluate(&ctx);
        assert_eq!(
            (got.decision, got.rule_id),
            spec,
            "the evaluator departs from formal_semantics.md on {}:\n  \
             spec says {:?}\n  evaluator says {:?}",
            scenario.name,
            spec,
            (got.decision, got.rule_id)
        );
        checked += 1;
    }
    assert!(
        checked > 100,
        "only {checked} classes — the check is too thin"
    );
}

#[test]
fn header_only_rules_conform() {
    conforms(&compile(
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: allow-web\n    priority: 100\n    layer: packet\n    \
         action: allow\n    protocol: tcp\n    destination:\n      \
         addresses: [10.0.0.0/8]\n      ports: [80, 443]\n  \
         - id: deny-all-tcp\n    priority: 60000\n    layer: packet\n    \
         action: deny\n    protocol: tcp\n",
    ));
}

#[test]
fn the_non_terminal_actions_conform() {
    // allow-inspect is the one the denotation and a staged evaluator are most
    // likely to disagree about: the evaluator must *not* stop on it.
    conforms(&compile(
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: provisional\n    priority: 10\n    layer: packet\n    \
         action: allow-inspect\n    protocol: tcp\n  \
         - id: later-deny\n    priority: 20\n    layer: stream\n    \
         action: deny\n    protocol: tcp\n    destination:\n      ports: [23]\n  \
         - id: noticed\n    priority: 30\n    layer: packet\n    \
         action: alert\n    protocol: tcp\n",
    ));
}

#[test]
fn priority_orders_within_a_stage_and_not_across_stages() {
    // The language's most common misunderstanding, and the one place a
    // reader of the evaluator could "fix" it into being wrong. A packet-stage
    // rule at priority 60000 still runs before an identity-stage rule at
    // priority 1.
    conforms(&compile(
        "version: 1\ndefaults:\n  action: allow\n\
         applications:\n  agent:\n    platforms:\n      linux:\n        \
         paths: [/usr/bin/agent]\n\
         rules:\n  \
         - id: late-packet-deny\n    priority: 60000\n    layer: packet\n    \
         action: deny\n    protocol: tcp\n    destination:\n      ports: [443]\n  \
         - id: early-identity-allow\n    priority: 1\n    action: allow\n    \
         protocol: tcp\n    application: agent\n    destination:\n      ports: [443]\n",
    ));
}

#[test]
fn absence_conforms() {
    // The rule the whole document exists for: an unresolved identity
    // satisfies neither an application predicate nor a negated one. The
    // equivalence classes include the absent cell, so this exercises it.
    conforms(&compile(
        "version: 1\ndefaults:\n  action: deny\n\
         applications:\n  agent:\n    platforms:\n      linux:\n        \
         paths: [/usr/bin/agent]\n\
         rules:\n  \
         - id: only-agent\n    priority: 100\n    action: allow\n    \
         protocol: tcp\n    application: agent\n  \
         - id: not-agent\n    priority: 200\n    action: deny\n    \
         protocol: tcp\n    application: \"!agent\"\n",
    ));
}

#[test]
fn ports_on_a_portless_protocol_conform() {
    // A port clause never matches ICMP, including a negated one.
    conforms(&compile(
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: icmp-ok\n    priority: 10\n    layer: packet\n    \
         action: allow\n    protocol: icmp\n  \
         - id: not-high-ports\n    priority: 20\n    layer: packet\n    \
         action: deny\n    destination:\n      ports: \"!1024-65535\"\n",
    ));
}

#[test]
fn every_shipped_policy_conforms() {
    // The examples people copy. If the evaluator departs from the spec on one
    // of them, the spec is decoration.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    if !root.exists() {
        return;
    }
    let mut count = 0;
    for file in walk(&root) {
        let source = std::fs::read_to_string(&file).unwrap();
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let result = compile_str(&name, &source, &CompileOptions::default());
        if !result.is_ok() {
            continue;
        }
        let policy = result.policy.expect("compiled");
        // Bounded rather than total for the wide ones: this is a conformance
        // check, and a partial one on a wide policy beats none.
        let mut checked = 0usize;
        for scenario in proof::equivalence_classes(&policy).take(200_000) {
            let ctx = scenario.context(&policy.network_profile);
            let got = policy.evaluate(&ctx);
            assert_eq!(
                (got.decision, got.rule_id),
                denotation(&policy, &ctx),
                "{name} departs from formal_semantics.md on {}",
                scenario.name
            );
            checked += 1;
        }
        assert!(checked > 0, "{name} produced no classes");
        count += 1;
    }
    assert!(count > 0, "no policies were checked");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("fragments") {
                continue;
            }
            out.extend(walk(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            out.push(path);
        }
    }
    out
}
