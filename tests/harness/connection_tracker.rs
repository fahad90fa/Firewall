//! Assert on decisions, and say something useful when they are wrong.
//!
//! # Why this exists rather than bare `assert_eq!`
//!
//! `assert_eq!(decision, Decision::Deny)` tells you the verdict was wrong. It
//! does not tell you which rule produced it, which is the only thing that
//! makes a policy failure diagnosable — and in a system where a rule can be
//! shadowed by an earlier *stage* regardless of its priority, "some other rule
//! matched first" is by far the most likely explanation.
//!
//! So every assertion here reports the rule that decided, and a mismatch
//! prints the flow, the expected verdict, the actual verdict and the rule
//! name. That turns a failure from "the policy is wrong somewhere" into a
//! line number in the policy.

use ufw_shared::policy_types::{CompiledPolicy, Decision, Evaluation, Layer};

use crate::packet_generator::Flow;

/// A flow, its expected verdict, and what actually happened.
pub struct Outcome {
    pub decision: Decision,
    pub rule_id: u32,
    pub rule_name: Option<String>,
    pub layer: Layer,
    pub description: String,
}

impl Outcome {
    fn render(&self) -> String {
        format!(
            "{}\n  decided {:?} by {} (id {}) at the {:?} stage",
            self.description,
            self.decision,
            self.rule_name.as_deref().unwrap_or("the policy default"),
            self.rule_id,
            self.layer
        )
    }
}

/// Evaluate a flow against a policy.
pub fn evaluate(policy: &CompiledPolicy, flow: &Flow, description: &str) -> Outcome {
    let ctx = flow.context(&policy.network_profile);
    let evaluation: Evaluation = policy.evaluate(&ctx);

    let rule_name = policy
        .rules
        .iter()
        .find(|r| r.id == evaluation.rule_id)
        .map(|r| r.name.clone());

    Outcome {
        decision: evaluation.decision,
        rule_id: evaluation.rule_id,
        rule_name,
        layer: evaluation.layer,
        description: description.to_string(),
    }
}

/// Assert a flow is permitted.
pub fn assert_allowed(policy: &CompiledPolicy, flow: &Flow, description: &str) -> Outcome {
    let outcome = evaluate(policy, flow, description);
    assert_eq!(
        outcome.decision,
        Decision::Allow,
        "expected this flow to be permitted:\n{}",
        outcome.render()
    );
    outcome
}

/// Assert a flow is denied.
pub fn assert_denied(policy: &CompiledPolicy, flow: &Flow, description: &str) -> Outcome {
    let outcome = evaluate(policy, flow, description);
    assert_eq!(
        outcome.decision,
        Decision::Deny,
        "expected this flow to be denied:\n{}",
        outcome.render()
    );
    outcome
}

/// Assert a flow is decided by a *named* rule.
///
/// Stronger than asserting the verdict, and worth using wherever a scenario
/// cares about *why*. A policy where the right verdict comes from the wrong
/// rule is a policy that will produce the wrong verdict as soon as anything
/// changes — and its logs are already misleading.
pub fn assert_decided_by(
    policy: &CompiledPolicy,
    flow: &Flow,
    rule: &str,
    description: &str,
) -> Outcome {
    let outcome = evaluate(policy, flow, description);
    assert_eq!(
        outcome.rule_name.as_deref(),
        Some(rule),
        "expected `{rule}` to decide this flow:\n{}",
        outcome.render()
    );
    outcome
}

/// Assert a flow falls through to the policy default.
pub fn assert_default(policy: &CompiledPolicy, flow: &Flow, description: &str) -> Outcome {
    let outcome = evaluate(policy, flow, description);
    assert!(
        outcome.rule_name.is_none(),
        "expected no rule to match this flow:\n{}",
        outcome.render()
    );
    outcome
}

/// Run a table of expectations, reporting every failure rather than the first.
///
/// A policy change usually breaks several expectations at once, and finding
/// out about them one test run at a time is how a five-minute fix becomes an
/// afternoon.
pub fn expect_all(policy: &CompiledPolicy, cases: Vec<(Flow, Decision, &str)>) {
    let mut failures = Vec::new();

    for (flow, expected, description) in cases {
        let outcome = evaluate(policy, &flow, description);
        if outcome.decision != expected {
            failures.push(format!(
                "  expected {:?}, got {:?} — {}",
                expected,
                outcome.decision,
                outcome.render()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the expected decisions were wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
