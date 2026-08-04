//! Scenario: the decision procedure's cost, measured against itself.
//!
//! # Why there are no absolute thresholds here
//!
//! "Under 10 microseconds per decision" is a number that passes on a developer
//! laptop and fails on a loaded CI runner, and the response is always the same:
//! raise the threshold until it stops failing. After two rounds of that the
//! test asserts nothing and everyone has learned to ignore it.
//!
//! So these assertions are about *shape* rather than magnitude:
//!
//!   - Evaluation is linear in rule count, not quadratic. A quadratic
//!     classifier is fine at 10 rules and unusable at 10,000, and the
//!     difference does not show up until someone deploys a real policy.
//!   - The stage index actually bounds the scan. A flow decided at the packet
//!     stage must not pay for the identity and stream rules below it.
//!   - The optimizer's output is not slower than its input.
//!
//! Real throughput numbers belong to `tests/docker/`, where there is a kernel
//! module and a packet generator, and to a benchmark run on known hardware.
//! This file is what CI can honestly assert.

use std::time::Instant;

use ufw_e2e::packet_generator::Flow;
use ufw_e2e::policy;
use ufw_shared::policy_types::CompiledPolicy;

/// Build a policy with `n` packet-stage rules, none of which match the probe
/// flow, followed by one that does.
fn policy_with_rules(n: usize) -> CompiledPolicy {
    let mut source = String::from("version: 1\ndefaults:\n  action: deny\nrules:\n");
    for i in 0..n {
        // Distinct destinations so the optimizer cannot collapse them, and so
        // the probe flow has to walk past all of them.
        source.push_str(&format!(
            "  - id: filler-{i}\n    priority: {}\n    layer: packet\n    \
             action: deny\n    protocol: tcp\n    destination:\n      \
             addresses: [198.51.{}.{}/32]\n      ports: [{}]\n",
            100 + i,
            (i / 250) % 250,
            i % 250,
            9000 + (i % 500),
        ));
    }
    source.push_str(
        "  - id: the-match\n    priority: 60000\n    layer: packet\n    \
         action: allow\n    protocol: tcp\n    destination:\n      ports: [443]\n",
    );
    policy(&source)
}

fn time_evaluations(policy: &CompiledPolicy, flow: &Flow, iterations: u32) -> f64 {
    let ctx = flow.context(&policy.network_profile);
    // One warm pass, so the measurement is not dominated by first-touch page
    // faults on the rule table.
    for _ in 0..64 {
        std::hint::black_box(policy.evaluate(&ctx));
    }

    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(policy.evaluate(&ctx));
    }
    start.elapsed().as_secs_f64() / f64::from(iterations)
}

#[test]
fn evaluation_cost_grows_linearly_with_rule_count() {
    let small = policy_with_rules(200);
    let large = policy_with_rules(2000);
    let flow = Flow::tcp("93.184.216.34", 443);

    let small_cost = time_evaluations(&small, &flow, 2_000);
    let large_cost = time_evaluations(&large, &flow, 400);

    // Ten times the rules should cost roughly ten times as much. The bound is
    // generous — 40x rather than 10x — because a CI runner's scheduler is
    // noisy and because this test is looking for the difference between linear
    // and quadratic, not for a regression of 20%.
    //
    // Quadratic growth would put this at 100x.
    let ratio = large_cost / small_cost.max(f64::EPSILON);
    assert!(
        ratio < 40.0,
        "evaluating 2000 rules cost {ratio:.1}x evaluating 200. Linear growth \
         would be about 10x; this looks super-linear, which means the rule scan \
         has acquired a nested loop over the table."
    );
}

#[test]
fn a_flow_decided_early_does_not_pay_for_the_stages_below_it() {
    // The stage index exists so that a packet-stage decision does not walk the
    // identity, DPI and stream rules. Without it, adding inspection rules to a
    // policy would slow down every flow those rules could never apply to.
    let mut source = String::from(
        "version: 1\ndefaults:\n  action: deny\nsignature_groups:\n  \
         bad: [http-exploit-post]\nrules:\n  - id: decided-early\n    \
         priority: 10\n    layer: packet\n    action: allow\n    protocol: tcp\n    \
         destination:\n      ports: [443]\n",
    );
    let baseline = policy(&source);

    // A pile of stream-stage rules, all after the packet-stage decision.
    for i in 0..500 {
        source.push_str(&format!(
            "  - id: inspect-{i}\n    priority: {}\n    layer: stream\n    \
             action: allow\n    protocol: tcp\n    dpi:\n      \
             signatures: [bad]\n      protocols: [http]\n      on_match: deny\n",
            1000 + i
        ));
    }
    let with_inspection = policy(&source);

    let flow = Flow::tcp("93.184.216.34", 443);
    let without = time_evaluations(&baseline, &flow, 4_000);
    let with = time_evaluations(&with_inspection, &flow, 4_000);

    // The flow is decided by `decided-early` before any stream rule is
    // considered, so 500 extra rules should cost close to nothing. 5x is a
    // deliberately loose bound on CI noise; without the stage index this would
    // be far higher, because every one of the 500 would be tested.
    let ratio = with / without.max(f64::EPSILON);
    assert!(
        ratio < 5.0,
        "adding 500 stream-stage rules made a packet-stage decision {ratio:.1}x \
         slower. It should be nearly free: the stage index is supposed to stop \
         the scan before those rules are reached."
    );
}

#[test]
fn the_optimizer_does_not_make_evaluation_slower() {
    // An optimizer that produced a larger or more expensive rule set than it
    // was given would be worse than no optimizer, and the failure would be
    // invisible — the policy still means the same thing.
    let source = {
        let mut s = String::from("version: 1\ndefaults:\n  action: deny\nrules:\n");
        for i in 0..300 {
            // Deliberately redundant: many rules covered by a broader one, which
            // is what the optimizer is meant to notice.
            s.push_str(&format!(
                "  - id: narrow-{i}\n    priority: {}\n    layer: packet\n    \
                 action: deny\n    protocol: tcp\n    destination:\n      \
                 addresses: [10.0.0.{}/32]\n      ports: [23]\n",
                500 + i,
                i % 250
            ));
        }
        s.push_str(
            "  - id: broad\n    priority: 100\n    layer: packet\n    \
             action: deny\n    protocol: tcp\n    destination:\n      ports: [23]\n",
        );
        s
    };

    let optimized = ufw_policy_lang::compile_str(
        "optimized", &source, &ufw_policy_lang::CompileOptions::default());
    assert!(optimized.is_ok(), "{}", optimized.render());

    let unoptimized = ufw_policy_lang::compile_str(
        "unoptimized",
        &source,
        &ufw_policy_lang::CompileOptions {
            optimizer: ufw_policy_lang::optimizer::OptimizerOptions {
                eliminate_unreachable: false,
                eliminate_duplicates: false,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    assert!(unoptimized.is_ok(), "{}", unoptimized.render());

    let a = optimized.policy.expect("compiled");
    let b = unoptimized.policy.expect("compiled");

    assert!(
        a.rules.len() <= b.rules.len(),
        "the optimizer produced {} rules from an input of {} — it is supposed \
         to remove rules, not add them",
        a.rules.len(),
        b.rules.len()
    );
}

#[test]
fn a_policy_at_the_documented_ceiling_still_compiles_and_evaluates() {
    // The limit is documented as 65536 rules. A policy near it should compile
    // in a reasonable time and evaluate without pathological behaviour —
    // otherwise the documented limit is a number nobody tested.
    //
    // Five thousand rather than the full ceiling: the point is to catch
    // super-linear *compile* cost, and 65536 rules of generated YAML would make
    // this test the slowest thing in CI for no additional signal.
    let start = Instant::now();
    let large = policy_with_rules(5_000);
    let compile_time = start.elapsed();

    assert_eq!(large.rules.len(), 5_001);
    assert!(
        compile_time.as_secs() < 30,
        "compiling 5000 rules took {compile_time:?}, which suggests the \
         compiler is super-linear in rule count"
    );

    let flow = Flow::tcp("93.184.216.34", 443);
    let cost = time_evaluations(&large, &flow, 200);
    assert!(
        cost < 0.01,
        "a single decision against 5000 rules took {cost:.6}s, which is far \
         beyond a linear scan of a table this size"
    );
}
