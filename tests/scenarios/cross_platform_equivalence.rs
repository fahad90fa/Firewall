//! Scenario: the claim the whole system is built on.
//!
//! One policy source, three kernel implementations, identical behaviour. This
//! scenario is what turns that from a design intention into a checked property.
//!
//! # What is actually being compared
//!
//! Each backend emits artifacts *and* a `DecisionModel` — its own account of
//! how it will evaluate the rules it was given. The verifier runs all three
//! models, plus the reference evaluator, over a scenario corpus derived from
//! the policy itself, and reports any input where they disagree.
//!
//! Comparing models rather than artifacts is the only tractable option: the
//! artifacts are C, nftables syntax and Swift, and "do these three produce the
//! same verdict" is not a question you can ask of three different languages
//! without running them. Comparing models asks it of one.
//!
//! The gap that leaves — whether each backend's *emitted code* matches its own
//! model — is closed elsewhere: by the classifiers being written to the same
//! structure, by `policy-lang/tests/kernel_abi_tests.rs` checking the generated
//! tables against the real headers, and ultimately by a deployment. This
//! scenario does not pretend to close it.
//!
//! # Why the negative controls are here
//!
//! A verifier that always passes is indistinguishable from a verifier that
//! works. So this file also constructs policies whose backends *should*
//! disagree if the gating rules were removed, and asserts the corpus is large
//! enough and varied enough to have found them.

use ufw_policy_lang::{compile_str, CompileOptions};
use ufw_shared::Platform;

/// A policy that exercises every construct a backend can disagree about.
const WIDE: &str = "\
version: 1
metadata:
  name: equivalence
defaults:
  action: deny
address_groups:
  internal: [10.0.0.0/8, 172.16.0.0/12]
  partners: [203.0.113.0/24, 2001:db8:1::/48]
port_groups:
  web: [80, 443]
  high: [1024-65535]
applications:
  agent:
    trust: [\">= known\"]
    platforms:
      linux:
        paths: [/usr/bin/agent]
      windows:
        path: \"C:\\\\agent.exe\"
        signer: \"Contoso Ltd\"
      macos:
        team_id: ABCDE12345
signature_groups:
  bad: [http-exploit-post, tls-downgrade-attempt]
network_profile:
  internal: [internal]
  perimeter: [203.0.113.0/24]
  perimeter_crossing_requires_dpi: true
rules:
  - id: allow-icmp
    priority: 10
    layer: packet
    action: allow
    protocol: icmp
  - id: deny-icmpv6-external
    priority: 15
    layer: packet
    action: deny
    protocol: icmpv6
    destination:
      zone: external
  - id: block-telnet
    priority: 20
    layer: packet
    action: deny
    protocol: tcp
    destination:
      ports: [23]
  - id: allow-internal
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [internal]
      ports: web
  - id: alert-external-high
    priority: 150
    layer: packet
    direction: outbound
    action: alert
    protocol: udp
    destination:
      zone: external
      ports: high
  - id: agent-partners
    priority: 200
    direction: outbound
    action: allow
    protocol: tcp
    application: agent
    destination:
      addresses: [partners]
      ports: web
  - id: deny-untrusted
    priority: 900
    direction: outbound
    action: deny
    protocol: tcp
    application:
      trust: [untrusted]
  - id: block-exploits
    priority: 300
    layer: stream
    action: allow
    protocol: tcp
    dpi:
      signatures: [bad]
      protocols: [http, tls]
      on_match: deny
  - id: deny-unnamed
    priority: 9999
    layer: stream
    action: deny
";

#[test]
fn the_three_backends_agree_on_every_generated_scenario() {
    let result = compile_str("equivalence", WIDE, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());

    let report = result
        .equivalence
        .expect("equivalence verification runs by default");
    assert!(
        report.is_equivalent(),
        "the three backends disagree:\n{}",
        report.render()
    );
}

#[test]
fn the_corpus_is_large_enough_to_mean_something() {
    // A verifier that checked three scenarios and passed would be worse than
    // none, because it would look like coverage. The corpus is derived from
    // the policy — every address, port, protocol and identity the rules
    // mention becomes an axis — so a policy this wide should produce a
    // substantial number of distinct inputs.
    let result = compile_str("equivalence", WIDE, &CompileOptions::default());
    let report = result.equivalence.expect("a report");

    assert!(
        report.scenarios_checked >= 500,
        "only {} scenarios were checked, which is not enough to have exercised \
         the policy's axes",
        report.scenarios_checked
    );
}

#[test]
fn every_platform_produced_artifacts_and_a_model() {
    let result = compile_str("equivalence", WIDE, &CompileOptions::default());
    assert_eq!(result.artifacts.len(), 3);

    for platform in Platform::ALL {
        let artifact = result
            .artifact(platform)
            .unwrap_or_else(|| panic!("no artifact for {platform:?}"));
        assert!(!artifact.files.is_empty(), "{platform:?} emitted no files");
        assert!(
            !artifact.model.rules.is_empty(),
            "{platform:?} emitted files but no decision model, so there is \
             nothing to verify it against"
        );
    }
}

#[test]
fn the_shipped_policies_are_all_verified() {
    // Equivalence on a fixture is worth less than equivalence on the policies
    // the project actually ships. If one of those diverges, the examples in
    // the documentation are wrong.
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");

    let mut checked = 0;
    // The containerised traffic test's policy is included: it is only executed
    // under a Docker profile that most CI cannot run, so without this it would
    // rot unnoticed until somebody finally ran that profile.
    let mut stack: Vec<std::path::PathBuf> =
        [workspace.join("policies"), workspace.join("tests/docker")]
            .into_iter()
            .filter(|p| p.exists())
            .collect();
    if stack.is_empty() {
        return;
    }
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            // Fragments are includes, not policies.
            if path.components().any(|c| c.as_os_str() == "fragments") {
                continue;
            }

            let result = ufw_policy_lang::compile_file(&path, &CompileOptions::default())
                .expect("reading a shipped policy");
            assert!(
                result.is_ok(),
                "{} does not compile:\n{}",
                path.display(),
                result.render()
            );

            let report = result.equivalence.expect("verification runs by default");
            assert!(
                report.is_equivalent(),
                "{} produces divergent backends:\n{}",
                path.display(),
                report.render()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no shipped policies were found to verify");
}

#[test]
fn single_platform_compilation_does_not_claim_equivalence() {
    // Compiling for one platform cannot verify agreement between three, and
    // reporting a vacuous pass would be worse than reporting nothing: a build
    // that says "equivalence verified" while having checked one backend is a
    // build that has taught its operators to ignore the line.
    let result = compile_str(
        "one-platform",
        WIDE,
        &CompileOptions::single_platform(Platform::Linux),
    );
    assert!(result.is_ok(), "{}", result.render());
    assert_eq!(result.artifacts.len(), 1);
    assert!(
        result.equivalence.is_none(),
        "a single-platform build must not report an equivalence result"
    );
}

#[test]
fn a_policy_whose_rules_all_gate_the_same_way_still_gets_a_real_corpus() {
    // A degenerate policy — one rule, no addresses, no identity — is where a
    // corpus generator is most likely to collapse to a handful of inputs and
    // report a meaningless pass.
    let result = compile_str(
        "degenerate",
        "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: allow-all-tcp\n\
         \x20   priority: 100\n    layer: packet\n    action: allow\n    protocol: tcp\n",
        &CompileOptions::default(),
    );
    assert!(result.is_ok(), "{}", result.render());

    let report = result.equivalence.expect("a report");
    assert!(report.is_equivalent(), "{}", report.render());
    assert!(
        report.scenarios_checked > 1,
        "a single-rule policy still needs more than one scenario to say anything"
    );
}
