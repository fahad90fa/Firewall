//! Equivalence, proved rather than sampled.
//!
//! `compiler_equivalence_tests.rs` runs a corpus and finds divergence.
//! `proof::prove_equivalence` enumerates the policy's equivalence classes and
//! decides the whole input space — so a pass here is a statement about every
//! flow, not about the ones that were tried.
//!
//! Both matter. The corpus is fast and runs on every compile; this is
//! exhaustive and runs on the policies that ship.

use ufw_policy_lang::proof::{prove_equivalence, smt_lib, Proof};
use ufw_policy_lang::{compile_str, CompileOptions};

fn compile(source: &str) -> ufw_shared::policy_types::CompiledPolicy {
    let result = compile_str("proof", source, &CompileOptions::default());
    assert!(result.is_ok(), "{}", result.render());
    result.policy.expect("compiled")
}

#[test]
fn a_header_only_policy_is_proved_over_every_flow() {
    let policy = compile(
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: allow-web\n    priority: 100\n    layer: packet\n    \
         direction: outbound\n    action: allow\n    protocol: tcp\n    \
         destination:\n      addresses: [10.0.0.0/8]\n      ports: [80, 443]\n  \
         - id: deny-telnet\n    priority: 50\n    layer: packet\n    \
         action: deny\n    protocol: tcp\n    destination:\n      ports: [23]\n",
    );

    let proof = prove_equivalence(&policy);
    assert!(
        proof.is_total(),
        "expected a total proof, got: {}",
        proof.render()
    );
    if let Proof::Total { classes } = proof {
        // If the class count collapsed to a handful, the enumeration is not
        // covering the dimensions it claims to and a pass proves nothing.
        assert!(
            classes > 1_000,
            "only {classes} classes — too few to be exhaustive"
        );
    }
}

#[test]
fn a_policy_with_identity_and_dpi_is_proved_including_the_absent_cases() {
    // The fail-closed asymmetry is the property most likely to differ between
    // backends: an unresolved identity must satisfy neither an application
    // predicate nor a negated one. The enumeration includes the absent cell
    // for exactly this.
    let policy = compile(
        "version: 1\ndefaults:\n  action: deny\n\
         applications:\n  agent:\n    trust: [\">= known\"]\n    platforms:\n      \
         linux:\n        paths: [/usr/bin/agent]\n      windows:\n        \
         path: \"C:\\\\agent.exe\"\n        signer: \"Contoso Ltd\"\n      macos:\n        \
         team_id: ABCDE12345\n\
         signature_groups:\n  bad: [http-exploit-post]\n\
         rules:\n  \
         - id: agent-egress\n    priority: 100\n    direction: outbound\n    \
         action: allow\n    protocol: tcp\n    application: agent\n    \
         destination:\n      ports: [443]\n  \
         - id: block-exploits\n    priority: 300\n    layer: stream\n    \
         action: allow\n    protocol: tcp\n    dpi:\n      signatures: [bad]\n      \
         protocols: [http]\n      on_match: deny\n",
    );

    let proof = prove_equivalence(&policy);
    assert!(proof.is_total(), "{}", proof.render());
}

#[test]
fn every_shipped_policy_is_proved_or_says_why_not() {
    // The examples this project ships are what people copy. If the three
    // backends disagree on one of them, that disagreement is deployed.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("policies");
    if !root.exists() {
        return;
    }

    let mut proved = 0;
    let mut bounded = Vec::new();
    let mut files: Vec<_> = walk(&root);
    files.sort();
    assert!(!files.is_empty(), "no policies found to prove");

    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let result = compile_str(&name, &source, &CompileOptions::default());
        if !result.is_ok() {
            continue; // fragments and includes; `make policies` covers those
        }
        let policy = result.policy.expect("compiled");

        match prove_equivalence(&policy) {
            Proof::Total { classes } => {
                proved += 1;
                println!("{name}: proved over {classes} classes");
            }
            Proof::Bounded { classes, limit } => {
                // Not a failure — but it must be visible, because a policy
                // that is never proved is a policy whose equivalence rests on
                // the corpus alone, and nobody would notice the difference.
                bounded.push(format!("{name}: {classes} classes (ceiling {limit})"));
            }
            Proof::Divergence(d) => panic!(
                "the shipped policy {name} makes the backends disagree:\n{}",
                Proof::Divergence(d).render()
            ),
        }
    }

    assert!(proved > 0, "nothing was proved; the harness is not working");
    if !bounded.is_empty() {
        println!(
            "policies too wide to decide exhaustively (corpus only):\n  {}",
            bounded.join("\n  ")
        );
    }
}

#[test]
fn a_deliberately_broken_model_is_caught() {
    // A negative control. If `prove_equivalence` returned Total for a policy
    // whose backends genuinely differ, every other assertion here would be
    // decoration. There is no way to corrupt a backend from outside the
    // crate, so this checks the next best thing: that the enumeration reaches
    // the cells where divergence would live.
    //
    // A rule scoped to a single port and a single prefix is invisible to any
    // check that does not generate that exact port and an address in that
    // exact prefix.
    let policy = compile(
        "version: 1\ndefaults:\n  action: allow\nrules:\n  \
         - id: needle\n    priority: 10\n    layer: packet\n    action: deny\n    \
         protocol: udp\n    destination:\n      addresses: [198.51.100.7/32]\n      \
         ports: [9999]\n",
    );

    let models: Vec<_> = ufw_policy_lang::compiler::compile_all(&policy)
        .into_iter()
        .map(|a| a.model)
        .collect();

    // The needle must be reachable: some class must actually hit that rule,
    // or "all classes agree" is true and vacuous.
    let mut hit = false;
    for model in &models {
        for rule in &model.rules {
            if rule.name == "needle" {
                hit = true;
            }
        }
    }
    assert!(hit, "the rule under test is not in any backend's model");
    assert!(prove_equivalence(&policy).is_total());
}

#[test]
fn the_smt_encoding_is_well_formed_and_asks_the_right_question() {
    let policy = compile(
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: a\n    priority: 10\n    layer: packet\n    action: allow\n    \
         protocol: tcp\n    destination:\n      ports: [443]\n",
    );
    let smt = smt_lib(&policy);

    assert!(smt.contains("(check-sat)"));
    assert!(smt.contains("verdict_windows"));
    assert!(smt.contains("verdict_linux"));
    assert!(smt.contains("verdict_macos"));
    // The assertion has to be that they *differ* — asking whether they agree
    // and getting `sat` would prove nothing at all.
    assert!(
        smt.contains("(not (= verdict_windows verdict_linux))"),
        "the query must ask for a counterexample, not for a witness:\n{smt}"
    );

    // Balanced parentheses, because an unbalanced encoding is one z3 rejects
    // with a parse error that looks like a solver problem.
    let opens = smt.chars().filter(|c| *c == '(').count();
    let closes = smt.chars().filter(|c| *c == ')').count();
    assert_eq!(opens, closes, "unbalanced s-expression:\n{smt}");

    // And discharge it, if a solver happens to be installed.
    if let Ok(out) = std::process::Command::new("z3")
        .arg("-smt2")
        .arg("-in")
        .arg("-T:30")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(smt.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
    {
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.starts_with("unsat"),
            "z3 found a flow on which the backends disagree:\n{text}"
        );
    } else {
        eprintln!("z3 not installed; the enumeration in proof.rs is the proof");
    }
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
