//! `ufw-nft` end to end, for the parts that need neither root nor nftables.
//!
//! `apply`, `trial`, `status` and `revert` all touch the live kernel and are
//! covered by unit tests plus manual use. `render`, `check` and the
//! policy-name resolution are pure compile-and-print paths, so they can be
//! exercised against the real binary here — which is exactly where the
//! IPv4/IPv6 regression that motivated this work would resurface.

use std::path::PathBuf;
use std::process::{Command, Output};

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test executable path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(if cfg!(windows) {
        "ufw-nft.exe"
    } else {
        "ufw-nft"
    })
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", binary().display()))
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}
fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The repo's own policies, found relative to this crate.
fn policy(rel: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    root.join(rel).to_string_lossy().into_owned()
}

#[test]
fn help_and_version_need_no_privileges() {
    let help = run(&["--help"]);
    assert_eq!(code(&help), 0);
    assert!(stdout(&help).contains("dashboard"));
    assert!(stdout(&help).contains("apply"));

    let v = run(&["--version"]);
    assert_eq!(code(&v), 0);
    assert!(stdout(&v).contains("ufw-nft"));
}

#[test]
fn render_emits_a_family_split_ruleset_for_default_deny() {
    let out = run(&["render", &policy("policies/base/default_deny.yaml")]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let nft = stdout(&out);

    // The bug this whole change fixes: loopback's mixed-family group must
    // become one `ip` rule and one `ip6` rule, never a set with `::1` in an
    // `ip` match.
    assert!(nft.contains("ip daddr { 127.0.0.0/8 }"));
    assert!(nft.contains("ip6 daddr { ::1/128 }"));
    for line in nft.lines() {
        let t = line.trim_start();
        if t.starts_with("ip daddr") {
            assert!(!line.contains("::"), "IPv6 literal in an ip match: {line}");
        }
        if t.starts_with("ip6 daddr") {
            assert!(
                !line.contains("127.0"),
                "IPv4 literal in an ip6 match: {line}"
            );
        }
    }

    // Logged denies carry the structured attribution prefix.
    assert!(nft.contains("log prefix \"ufw#deny#deny-all \""));
    // The render is instrumented for counters, like apply.
    assert!(nft.contains("counter drop"));
}

#[test]
fn every_shipped_policy_renders_and_stays_family_pure() {
    for rel in [
        "policies/base/default_deny.yaml",
        "policies/base/default_allow.yaml",
        "policies/hardening/zero_trust.yaml",
        "policies/hardening/airgapped.yaml",
        "policies/applications/browser_rules.yaml",
    ] {
        let out = run(&["render", &policy(rel)]);
        assert_eq!(code(&out), 0, "{rel}: {}", stderr(&out));
        let nft = stdout(&out);
        assert!(nft.contains("table inet ufw"), "{rel} produced no table");
        for line in nft.lines() {
            let t = line.trim_start();
            // No set may ever mix families — that is precisely what nft
            // rejects with "Address family for hostname not supported".
            if t.starts_with("ip daddr") || t.starts_with("ip saddr") {
                assert!(!line.contains("::"), "{rel}: v6 in v4 match: {line}");
            }
        }
    }
}

#[test]
fn check_validates_structure_without_nft_when_nft_is_absent() {
    // `check` runs `nft -c`; on a host without nft it should fail with a
    // clear message, not a panic. Where nft *is* present it should pass on a
    // shipped policy. Either way the exit is clean (0 or 1), never a crash.
    let out = run(&["check", &policy("policies/base/default_allow.yaml")]);
    let c = code(&out);
    assert!(c == 0 || c == 1, "unexpected exit {c}: {}", stderr(&out));
    if c == 0 {
        assert!(stdout(&out).contains("nft accepts"));
    } else {
        assert!(
            stderr(&out).contains("nft"),
            "a check failure should mention nft: {}",
            stderr(&out)
        );
    }
}

#[test]
fn a_missing_policy_name_is_a_clear_error_not_a_panic() {
    let out = run(&["render", "this-policy-does-not-exist"]);
    assert_eq!(code(&out), 1);
    let err = stderr(&out);
    assert!(
        err.contains("not a file") || err.contains("does not exist"),
        "{err}"
    );
}

#[test]
fn an_explicit_missing_path_says_so() {
    let out = run(&["render", "./nope/missing.yaml"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("does not exist"));
}

#[test]
fn an_unknown_subcommand_exits_nonzero() {
    let out = run(&["frobnicate"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("unknown command"));
}
