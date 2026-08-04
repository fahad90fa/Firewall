//! `ufwctl` end to end: the real binary, real policy files, real exit codes.
//!
//! The unit tests drive the command functions against a scripted daemon. These
//! run the compiled binary, because argument parsing, exit codes and what
//! lands on stdout versus stderr are the parts an operator and a CI pipeline
//! actually depend on, and none of them are exercised by calling a function.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const POLICY: &str = "\
version: 1
metadata:
  name: cli-test
defaults:
  action: deny
network_profile:
  internal: [10.0.0.0/8]
address_groups:
  dns: [1.1.1.1/32, 8.8.8.8/32]
rules:
  - id: allow-dns
    priority: 100
    action: allow
    protocol: udp
    destination:
      addresses: [dns]
      ports: [53]
  - id: block-telnet
    priority: 50
    action: deny
    protocol: tcp
    destination:
      ports: [23]
";

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ufwctl-e2e-{}-{}-{name}",
            std::process::id(),
            ufw_shared::now_us()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Fixture { dir }
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Locate the built binary next to the integration test executable.
fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test executable path");
    path.pop(); // the test binary's own name
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(if cfg!(windows) {
        "ufwctl.exe"
    } else {
        "ufwctl"
    })
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", binary().display()))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

#[test]
fn help_and_version_succeed_without_a_daemon() {
    let help = run(&["--help"]);
    assert_eq!(code(&help), 0);
    assert!(stdout(&help).contains("USAGE:"));
    assert!(stdout(&help).contains("EXIT CODES:"));

    // No arguments prints help rather than an error.
    let bare = run(&[]);
    assert_eq!(code(&bare), 0);
    assert!(stdout(&bare).contains("COMMANDS:"));

    let version = run(&["--version"]);
    assert_eq!(code(&version), 0);
    assert!(stdout(&version).contains(ufw_shared::constants::VERSION));
}

#[test]
fn validating_a_good_policy_exits_zero() {
    let f = Fixture::new("valid");
    let path = f.write("p.yaml", POLICY);
    let out = run(&["policy", "validate", path.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("is valid: 2 rules"), "{text}");
    assert!(text.contains("equivalence  verified"), "{text}");
}

#[test]
fn validating_a_broken_policy_exits_one_with_diagnostics_on_stderr() {
    let f = Fixture::new("broken");
    let path = f.write("p.yaml", "version: 1\nrules:\n  - id: a\n");
    let out = run(&["policy", "validate", path.to_str().unwrap()]);
    assert_eq!(code(&out), 1);
    // Diagnostics go to stderr so `ufwctl ... > artifact` does not capture
    // them into a file that is supposed to hold output.
    let err = stderr(&out);
    assert!(err.contains("E0201"), "{err}");
    assert!(err.contains("action"), "{err}");
}

#[test]
fn a_usage_error_exits_two() {
    for args in [
        vec!["teleport"],
        vec!["policy", "rollback", "soon"],
        vec!["--output", "xml", "status"],
        vec!["policy", "explain"],
    ] {
        let out = run(&args);
        assert_eq!(
            code(&out),
            2,
            "{args:?} should be a usage error: {}",
            stderr(&out)
        );
    }
}

#[test]
fn an_unreachable_daemon_exits_three_with_an_actionable_message() {
    let out = run(&["--socket", "/nonexistent/ufw.sock", "status"]);
    assert_eq!(code(&out), 3);
    let err = stderr(&out);
    assert!(err.contains("cannot reach the daemon"), "{err}");
    assert!(err.contains("ufwd is running"), "{err}");
}

#[test]
fn deny_warnings_turns_a_lint_into_a_nonzero_exit() {
    let f = Fixture::new("lint");
    let path = f.write(
        "p.yaml",
        "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n",
    );
    let p = path.to_str().unwrap();

    assert_eq!(code(&run(&["policy", "validate", p])), 0);
    let strict = run(&["policy", "validate", p, "--deny-warnings"]);
    assert_eq!(code(&strict), 1, "CI should be able to fail on warnings");
}

#[test]
fn compile_writes_artifacts_for_all_three_platforms() {
    let f = Fixture::new("compile");
    let path = f.write("p.yaml", POLICY);
    let out_dir = f.dir.join("generated");

    let out = run(&[
        "policy",
        "compile",
        path.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let expected: [&str; 9] = [
        "windows/ufw_filters.json",
        "windows/ufw_policy_generated.h",
        "windows/ufw_filters.txt",
        "linux/ufw_ebpf_rules.h",
        "linux/ufw_rules.h",
        "linux/ufw_policy.json",
        "linux/ufw.nft",
        "macos/ufw-policy.json",
        "macos/UFWPolicy.generated.swift",
    ];
    for name in expected {
        let artifact = out_dir.join(name);
        assert!(artifact.exists(), "{name} was not written");
        assert!(
            std::fs::metadata(&artifact).unwrap().len() > 0,
            "{name} is empty"
        );
    }

    // The JSON artifacts have to actually be JSON.
    for name in [
        "windows/ufw_filters.json",
        "linux/ufw_policy.json",
        "macos/ufw-policy.json",
    ] {
        let text = std::fs::read_to_string(out_dir.join(name)).unwrap();
        ufw_shared::json::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn explain_answers_the_question_an_operator_actually_asks() {
    let f = Fixture::new("explain");
    let path = f.write("p.yaml", POLICY);
    let p = path.to_str().unwrap();

    let allowed = run(&["policy", "explain", p, "udp:8.8.8.8:53:out"]);
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    let text = stdout(&allowed);
    assert!(text.contains("decision   ALLOW"), "{text}");
    assert!(text.contains("allow-dns"), "{text}");

    let denied = run(&["policy", "explain", p, "tcp:8.8.8.8:23:out"]);
    assert_eq!(code(&denied), 0);
    let text = stdout(&denied);
    assert!(text.contains("decision   DENY"), "{text}");
    assert!(text.contains("block-telnet"), "{text}");

    // And every backend agrees, which is the claim the whole system makes.
    for platform in ["windows", "linux", "macos"] {
        assert!(text.contains(platform), "{platform} missing from:\n{text}");
    }
}

#[test]
fn explain_reports_the_zone_a_destination_falls_into() {
    let f = Fixture::new("zone");
    let path = f.write("p.yaml", POLICY);
    let p = path.to_str().unwrap();

    let internal = stdout(&run(&["policy", "explain", p, "tcp:10.1.2.3:443:out"]));
    assert!(internal.contains("zone       internal"), "{internal}");

    let external = stdout(&run(&["policy", "explain", p, "tcp:8.8.8.8:443:out"]));
    assert!(external.contains("zone       external"), "{external}");
}

#[test]
fn json_output_is_machine_readable_for_ci() {
    let f = Fixture::new("ci");
    let path = f.write("p.yaml", POLICY);

    let out = run(&[
        "--output",
        "json",
        "policy",
        "validate",
        path.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v = ufw_shared::json::parse(stdout(&out).trim()).expect("valid JSON");
    assert_eq!(v.get("ok").unwrap().as_bool(), Some(true));
    assert_eq!(v.get("rules").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("ruleset_sha256").unwrap().as_str().unwrap().len(), 64);
}

#[test]
fn yaml_output_is_readable() {
    let f = Fixture::new("yaml");
    let path = f.write("p.yaml", POLICY);
    let out = run(&[
        "--output",
        "yaml",
        "policy",
        "explain",
        path.to_str().unwrap(),
        "udp:8.8.8.8:53:out",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("decision: allow"), "{text}");
    assert!(text.contains("rule: allow-dns"), "{text}");
}

#[test]
fn the_example_policies_shipped_with_the_project_all_compile() {
    // If the examples do not compile, the documentation is wrong.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let policies = root.join("policies");
    if !policies.exists() {
        return;
    }

    let mut checked = 0;
    let mut stack = vec![policies];
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
            // Files under a `fragments` directory are includes, not policies.
            if path.components().any(|c| c.as_os_str() == "fragments") {
                continue;
            }
            let out = run(&["policy", "validate", path.to_str().unwrap()]);
            assert_eq!(
                code(&out),
                0,
                "{} does not compile:\n{}",
                path.display(),
                stderr(&out)
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no example policies were found to check");
}

#[test]
fn a_missing_policy_file_is_reported_clearly() {
    let out = run(&["policy", "validate", "/nonexistent/policy.yaml"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("/nonexistent/policy.yaml"));
}

#[test]
fn compiling_for_one_platform_skips_the_others() {
    let f = Fixture::new("single");
    let path = f.write("p.yaml", POLICY);
    let out_dir = f.dir.join("generated");

    let out = run(&[
        "policy",
        "compile",
        path.to_str().unwrap(),
        "--platform",
        "linux",
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(out_dir.join("linux").exists());
    assert!(!out_dir.join("windows").exists());
    assert!(!out_dir.join("macos").exists());
}

#[test]
fn subcommand_help_never_needs_a_daemon() {
    for args in [
        vec!["policy", "--help"],
        vec!["rules", "--help"],
        vec!["identity", "--help"],
        vec!["logs", "--help"],
        vec!["debug", "--help"],
    ] {
        let out = run(&args);
        // Help you can only read when the service is up is help you cannot
        // read when you need it.
        assert_eq!(code(&out), 0, "{args:?}: {}", stderr(&out));
        assert!(
            stdout(&out).contains("ufwctl"),
            "{args:?}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn a_mistyped_command_suggests_the_real_one() {
    let out = run(&["polciy", "validate"]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("did you mean `policy`"),
        "{}",
        stderr(&out)
    );
}
