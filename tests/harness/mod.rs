//! The end-to-end test harness.
//!
//! # What these tests can and cannot do
//!
//! They cannot load a kernel module. Nothing in CI can, and a test that only
//! runs on a machine with a signed driver and a rebooted kernel is a test that
//! runs once a quarter. So the harness draws the line deliberately:
//!
//!   - **Everything above the kernel boundary is real.** The compiler is real,
//!     the policy store is real, the IPC framing is real, the identity trust
//!     logic is real, the log pipeline is real.
//!   - **The kernel module is a mock** that speaks the real wire protocol and
//!     can be told to misbehave. It is the only substitution.
//!
//! That boundary is where the substitution is honest. Everything a mock kernel
//! module could get wrong about *policy* is checked against the reference
//! evaluator instead, and the C and Swift classifiers are checked against the
//! reference by the compiler's equivalence verifier, which does not need a
//! running kernel either.
//!
//! What is genuinely not covered here is whether the C compiles and behaves as
//! written. `tests/docker/` covers the compile; only a real deployment covers
//! the behaviour, and the documentation says so rather than implying otherwise.
//!
//! # Determinism
//!
//! No timing dependencies, no sleeps waiting for a condition, no ports bound to
//! fixed numbers. A flaky end-to-end test is worse than a missing one: it
//! trains people to re-run the suite until it passes, which is the same as not
//! having it.

pub mod connection_tracker;
pub mod enforcement;
pub mod log_verifier;
pub mod packet_generator;

use std::path::PathBuf;

use ufw_policy_lang::{compile_str, Compilation, CompileOptions};
use ufw_shared::policy_types::CompiledPolicy;

/// A scratch directory that cleans up after itself.
///
/// Not `/tmp/<fixed name>`: two scenarios running concurrently would share it,
/// and the failure would look like a bug in whichever one lost the race.
pub struct Scratch {
    pub dir: PathBuf,
}

impl Scratch {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ufw-e2e-{}-{}-{name}",
            std::process::id(),
            ufw_shared::now_us()
        ));
        std::fs::create_dir_all(&dir).expect("creating the scratch directory");
        Scratch { dir }
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, contents).expect("writing a fixture file");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Compile a policy, failing the test with the rendered diagnostics if it does
/// not compile.
///
/// Scenarios assert on behaviour, so a scenario that fails because its fixture
/// stopped compiling should say *that*, with the compiler's own caret output,
/// rather than panicking on an `unwrap` several lines later.
pub fn compile(source: &str) -> Compilation {
    let result = compile_str("scenario", source, &CompileOptions::default());
    assert!(
        result.is_ok(),
        "the scenario's policy does not compile:\n{}",
        result.render()
    );
    result
}

pub fn policy(source: &str) -> CompiledPolicy {
    compile(source).policy.expect("a compiled policy")
}

/// A policy most scenarios can share.
///
/// Deliberately small and hand-verifiable: a scenario that fails should send
/// the reader to the scenario, not to a hundred-rule fixture.
pub const BASELINE: &str = "\
version: 1
metadata:
  name: e2e-baseline
defaults:
  action: deny
  log: true
address_groups:
  internal: [10.0.0.0/8]
  dns: [1.1.1.1/32, 8.8.8.8/32]
port_groups:
  web: [80, 443]
network_profile:
  internal: [internal]
  dns_servers: [1.1.1.1]
rules:
  - id: allow-icmp
    priority: 10
    layer: packet
    action: allow
    protocol: icmp
  - id: block-telnet
    priority: 20
    layer: packet
    action: deny
    protocol: tcp
    destination:
      ports: [23]
  - id: allow-dns
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: udp
    destination:
      addresses: [dns]
      ports: [53]
  - id: allow-internal-web
    priority: 200
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [internal]
      ports: web
";
