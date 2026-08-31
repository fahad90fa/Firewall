//! Real-packet enforcement conformance: does the *emitted* Linux artifact
//! actually enforce the policy, or does it only look like it would?
//!
//! Every other test in this workspace checks the policy *model* — the reference
//! evaluator, the cross-platform equivalence verifier, the optimizer. None of
//! them loads the nftables the compiler emits into a kernel and fires a packet
//! at it. That gap is exactly where the `allow-inspect` bypass hid: the model
//! was correct, the equivalence checker compared models, and the emitted nft
//! quietly lowered a provisional permit to a terminal `accept`. A model test
//! could not have caught it. A packet can.
//!
//! This module supplies the two levels of that packet test:
//!
//!   * **Level 1 — loadability.** `nft --check -f` on the emitted ruleset. The
//!     kernel's own parser validates every expression against the features it
//!     actually supports; a rule that names a match the running kernel does not
//!     have fails here rather than in production. Needs `nft` and root.
//!
//!   * **Level 2 — enforcement.** The ruleset is loaded in a throwaway network
//!     namespace and a real loopback connection is attempted for each probe.
//!     A policy that says *allow* must let the handshake complete; one that says
//!     *deny* must drop it. This is the level that turns "plausible nftables"
//!     into "nftables that enforces what the policy says." Needs `nft`, root,
//!     `unshare`, and a C compiler for the ~60-line probe helper.
//!
//! Both levels are *gated on capability, not skipped silently*: when the tools
//! are missing the functions report `Unavailable(reason)`, and the caller
//! decides. In CI the caller sets `UFW_NFT_REQUIRE=1` / `UFW_NETNS_REQUIRE=1`
//! and an `Unavailable` becomes a hard failure — the same pattern the
//! differential fuzzing gate uses — so "the conformance test did not actually
//! run" can never masquerade as "the conformance test passed."

use std::path::{Path, PathBuf};
use std::process::Command;

use ufw_policy_lang::{compile_str, CompileOptions};
use ufw_shared::Platform;

/// The verdict a probe expects, and the verdict a probe observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The handshake completed: the ruleset let the packet through.
    Allow,
    /// The handshake did not complete: the ruleset dropped the packet.
    Deny,
}

impl Verdict {
    fn parse(s: &str) -> Option<Verdict> {
        match s {
            "allow" => Some(Verdict::Allow),
            "deny" => Some(Verdict::Deny),
            _ => None,
        }
    }
}

/// A single probe: attempt a loopback TCP connection to `port` and expect
/// `want`.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub port: u16,
    pub want: Verdict,
}

impl Probe {
    pub fn allow(port: u16) -> Probe {
        Probe {
            port,
            want: Verdict::Allow,
        }
    }
    pub fn deny(port: u16) -> Probe {
        Probe {
            port,
            want: Verdict::Deny,
        }
    }
}

/// The outcome of asking for a capability-gated check.
#[derive(Debug)]
pub enum Outcome {
    /// The check ran and every assertion held.
    Ran,
    /// The check could not run, for the stated reason. Whether that is a skip
    /// or a failure is the caller's decision (see [`resolve`]).
    Unavailable(String),
    /// The check ran and an assertion failed. Always a test failure.
    Mismatch(String),
}

/// Turn an [`Outcome`] into a pass/fail, honoring a `require` environment
/// variable so CI can forbid the "did not run" outcome.
///
/// `Ran` passes. `Mismatch` always panics. `Unavailable` panics *iff* the named
/// variable is set to `1`, and otherwise prints why it was skipped and returns.
#[track_caller]
pub fn resolve(outcome: Outcome, require_env: &str) {
    match outcome {
        Outcome::Ran => {}
        Outcome::Mismatch(why) => panic!("enforcement conformance mismatch: {why}"),
        Outcome::Unavailable(why) => {
            if std::env::var(require_env).as_deref() == Ok("1") {
                panic!("{require_env}=1 requires the check to run, but it could not: {why}");
            }
            eprintln!("skipping ({require_env} unset): {why}");
        }
    }
}

/// Compile `source` for Linux only and return the emitted `linux/ufw.nft` text.
///
/// Linux-only so the equivalence verifier (which needs all three backends) is
/// not invoked; this module is about the Linux artifact specifically.
pub fn emit_linux_nft(source: &str) -> String {
    let c = compile_str(
        "conformance",
        source,
        &CompileOptions::single_platform(Platform::Linux),
    );
    assert!(
        c.is_ok(),
        "the conformance policy does not compile:\n{}",
        c.render()
    );
    let artifact = c
        .artifact(Platform::Linux)
        .expect("a Linux artifact for a Linux-only compilation");
    artifact
        .file("linux/ufw.nft")
        .expect("the Linux artifact emits linux/ufw.nft")
        .contents
        .clone()
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_root() -> bool {
    // No libc in the tree; ask `id -u`. Absent `id` means we cannot prove root,
    // so treat it as not-root and let the check report itself unavailable.
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn unique_tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ufw-conf-{}-{}-{name}",
        std::process::id(),
        ufw_shared::now_us()
    ))
}

/// Level 1: does the emitted ruleset load into the kernel's nftables parser?
pub fn nft_check(nft_text: &str) -> Outcome {
    if !have("nft") {
        return Outcome::Unavailable("`nft` not found on PATH".into());
    }
    if !is_root() {
        return Outcome::Unavailable("not root; `nft --check` needs CAP_NET_ADMIN".into());
    }
    let file = unique_tmp("check.nft");
    if std::fs::write(&file, nft_text).is_err() {
        return Outcome::Unavailable("could not write the ruleset to a temp file".into());
    }
    let out = Command::new("nft")
        .arg("--check")
        .arg("-f")
        .arg(&file)
        .output();
    let _ = std::fs::remove_file(&file);
    match out {
        Ok(o) if o.status.success() => Outcome::Ran,
        Ok(o) => Outcome::Mismatch(format!(
            "`nft --check` rejected the emitted ruleset:\n{}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Outcome::Unavailable(format!("could not run `nft`: {e}")),
    }
}

/// The directory holding this crate's netns helpers (`run.sh`, `netprobe.c`).
fn netns_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("netns")
}

/// Compile the `netprobe` helper into a temp path, returning it. `cc` is the
/// same compiler the kernel module build already requires.
fn compile_netprobe() -> Result<PathBuf, String> {
    let src = netns_dir().join("netprobe.c");
    let bin = unique_tmp("netprobe");
    let status = Command::new("cc")
        .arg("-O2")
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .status()
        .map_err(|e| format!("could not run `cc`: {e}"))?;
    if !status.success() {
        return Err("compiling netprobe.c failed".into());
    }
    Ok(bin)
}

/// Level 2: load the ruleset in a throwaway netns and fire a real loopback
/// packet for each probe, asserting the observed verdict matches the expected.
pub fn netns_enforces(nft_text: &str, probes: &[Probe]) -> Outcome {
    if !is_root() {
        return Outcome::Unavailable("not root; a network namespace needs CAP_SYS_ADMIN".into());
    }
    if !have("nft") {
        return Outcome::Unavailable("`nft` not found on PATH".into());
    }
    if !have("unshare") {
        return Outcome::Unavailable("`unshare` not found on PATH".into());
    }
    if !have("cc") {
        return Outcome::Unavailable("no C compiler for the probe helper".into());
    }
    let netprobe = match compile_netprobe() {
        Ok(p) => p,
        Err(e) => return Outcome::Unavailable(e),
    };
    let nft_file = unique_tmp("enforce.nft");
    if std::fs::write(&nft_file, nft_text).is_err() {
        let _ = std::fs::remove_file(&netprobe);
        return Outcome::Unavailable("could not write the ruleset to a temp file".into());
    }

    let mut cmd = Command::new("sh");
    cmd.arg(netns_dir().join("run.sh"))
        .arg(&netprobe)
        .arg(&nft_file);
    for p in probes {
        cmd.arg(format!("{}:{}", p.port, verdict_word(p.want)));
    }
    let out = cmd.output();
    let _ = std::fs::remove_file(&netprobe);
    let _ = std::fs::remove_file(&nft_file);

    let out = match out {
        Ok(o) => o,
        Err(e) => return Outcome::Unavailable(format!("could not run the netns harness: {e}")),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        // The harness distinguishes "could not run" (RESULT error) from a real
        // enforcement disagreement, but a non-zero exit with no RESULT line is
        // an environment problem, not a policy failure.
        let reason = stdout
            .lines()
            .find_map(|l| l.strip_prefix("RESULT error: "))
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("netns harness exited non-zero: {stderr}"));
        return Outcome::Unavailable(reason);
    }

    // Parse `PORT observed=allow|deny` lines and compare to expectations.
    let mut observed = std::collections::HashMap::new();
    for line in stdout.lines() {
        if let Some((port, rest)) = line.split_once(' ') {
            if let (Ok(port), Some(word)) = (port.parse::<u16>(), rest.strip_prefix("observed=")) {
                if let Some(v) = Verdict::parse(word.trim()) {
                    observed.insert(port, v);
                }
            }
        }
    }
    for p in probes {
        match observed.get(&p.port) {
            Some(&got) if got == p.want => {}
            Some(&got) => {
                return Outcome::Mismatch(format!(
                    "port {}: policy says {:?}, the loaded ruleset {:?}\n\
                     --- ruleset ---\n{}",
                    p.port, p.want, got, nft_text
                ));
            }
            None => {
                return Outcome::Unavailable(format!(
                    "the harness produced no verdict for port {} (output:\n{stdout})",
                    p.port
                ));
            }
        }
    }
    Outcome::Ran
}

fn verdict_word(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    }
}
