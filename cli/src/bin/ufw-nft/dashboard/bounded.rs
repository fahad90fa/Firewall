//! Bounded external-command execution.
//!
//! `state_json` shells out to `nft`, `journalctl`, and `dmesg` on the request
//! thread. `Command::output()` blocks until the child exits with no deadline,
//! so a child that wedges — `nft` contending on the kernel's nftables lock
//! while a concurrent `apply`/trial transaction holds it, a slow or oversized
//! journal — parks the HTTP handler past the browser's 8-second abort, and the
//! page reports "Connection lost" for a server that is in fact alive and would
//! have answered a moment later.
//!
//! [`run_bounded`] gives every such call a hard deadline: on expiry the child
//! is killed and the caller gets a `TimedOut` error it can render as a
//! per-source failure, exactly like a command that could not be spawned. The
//! endpoint is already built for per-source failure, so a wedged `nft` becomes
//! an error banner instead of a lost connection.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Run `cmd` to completion, or kill it once `budget` elapses.
///
/// stdout and stderr are drained on their own threads: a child can fill its
/// pipe buffer and block on `write` while we are blocked on `wait`, so reading
/// the pipes concurrently is what keeps the deadline honest for large output
/// (a full ruleset, a busy journal).
pub fn run_bounded(mut cmd: Command, budget: Duration) -> std::io::Result<Output> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        // Unreachable: we just set both to piped(). Fail closed rather than
        // unwrap, so this stays panic-free on the request path.
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other("could not capture child output"));
    };
    let reader_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let reader_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });

    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait()? {
            Some(status) => {
                let stdout = reader_out.join().unwrap_or_default();
                let stderr = reader_err.join().unwrap_or_default();
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "command exceeded its time budget",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_command_returns_its_output() {
        let mut cmd = Command::new("printf");
        cmd.arg("hello");
        let out = run_bounded(cmd, Duration::from_secs(5)).expect("printf runs");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
    }

    #[test]
    fn a_command_past_its_budget_is_killed_and_times_out() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let started = Instant::now();
        let err = run_bounded(cmd, Duration::from_millis(150)).expect_err("must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        // The deadline is honored: we do not wait anywhere near the full sleep.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "run_bounded waited too long: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_missing_binary_is_a_spawn_error_not_a_hang() {
        let cmd = Command::new("this-binary-does-not-exist-ufwnft");
        let r = run_bounded(cmd, Duration::from_secs(5));
        assert!(r.is_err());
    }
}
