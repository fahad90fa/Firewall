//! `ufw-nft` — enforce a Unified Firewall policy on this host with nftables.
//!
//! This is **real enforcement**, not a simulator. It compiles a policy with the
//! project's own compiler, renders the Linux nftables artifact, and loads it
//! into the running kernel with `nft`. From the moment `apply` returns, the
//! kernel's netfilter hooks are deciding this machine's packets against the
//! policy.
//!
//! # Scope, honestly
//!
//! nftables expresses the packet-layer policy — addresses, ports, protocols,
//! directions. It cannot express the identity (which signed program) or DPI
//! (payload) predicates; those are the kernel module's job. The compiler emits
//! this same file as a documented "parity artifact", and any rule it could not
//! translate is dropped rather than silently weakened. So this enforces the
//! L3/L4 policy faithfully and nothing it cannot express — never more than it
//! says.
//!
//! # Not locking yourself out
//!
//! A default-deny policy blocks everything it does not explicitly allow, which
//! on a live machine can cut your own access. Two guards:
//!
//! * `apply` warns loudly when the policy is default-drop, and always prints the
//!   one-line revert.
//! * `trial <policy> <secs>` applies the policy and arms a **detached**
//!   auto-revert that fires after `secs` even if this process, or the whole
//!   terminal, goes away. Test a tightening there first; if it locks you out,
//!   it heals itself.
//!
//! Everything lives in one table, `inet ufw`, so `revert` removes exactly what
//! this tool added and touches no other firewall rules on the host.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use ufw_policy_lang::{compile_file, CompileOptions};
use ufw_shared::Platform;

/// The nftables artifact the Linux backend emits.
const NFT_ARTIFACT: &str = "linux/ufw.nft";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);
    let rest = args.get(1..).unwrap_or(&[]);

    let result = match cmd {
        Some("apply") => cmd_apply(rest),
        Some("trial") => cmd_trial(rest),
        Some("status") => cmd_status(),
        Some("revert") => cmd_revert(),
        Some("-h") | Some("--help") | None => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        Some("-V") | Some("--version") => {
            println!("ufw-nft {}", ufw_shared::constants::VERSION);
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown command `{other}` (try --help)")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ufw-nft: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "\
ufw-nft — enforce a Unified Firewall policy on this host with nftables

USAGE:
    ufw-nft apply  <policy.yaml>          Compile the policy and load it into the kernel
    ufw-nft trial  <policy.yaml> <secs>   Apply it, then auto-revert after <secs> (lockout-safe)
    ufw-nft status                        Show the loaded ruleset and per-rule counters
    ufw-nft revert                        Remove the ruleset (table inet ufw)
    ufw-nft --version | --help

This is real enforcement: after `apply`, the kernel filters this machine's
traffic against the policy. It covers the packet-layer policy (addresses,
ports, protocols); identity and DPI rules need the kernel module. Loading
rules needs root — run these with sudo. Everything is confined to the
`inet ufw` table, so `revert` removes exactly what was added."
    );
}

// --- commands --------------------------------------------------------------

fn cmd_apply(args: &[String]) -> Result<(), String> {
    let path = policy_arg(args)?;
    let (nft, restrictive) = compile_ruleset(&path)?;

    // The kernel's own parser validates it before we commit anything live.
    nft_pipe(&nft, true).map_err(|e| format!("the generated ruleset failed nft's own check: {e}"))?;
    nft_pipe(&nft, false)?;

    println!(
        "applied: {} is now enforced by the kernel (table inet ufw)",
        path.display()
    );
    if restrictive {
        println!(
            "\n  \u{26a0} default-drop policy: traffic this policy does not explicitly allow is now BLOCKED,\n     \
             including, potentially, your own access to this machine."
        );
    }
    println!("\n  inspect:  ufw-nft status");
    println!("  undo:     ufw-nft revert   (or: sudo nft delete table inet ufw)");
    Ok(())
}

fn cmd_trial(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: ufw-nft trial <policy.yaml> <secs>".into());
    }
    let path = Path::new(&args[0]).to_path_buf();
    let secs: u64 = args[1]
        .parse()
        .map_err(|_| format!("`{}` is not a number of seconds", args[1]))?;
    if secs == 0 {
        return Err("the trial duration must be at least 1 second".into());
    }

    let (nft, restrictive) = compile_ruleset(&path)?;
    nft_pipe(&nft, true).map_err(|e| format!("the generated ruleset failed nft's own check: {e}"))?;
    nft_pipe(&nft, false)?;

    // Arm a detached watchdog that reverts after `secs`, surviving this
    // process, the shell, and the terminal — so a lockout heals itself. If it
    // cannot be armed, revert immediately rather than leave rules up with no
    // safety net.
    let script = format!("sleep {secs}; nft delete table inet ufw 2>/dev/null");
    let armed = spawn_detached(&script);
    if !armed {
        let _ = nft_run(&["delete", "table", "inet", "ufw"]);
        return Err(
            "could not arm the auto-revert watchdog; reverted immediately to stay safe".into(),
        );
    }

    println!(
        "applied: {} is enforced by the kernel (table inet ufw)",
        path.display()
    );
    if restrictive {
        println!("\n  \u{26a0} default-drop policy — non-allowed traffic is BLOCKED for the trial.");
    }
    println!(
        "\n  \u{23f1} TRIAL: this will AUTO-REVERT in {secs}s, even if you close the terminal.\n     \
         keep it:  ufw-nft apply {}\n     \
         undo now: ufw-nft revert",
        path.display()
    );
    Ok(())
}

fn cmd_status() -> Result<(), String> {
    let out = nft_run(&["list", "table", "inet", "ufw"])?;
    if out.status.success() {
        print!("{}", String::from_utf8_lossy(&out.stdout));
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        if is_missing_table(&err) {
            println!("no ufw ruleset is loaded (run `ufw-nft apply <policy.yaml>`)");
            Ok(())
        } else {
            Err(with_root_hint(err.trim()))
        }
    }
}

fn cmd_revert() -> Result<(), String> {
    let out = nft_run(&["delete", "table", "inet", "ufw"])?;
    if out.status.success() {
        println!("reverted: removed table inet ufw; this tool's rules are no longer enforced");
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        if is_missing_table(&err) {
            println!("nothing to revert: no `inet ufw` table is loaded");
            Ok(())
        } else {
            Err(with_root_hint(err.trim()))
        }
    }
}

// --- compilation -----------------------------------------------------------

fn policy_arg(args: &[String]) -> Result<std::path::PathBuf, String> {
    match args.first() {
        Some(p) => Ok(Path::new(p).to_path_buf()),
        None => Err("usage: ufw-nft apply <policy.yaml>".into()),
    }
}

/// Compile `path` to its nftables ruleset with per-rule counters added, and
/// report whether the policy is default-drop (restrictive).
fn compile_ruleset(path: &Path) -> Result<(String, bool), String> {
    let opts = CompileOptions {
        platforms: vec![Platform::Linux],
        // The equivalence verifier compares three backends; enforcing on one
        // host does not need it, and skipping it keeps `apply` snappy.
        verify_equivalence: false,
        ..Default::default()
    };

    let comp = compile_file(path, &opts).map_err(|e| format!("{}: {e}", path.display()))?;
    if comp.policy.is_none() {
        let rendered = comp.render();
        let sep = if rendered.is_empty() { "" } else { "\n" };
        return Err(format!("{rendered}{sep}{} failed to compile", path.display()));
    }

    let raw = comp
        .artifact(Platform::Linux)
        .and_then(|a| a.file(NFT_ARTIFACT))
        .map(|f| f.contents.clone())
        .ok_or_else(|| "the compiler produced no nftables artifact".to_string())?;

    // `policy drop;` on a hooked chain is nftables' way of spelling
    // default-deny; its presence is what makes a policy able to lock you out.
    let restrictive = raw.contains("policy drop");
    Ok((add_counters(&raw), restrictive))
}

/// Add a `counter` to every rule so `status` shows real per-rule packet and
/// byte hits — the difference between "loaded" and "actually matching traffic".
/// Chain-policy lines (`type filter hook … policy drop;`) are left untouched.
fn add_counters(nft: &str) -> String {
    let mut out = String::with_capacity(nft.len() + 256);
    for line in nft.lines() {
        out.push_str(&counter_line(line));
        out.push('\n');
    }
    out
}

fn counter_line(line: &str) -> String {
    let trimmed = line.trim_start();
    // Structure, comments, and the chain declaration are never rules.
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("table ")
        || trimmed.starts_with("chain ")
        || trimmed.starts_with("type ")
        || trimmed.starts_with('}')
    {
        return line.to_string();
    }

    // A rule is `<matchers> <verdict> [comment "…"]`; the verdict is the token
    // right before `comment` (or the last token). Splitting off the comment
    // first keeps a rule name that contains "drop"/"accept" from being mistaken
    // for the verdict.
    let (head, comment) = match line.find(" comment ") {
        Some(i) => (&line[..i], &line[i..]),
        None => (line, ""),
    };
    let head = head.trim_end();
    for verdict in ["accept", "drop", "reject"] {
        if head.ends_with(verdict) && !head.ends_with(&format!("counter {verdict}")) {
            let base = &head[..head.len() - verdict.len()];
            return format!("{base}counter {verdict}{comment}");
        }
    }
    line.to_string()
}

// --- nft plumbing ----------------------------------------------------------

/// Feed a ruleset to `nft -f -`. With `check_only`, `nft -c` validates without
/// committing.
fn nft_pipe(ruleset: &str, check_only: bool) -> Result<(), String> {
    let mut cmd = Command::new("nft");
    if check_only {
        cmd.arg("-c");
    }
    cmd.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(spawn_err)?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "could not write to nft".to_string())?;
        stdin
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("could not send the ruleset to nft: {e}"))?;
        // stdin drops here, closing the pipe so nft can finish.
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft did not run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(with_root_hint(
            String::from_utf8_lossy(&out.stderr).trim(),
        ))
    }
}

fn nft_run(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("nft").args(args).output().map_err(spawn_err)
}

/// Spawn a fire-and-forget shell command in its own session so it outlives this
/// process and the terminal. Returns whether it was launched.
fn spawn_detached(script: &str) -> bool {
    let quiet = |c: &mut Command| {
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    };
    // `setsid` fully detaches; if it is missing, a plain spawn still survives
    // this process exiting, which is enough for the common case.
    let mut with_setsid = Command::new("setsid");
    with_setsid.arg("sh").arg("-c").arg(script);
    quiet(&mut with_setsid);
    if with_setsid.spawn().is_ok() {
        return true;
    }
    let mut plain = Command::new("sh");
    plain.arg("-c").arg(script);
    quiet(&mut plain);
    plain.spawn().is_ok()
}

fn spawn_err(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        "`nft` was not found; install nftables (Debian/Parrot: `sudo apt install nftables`)".into()
    } else {
        format!("could not run nft: {e}")
    }
}

fn is_missing_table(stderr: &str) -> bool {
    stderr.contains("No such file or directory") || stderr.contains("does not exist")
}

/// nftables refuses without CAP_NET_ADMIN; say so usefully instead of echoing a
/// bare "Operation not permitted".
fn with_root_hint(stderr: &str) -> String {
    if stderr.contains("permitted") || stderr.contains("Permission denied") {
        format!("{stderr}\n(loading firewall rules needs root — run this with `sudo`)")
    } else if stderr.is_empty() {
        "nft failed with no message".to_string()
    } else {
        stderr.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_added_to_rules_only() {
        let src = "\
table inet ufw {
    chain input {
        type filter hook input priority 0; policy drop;
        ip daddr { 127.0.0.0/8 } accept comment \"allow-loopback\"
        drop comment \"deny-inbound\"
    }
}";
        let out = add_counters(src);
        // The chain policy line is untouched.
        assert!(out.contains("type filter hook input priority 0; policy drop;"));
        assert!(!out.contains("policy counter drop"));
        // Rules gain a counter before their verdict, comments preserved.
        assert!(out.contains("accept comment \"allow-loopback\""));
        assert!(out.contains("counter accept comment \"allow-loopback\""));
        assert!(out.contains("counter drop comment \"deny-inbound\""));
    }

    #[test]
    fn counter_insertion_is_idempotent() {
        let once = counter_line("        drop comment \"x\"");
        let twice = counter_line(&once);
        assert_eq!(once, twice);
        assert!(once.contains("counter drop"));
    }

    #[test]
    fn structure_lines_are_left_alone() {
        for line in ["table inet ufw {", "    chain output {", "    }", "}", ""] {
            assert_eq!(counter_line(line), line);
        }
    }

    #[test]
    fn a_rule_name_containing_a_verdict_word_is_not_mistaken_for_one() {
        // The comment says "accept-dns" but the verdict is drop; the counter
        // must attach to the real verdict.
        let line = "        tcp dport 53 drop comment \"block-accept-dns\"";
        let out = counter_line(line);
        assert!(out.contains("counter drop comment \"block-accept-dns\""));
        assert!(!out.contains("counter accept"));
    }
}
