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

mod dashboard;
mod knock;
mod license;
mod state;

use std::io::Write;
use std::path::{Path, PathBuf};
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
        Some("boot-apply") => cmd_boot_apply(rest),
        Some("trial") => cmd_trial(rest),
        Some("status") => cmd_status(),
        Some("revert") => cmd_revert(rest),
        Some("check") => cmd_check(rest),
        Some("render") => cmd_render(rest),
        Some("dashboard") => cmd_dashboard(rest),
        Some("knock") => cmd_knock(rest),
        Some("license") => license::cmd_license(rest),
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
    ufw-nft boot-apply [fallback.yaml]    Restore the last-applied policy at boot (for systemd)
    ufw-nft trial  <policy.yaml> <secs>   Apply it, then auto-revert after <secs> (lockout-safe)
    ufw-nft status                        Show the loaded ruleset and per-rule counters
    ufw-nft revert                        Remove the ruleset (table inet ufw)
    ufw-nft check  <policy.yaml>          Compile and validate with nft, loading nothing
    ufw-nft render <policy.yaml>          Print the exact ruleset `apply` would load
    ufw-nft dashboard [addr:port]         Serve the live web console (default 127.0.0.1:8787)
                      [--tls-cert F --tls-key F --tls-client-ca F]
                                          Serve it over mTLS: a client certificate that chains to
                                          --tls-client-ca is mapped to an RBAC role by its SHA-256
                                          fingerprint (console-auth.json). Needs a --features tls build.
    ufw-nft knock  <port> <k1> <k2>…      Hide a port behind a knock sequence (off | status)
    ufw-nft license activate <KEY>        Activate this machine (node-locked, one key one machine)
    ufw-nft license status [--refresh]    Show the license state (and re-check online with --refresh)
    ufw-nft license check                 Re-validate online; revert enforcement if the key has lapsed
    ufw-nft --version | --help

This is real enforcement: after `apply`, the kernel filters this machine's
traffic against the policy. It covers the packet-layer policy (addresses,
ports, protocols); identity and DPI rules need the kernel module. Loading
rules needs root — run these with sudo. Everything is confined to the
`inet ufw` table, so `revert` removes exactly what was added.

The dashboard shows, live: every rule with its packet counters, every denied
or alerted packet with the rule and reason that produced it, attack-pattern
analysis per source, and this host's listening services and connections.

A bare policy name is looked up under {} —
`apply default_deny` finds base/default_deny.yaml there.",
        POLICY_DIR
    );
}

// --- commands --------------------------------------------------------------

/// Compile `path`, let the kernel validate it, load it live, and record it for
/// the dashboard (and for boot restore). The shared core of `apply` and
/// `boot-apply`.
fn enforce(path: &Path) -> Result<CompiledRuleset, String> {
    let compiled = compile_ruleset(path)?;
    // The kernel's own parser validates it before we commit anything live.
    nft_pipe(&compiled.nft, true)
        .map_err(|e| format!("the generated ruleset failed nft's own check: {e}"))?;
    nft_pipe(&compiled.nft, false)?;
    if let Err(e) = state::record(path, &compiled, "apply", 0) {
        eprintln!("  note: could not record dashboard state: {e}");
    }
    Ok(compiled)
}

fn cmd_apply(args: &[String]) -> Result<(), String> {
    let path = policy_arg(args)?;
    if let license::Gate::Deny(why) = license::gate_enforcement() {
        return Err(why);
    }
    let compiled = enforce(&path)?;

    println!(
        "applied: {} is now enforced by the kernel (table inet ufw)",
        path.display()
    );
    if compiled.restrictive {
        println!(
            "\n  \u{26a0} default-drop policy: traffic this policy does not explicitly allow is now BLOCKED,\n     \
             including, potentially, your own access to this machine."
        );
    }
    println!("\n  inspect:  ufw-nft status");
    println!("  watch:    ufw-nft dashboard   (live rules, denials, attacks)");
    println!("  undo:     ufw-nft revert   (or: sudo nft delete table inet ufw)");
    Ok(())
}

/// Re-establish the kernel ruleset at boot. nftables does not persist across a
/// reboot, so a systemd oneshot calls this to load the firewall again. It
/// restores whatever policy was last `apply`d (recorded in the state file); if
/// nothing was recorded — or the recorded file is gone — it applies the
/// fallback policy named as an argument (the installer points this at the
/// monitor baseline, so a fresh box still comes up protected). Trials are
/// deliberately not restored: they are meant to be ephemeral and self-revert.
fn cmd_boot_apply(args: &[String]) -> Result<(), String> {
    // At boot a lapsed license means: come up unprotected and say so, rather
    // than fail the unit or silently restore stale rules. (An unlicensed source
    // build is ungated and falls straight through.)
    if let license::Gate::Deny(why) = license::gate_enforcement() {
        eprintln!("boot: not restoring the firewall — {why}");
        eprintln!("  this machine is running UNPROTECTED until the license is renewed.");
        return Ok(());
    }
    if let Some(st) = state::load() {
        if st.mode == "apply" && !st.policy_path.is_empty() {
            let recorded = PathBuf::from(&st.policy_path);
            if recorded.is_file() {
                let compiled = enforce(&recorded)?;
                println!(
                    "boot: restored last-applied policy {} (table inet ufw){}",
                    recorded.display(),
                    if compiled.restrictive {
                        " — default-drop"
                    } else {
                        ""
                    }
                );
                return Ok(());
            }
            eprintln!(
                "  note: recorded policy {} no longer exists; using the fallback",
                recorded.display()
            );
        }
    }

    let fallback = args.first().ok_or_else(|| {
        "no recorded policy to restore and no fallback policy given \
         (usage: ufw-nft boot-apply <fallback.yaml>)"
            .to_string()
    })?;
    let path = resolve_policy(fallback)?;
    let compiled = enforce(&path)?;
    println!(
        "boot: applied fallback policy {} (table inet ufw){}",
        path.display(),
        if compiled.restrictive {
            " — default-drop"
        } else {
            ""
        }
    );
    Ok(())
}

fn cmd_trial(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: ufw-nft trial <policy.yaml> <secs>".into());
    }
    let path = resolve_policy(&args[0])?;
    let secs: u64 = args[1]
        .parse()
        .map_err(|_| format!("`{}` is not a number of seconds", args[1]))?;
    if secs == 0 {
        return Err("the trial duration must be at least 1 second".into());
    }
    if let license::Gate::Deny(why) = license::gate_enforcement() {
        return Err(why);
    }

    let compiled = compile_ruleset(&path)?;
    nft_pipe(&compiled.nft, true)
        .map_err(|e| format!("the generated ruleset failed nft's own check: {e}"))?;
    nft_pipe(&compiled.nft, false)?;

    // Arm a detached watchdog that reverts after `secs`, surviving this
    // process, the shell, and the terminal — so a lockout heals itself. If it
    // cannot be armed, revert immediately rather than leave rules up with no
    // safety net.
    let script = format!(
        "sleep {secs}; nft delete table inet ufw 2>/dev/null; rm -f {} 2>/dev/null",
        state::STATE_PATH
    );
    let armed = spawn_detached(&script);
    if !armed {
        let _ = nft_run(&["delete", "table", "inet", "ufw"]);
        return Err(
            "could not arm the auto-revert watchdog; reverted immediately to stay safe".into(),
        );
    }
    if let Err(e) = state::record(&path, &compiled, "trial", secs) {
        eprintln!("  note: could not record dashboard state: {e}");
    }

    println!(
        "applied: {} is enforced by the kernel (table inet ufw)",
        path.display()
    );
    if compiled.restrictive {
        println!(
            "\n  \u{26a0} default-drop policy — non-allowed traffic is BLOCKED for the trial."
        );
    }
    println!(
        "\n  \u{23f1} TRIAL: this will AUTO-REVERT in {secs}s, even if you close the terminal.\n     \
         keep it:  ufw-nft apply {}\n     \
         undo now: ufw-nft revert",
        path.display()
    );
    Ok(())
}

/// Compile and validate with `nft -c`, loading nothing. This is the command
/// to run in CI or before a change window: it exercises the exact bytes
/// `apply` would commit, against the kernel's own parser.
fn cmd_check(args: &[String]) -> Result<(), String> {
    let path = policy_arg(args)?;
    let compiled = compile_ruleset(&path)?;
    nft_pipe(&compiled.nft, true)
        .map_err(|e| format!("the generated ruleset failed nft's own check: {e}"))?;
    println!(
        "ok: {} compiles to a ruleset nft accepts ({} would be enforced; nothing was loaded)",
        path.display(),
        if compiled.restrictive {
            "default-drop"
        } else {
            "default-accept"
        }
    );
    Ok(())
}

/// Print the exact instrumented ruleset `apply` would feed to nft.
fn cmd_render(args: &[String]) -> Result<(), String> {
    let path = policy_arg(args)?;
    let compiled = compile_ruleset(&path)?;
    print!("{}", compiled.nft);
    Ok(())
}

fn cmd_dashboard(args: &[String]) -> Result<(), String> {
    // The first non-flag argument is the bind address; the rest configure TLS.
    // Each `--tls-*` flag consumes the following argument as a file path.
    let mut bind: Option<String> = None;
    let mut tls = dashboard::TlsOptions::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let value = |i: usize| -> Result<std::path::PathBuf, String> {
            args.get(i + 1)
                .map(std::path::PathBuf::from)
                .ok_or_else(|| format!("{a} needs a file path"))
        };
        match a {
            "--tls-cert" => {
                tls.cert_path = Some(value(i)?);
                i += 1;
            }
            "--tls-key" => {
                tls.key_path = Some(value(i)?);
                i += 1;
            }
            "--tls-client-ca" => {
                tls.client_ca_path = Some(value(i)?);
                i += 1;
            }
            _ if a.starts_with("--") => return Err(format!("unknown flag {a}")),
            _ if bind.is_none() => bind = Some(a.to_string()),
            _ => return Err(format!("unexpected argument {a}")),
        }
        i += 1;
    }
    let bind = match bind.as_deref() {
        None => "127.0.0.1:8787".to_string(),
        Some(a) if a.contains(':') => a.to_string(),
        Some(port) => format!("127.0.0.1:{port}"),
    };
    dashboard::serve(&bind, &tls)
}

/// Port knocking: `ufw-nft knock <protected> <p1> <p2> [p3 …] [--ttl secs]`,
/// `ufw-nft knock off`, `ufw-nft knock status`.
fn cmd_knock(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => Err("usage: ufw-nft knock <protected-port> <knock1> <knock2> [knock3 …] [--ttl secs]\n       ufw-nft knock off | status".into()),
        Some("off") => {
            let out = nft_run(&["delete", "table", "inet", "ufw_knock"])?;
            if out.status.success() {
                println!("port knocking removed (table inet ufw_knock)");
                Ok(())
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                if is_missing_table(&err) {
                    println!("port knocking was not active");
                    Ok(())
                } else {
                    Err(with_root_hint(err.trim()))
                }
            }
        }
        Some("status") => {
            let out = nft_run(&["list", "table", "inet", "ufw_knock"])?;
            if out.status.success() {
                print!("{}", String::from_utf8_lossy(&out.stdout));
                Ok(())
            } else {
                println!("port knocking is not active (run: ufw-nft knock <port> <k1> <k2>)");
                Ok(())
            }
        }
        Some(_) => {
            // Parse: <protected> <k1> <k2> [k3…] [--ttl secs]
            let mut ttl = 3600u64;
            let mut ports: Vec<u16> = Vec::new();
            let mut it = args.iter();
            while let Some(a) = it.next() {
                if a == "--ttl" {
                    ttl = it
                        .next()
                        .and_then(|s| s.parse().ok())
                        .ok_or("--ttl needs a number of seconds")?;
                } else {
                    ports.push(
                        a.parse::<u16>()
                            .map_err(|_| format!("`{a}` is not a valid port"))?,
                    );
                }
            }
            if ports.len() < 3 {
                return Err(
                    "usage: ufw-nft knock <protected-port> <knock1> <knock2> [knock3 …]".into(),
                );
            }
            let protected = ports[0];
            let knocks = &ports[1..];
            knock::validate(protected, knocks)?;
            let prog = knock::program(protected, knocks, ttl);
            // The kernel's own parser validates it before we load anything.
            nft_pipe(&prog, true)
                .map_err(|e| format!("the generated knock ruleset failed nft's own check: {e}"))?;
            nft_pipe(&prog, false)?;
            let seq = knocks
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "port knocking active: TCP {protected} is now hidden — dropped until the sequence is knocked."
            );
            println!("\n  knock, in order (each a TCP SYN within 10s of the last), then connect:");
            println!("    for p in {seq}; do nmap -Pn --host-timeout 1 -p $p <this-host> >/dev/null; done");
            println!("    # or:  for p in {seq}; do (exec 3<>/dev/tcp/<this-host>/$p) 2>/dev/null; done");
            println!("  an admitted source keeps access for {ttl}s.");
            println!("\n  applies-when: your policy does not itself drop {protected} (default-allow, or leave {protected} unlisted).");
            println!("  inspect: ufw-nft knock status     remove: ufw-nft knock off");
            Ok(())
        }
    }
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

/// Remove the loaded ruleset. By default this also forgets the recorded policy,
/// so a plain `revert` means "turn my firewall off". `--keep-state` removes only
/// the runtime table and leaves the record intact — that is what the boot
/// service's ExecStop uses, so stopping the service (or a normal shutdown, where
/// the rules would vanish anyway) does not erase what the next boot must restore.
fn cmd_revert(args: &[String]) -> Result<(), String> {
    let keep_state = args.iter().any(|a| a == "--keep-state");
    let out = nft_run(&["delete", "table", "inet", "ufw"])?;
    if out.status.success() {
        if !keep_state {
            state::clear();
        }
        println!(
            "{}",
            if keep_state {
                "removed table inet ufw (kept the recorded policy so the next boot restores it)"
            } else {
                "reverted: removed table inet ufw; this tool's rules are no longer enforced"
            }
        );
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        if is_missing_table(&err) {
            if !keep_state {
                state::clear();
            }
            println!("nothing to revert: no `inet ufw` table is loaded");
            Ok(())
        } else {
            Err(with_root_hint(err.trim()))
        }
    }
}

// --- compilation -----------------------------------------------------------

/// Where `make install` / install.sh put the shipped policies.
const POLICY_DIR: &str = "/etc/unified-firewall/policies";

fn policy_arg(args: &[String]) -> Result<PathBuf, String> {
    match args.first() {
        Some(p) => resolve_policy(p),
        None => Err("usage: ufw-nft apply <policy.yaml>".into()),
    }
}

/// Resolve a policy argument: an existing path wins; a bare name is looked up
/// under the installed policy tree, so `firewall apply default_deny` works
/// from any directory once the project is installed.
fn resolve_policy(arg: &str) -> Result<PathBuf, String> {
    let direct = Path::new(arg);
    if direct.exists() {
        return Ok(direct.to_path_buf());
    }
    // Only bare names get the search treatment; an explicit path that does
    // not exist should say so, not silently match something else.
    if !arg.contains('/') {
        let mut names = vec![arg.to_string()];
        if !arg.ends_with(".yaml") {
            names.push(format!("{arg}.yaml"));
        }
        for sub in ["", "base", "hardening", "applications", "test"] {
            for name in &names {
                let candidate = Path::new(POLICY_DIR).join(sub).join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
        return Err(format!(
            "`{arg}` is not a file here and not a policy under {POLICY_DIR}\n\
             (installed policies: try `ls -R {POLICY_DIR}`)"
        ));
    }
    Err(format!("`{arg}` does not exist"))
}

/// Everything `apply` needs to enforce a policy and everything the dashboard
/// later needs to explain it.
pub struct CompiledRuleset {
    /// The instrumented ruleset fed to nft.
    pub nft: String,
    /// Whether any hooked chain defaults to drop.
    pub restrictive: bool,
    pub policy_name: String,
    pub revision: u64,
    /// The compiler's JSON model of the policy (`linux/ufw_policy.json`).
    pub policy_json: String,
    /// Rule name → the YAML `description:`, the human "why" the dashboard
    /// shows next to a denial.
    pub descriptions: Vec<(String, String)>,
}

/// Compile `path` to its nftables ruleset with per-rule counters added.
fn compile_ruleset(path: &Path) -> Result<CompiledRuleset, String> {
    let opts = CompileOptions {
        platforms: vec![Platform::Linux],
        // The equivalence verifier compares three backends; enforcing on one
        // host does not need it, and skipping it keeps `apply` snappy.
        verify_equivalence: false,
        ..Default::default()
    };

    let comp = compile_file(path, &opts).map_err(|e| format!("{}: {e}", path.display()))?;
    let policy = match &comp.policy {
        Some(p) => p,
        None => {
            let rendered = comp.render();
            let sep = if rendered.is_empty() { "" } else { "\n" };
            return Err(format!(
                "{rendered}{sep}{} failed to compile",
                path.display()
            ));
        }
    };
    let policy_name = policy.name.clone();
    let revision = policy.revision;

    let artifact = comp
        .artifact(Platform::Linux)
        .ok_or_else(|| "the compiler produced no Linux artifact".to_string())?;
    let raw = artifact
        .file(NFT_ARTIFACT)
        .map(|f| f.contents.clone())
        .ok_or_else(|| "the compiler produced no nftables artifact".to_string())?;
    let policy_json = artifact
        .file("linux/ufw_policy.json")
        .map(|f| f.contents.clone())
        .unwrap_or_else(|| "{}".to_string());

    // `policy drop;` on a hooked chain is nftables' way of spelling
    // default-deny; its presence is what makes a policy able to lock you out.
    let restrictive = raw.contains("policy drop");
    Ok(CompiledRuleset {
        nft: add_counters(&raw),
        restrictive,
        policy_name,
        revision,
        policy_json,
        descriptions: rule_descriptions(path),
    })
}

/// Pull each rule's YAML `description:` back out of the source. Compiled
/// rules do not carry descriptions — the kernel has no use for prose — but
/// the dashboard does: it is the author's own words for *why* the rule
/// exists. Best-effort: a rule from an `include:` file simply has none.
fn rule_descriptions(path: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let (tokens, _) = ufw_policy_lang::lexer::tokenize(&text);
    let (doc, _) = ufw_policy_lang::parser::parse(&tokens);
    doc.rules
        .iter()
        .filter_map(|r| {
            let id = r.id.as_ref()?.value.clone();
            let desc = r.description.as_ref()?.value.clone();
            Some((id, desc))
        })
        .collect()
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
    // An alert rule has no verdict: its last statement is the log itself
    // (`… log prefix "ufw#alert#name "`). Count it too, so `status` and the
    // dashboard show how often the alert fired.
    if head.ends_with('"')
        && head.contains(" log prefix \"")
        && !head.contains("counter log prefix \"")
    {
        if let Some(i) = head.rfind("log prefix \"") {
            return format!("{}counter {}{comment}", &head[..i], &head[i..]);
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
        Err(with_root_hint(String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn nft_run(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("nft").args(args).output().map_err(spawn_err)
}

/// Spawn a fire-and-forget shell command in its own session so it outlives this
/// process and the terminal. Returns whether it was launched.
fn spawn_detached(script: &str) -> bool {
    let quiet = |c: &mut Command| {
        c.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
    fn alert_rules_get_counters_on_their_log_statement() {
        let line =
            "        tcp dport { 5432 } log prefix \"ufw#alert#watch-db \" comment \"watch-db\"";
        let once = counter_line(line);
        assert!(
            once.contains("counter log prefix \"ufw#alert#watch-db \""),
            "{once}"
        );
        assert_eq!(counter_line(&once), once, "must be idempotent");
    }

    #[test]
    fn logged_drops_keep_their_log_statement_and_gain_a_counter() {
        let line = "        tcp dport { 23 } log prefix \"ufw#deny#no-telnet \" drop comment \"no-telnet\"";
        let once = counter_line(line);
        assert!(
            once.contains("log prefix \"ufw#deny#no-telnet \" counter drop"),
            "{once}"
        );
        assert_eq!(counter_line(&once), once, "must be idempotent");
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
