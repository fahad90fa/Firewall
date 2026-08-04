//! `ufwd` — the Unified Firewall control daemon.
//!
//! # Startup order, and why it is this order
//!
//! ```text
//!   config -> logging -> identity -> state -> kernel -> policy -> APIs
//! ```
//!
//! Logging comes up second so that everything after it can report its own
//! failures through the same pipeline an operator is already watching. The
//! kernel connection comes up before the policy is compiled, so that a
//! successful compile is followed immediately by an install rather than
//! sitting in memory while the daemon discovers the module is missing. The
//! management APIs come last, because an API that answers `status` before the
//! daemon knows its own status is worse than one that is briefly unavailable.
//!
//! # Failing loudly
//!
//! `daemon.require_kernel_module = true` (the default) means the daemon exits
//! rather than running with nothing enforcing. A firewall that is up but not
//! filtering, and does not say so, is the worst outcome available — worse than
//! one that failed to start, because the latter gets noticed.
//!
//! # Signals
//!
//! Installing a `SIGTERM` handler needs `sigaction`, which needs `libc`, which
//! this workspace does not take. Shutdown is therefore driven through the
//! control socket (`ufwctl shutdown`, which is what the systemd unit's
//! `ExecStop` invokes) and through the API's shutdown endpoint. A `SIGTERM`
//! with no handler still terminates the process; the sockets and the kernel
//! channel are cleaned up by the operating system, and the next start clears
//! any stale socket file itself.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::Duration;

use ufw_daemon::config::Config;
use ufw_daemon::identity::TrustDatabase;
use ufw_daemon::ipc::{self, KernelChannel, KernelEvent};
use ufw_daemon::logging::{Enrichment, Logger};
use ufw_daemon::management_api::{cli, rest, ApiError, ControlPlane, Router};
use ufw_daemon::policy_loader;
use ufw_daemon::policy_store::describe;
use ufw_daemon::signatures;
use ufw_daemon::state::{self, DaemonState, Health};
use ufw_shared::constants;
use ufw_shared::log_types::{EventKind, Severity};
use ufw_shared::protocol::{Capabilities, EnforcementMode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ufwd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "\
{name} {version} — Unified Firewall control daemon

USAGE:
    ufwd [OPTIONS]

OPTIONS:
    -c, --config <PATH>     Configuration file
                            [default: {config}]
        --check             Validate the configuration and policy, then exit
        --foreground        Log to stdout as well as the configured sinks
        --mode <MODE>       Override daemon.mode (enforce|monitor|emergency-allow)
        --load-ebpf         Pin the eBPF programs and maps, then exit
        --unload-ebpf       Remove those pins, then exit
    -V, --version           Print the version and exit
    -h, --help              Print this help and exit

The daemon is stopped with `ufwctl shutdown`, which is what a service
manager's stop command should invoke.",
        name = constants::PRODUCT_NAME,
        version = constants::VERSION,
        config = constants::DEFAULT_CONFIG_PATH_UNIX,
    );
}

struct Args {
    config: PathBuf,
    check_only: bool,
    foreground: bool,
    mode: Option<EnforcementMode>,
    /// Pin the eBPF programs and maps, then exit. Run by a `oneshot` unit
    /// before the daemon proper, so the maps outlive every later restart.
    ebpf: Option<EbpfAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EbpfAction {
    Load,
    Unload,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        config: PathBuf::from(constants::DEFAULT_CONFIG_PATH_UNIX),
        check_only: false,
        foreground: false,
        mode: None,
        ebpf: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("{} {}", constants::PRODUCT_NAME, constants::VERSION);
                return Ok(None);
            }
            "-c" | "--config" => {
                args.config = PathBuf::from(
                    argv.next()
                        .ok_or_else(|| "--config needs a path".to_string())?,
                );
            }
            "--check" => args.check_only = true,
            "--foreground" => args.foreground = true,
            "--mode" => {
                let value = argv
                    .next()
                    .ok_or_else(|| "--mode needs a value".to_string())?;
                args.mode = Some(
                    EnforcementMode::parse(&value)
                        .ok_or_else(|| format!("`{value}` is not an enforcement mode"))?,
                );
            }
            "--load-ebpf" => args.ebpf = Some(EbpfAction::Load),
            "--unload-ebpf" => args.ebpf = Some(EbpfAction::Unload),
            other => return Err(format!("unknown argument `{other}` (try --help)")),
        }
    }
    Ok(Some(args))
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    // --- configuration ---------------------------------------------------
    let mut config = if args.config.exists() {
        Config::load(&args.config).map_err(|e| format!("{}: {e}", args.config.display()))?
    } else if args.config == PathBuf::from(constants::DEFAULT_CONFIG_PATH_UNIX) {
        // Running with no configuration file is legitimate: the defaults are a
        // working default-deny deployment.
        Config::default()
    } else {
        return Err(format!("{} does not exist", args.config.display()));
    };
    if args.foreground {
        config.logging.stdout = true;
    }
    if let Some(mode) = args.mode {
        config.daemon.mode = mode;
    }

    if args.check_only {
        return check(&config);
    }

    // Before anything else, and without touching the policy: this runs as its
    // own `oneshot` unit ordered ahead of the daemon.
    if let Some(action) = args.ebpf {
        return ebpf(action);
    }

    // --- logging ---------------------------------------------------------
    let enrichment = Enrichment {
        host_id: config.daemon.host_id.clone(),
        policy_revision: 0,
        profile: Default::default(),
    };
    let (mut logger, problems) = Logger::start(&config.logging, enrichment);
    let logs = logger.handle();
    for problem in &problems {
        logs.note(
            &config.daemon.host_id,
            Severity::Error,
            EventKind::SystemFault,
            problem.clone(),
        );
        eprintln!("ufwd: {problem}");
    }
    logs.note(
        &config.daemon.host_id,
        Severity::Notice,
        EventKind::PolicyChange,
        format!(
            "{} {} starting on {}",
            constants::PRODUCT_NAME,
            constants::VERSION,
            ufw_shared::BUILD_TARGET
        ),
    );

    // --- identity --------------------------------------------------------
    // Platform anchors first, so a configured anchor for the same subject
    // overrides rather than duplicates it.
    let mut anchors = state::platform_trust_anchors();
    anchors.extend(config.identity.trust_anchors.iter().cloned());
    let identity = {
        let mut identity_config = config.identity.clone();
        identity_config.trust_anchors = anchors.clone();
        state::build_identity_service(&identity_config)
    };
    identity.set_trust(TrustDatabase::from_entries(&anchors));

    // --- state -----------------------------------------------------------
    let daemon = Arc::new(DaemonState::new(
        config.daemon.host_id.clone(),
        config.daemon.mode,
        Arc::clone(&identity),
        logs.clone(),
    ));

    // --- signatures ------------------------------------------------------
    //
    // Before the policy, so the policy load can report DPI rules that name a
    // signature nothing defines. A malformed signature file is logged and
    // skipped rather than fatal: the alternative is that one bad entry in a
    // threat-intel drop takes the whole firewall down, which trades a partial
    // inspection capability for no filtering at all.
    {
        let (signatures, problems) = signatures::load_dir(&config.policy.signature_dir);
        for problem in &problems {
            logs.note(
                &config.daemon.host_id,
                Severity::Error,
                EventKind::SystemFault,
                format!("signature: {problem}"),
            );
            eprintln!("ufwd: signature: {problem}");
        }
        logs.note(
            &config.daemon.host_id,
            Severity::Notice,
            EventKind::PolicyChange,
            format!(
                "loaded {} signature(s) from {}{}",
                signatures.len(),
                config.policy.signature_dir.display(),
                if problems.is_empty() {
                    String::new()
                } else {
                    format!(", {} skipped", problems.len())
                }
            ),
        );
        daemon.set_signatures(signatures);
    }

    // --- kernel ----------------------------------------------------------
    let connection = ipc::establish(
        &config.ipc.endpoint,
        &config.daemon.host_id,
        Duration::from_millis(config.ipc.connect_timeout_ms),
    );

    let (channel, events) = match connection {
        Ok(conn) => {
            daemon.set_kernel_connected(
                conn.channel.endpoint().to_string(),
                conn.handshake.module_version.clone(),
                conn.handshake.platform.clone(),
                conn.handshake.capabilities,
                conn.handshake.installed_revision,
            );
            logs.note(
                &config.daemon.host_id,
                Severity::Notice,
                EventKind::PolicyChange,
                format!(
                    "kernel module {} on {} at {} (capabilities: {})",
                    conn.handshake.module_version,
                    conn.handshake.platform,
                    conn.channel.endpoint(),
                    conn.handshake.capabilities.names().join(", ")
                ),
            );
            (Some(Arc::new(conn.channel)), Some(conn.events))
        }
        Err(e) => {
            let message = format!("cannot reach the kernel module: {e}");
            daemon.set_kernel_disconnected(Some(e.to_string()));
            logs.note(
                &config.daemon.host_id,
                Severity::Critical,
                EventKind::SystemFault,
                message.clone(),
            );
            if config.daemon.require_kernel_module {
                // Refusing to run is the only honest outcome: continuing would
                // present a firewall that is not filtering anything.
                logger.shutdown();
                return Err(format!(
                    "{message}\n\
                     Set `daemon.require_kernel_module = false` to run without enforcement \
                     (policy will compile and the APIs will answer, but nothing will be filtered)."
                ));
            }
            eprintln!("ufwd: {message} — continuing without enforcement");
            (None, None)
        }
    };

    // --- signature install -----------------------------------------------
    //
    // After the handshake, before the policy. A module that receives a DPI
    // rule before the signature it names would evaluate that rule against an
    // empty signature set for however long the gap lasted, and report a clean
    // scan of traffic nothing had been loaded to look for.
    //
    // A module without the DPI capability is skipped rather than failed: the
    // policy may not use DPI at all, and refusing to start would turn an
    // unused feature into an outage. A policy that *does* use DPI on such a
    // module is reported by the dangling-reference check further down.
    if let Some(channel) = &channel {
        let capabilities = daemon.kernel().capabilities;
        if capabilities.has(Capabilities::DPI) {
            let payload = daemon.signatures().encode();
            match channel.install_signatures(
                &payload,
                Duration::from_millis(config.ipc.connect_timeout_ms),
            ) {
                Ok(ack) => logs.note(
                    &config.daemon.host_id,
                    Severity::Notice,
                    EventKind::PolicyChange,
                    format!(
                        "installed {} signature(s) into the kernel module{}",
                        ack.signatures_installed,
                        if ack.patterns_installed > 0 {
                            format!(
                                ", {} content pattern(s) in one shared automaton",
                                ack.patterns_installed
                            )
                        } else {
                            // Either nothing to search for, or a set past the
                            // module's table limits. Both mean the module
                            // searches per signature: slower, same verdicts.
                            String::from(", no shared automaton (per-signature search)")
                        }
                    ),
                ),
                Err(e) => {
                    // Not fatal. The module keeps filtering on the policy it
                    // has; what it loses is payload inspection, and saying so
                    // is more use than exiting.
                    let message = format!("signature install rejected by the module: {e}");
                    logs.note(
                        &config.daemon.host_id,
                        Severity::Error,
                        EventKind::SystemFault,
                        message.clone(),
                    );
                    eprintln!("ufwd: {message}");
                }
            }
        } else if !daemon.signatures().is_empty() {
            logs.note(
                &config.daemon.host_id,
                Severity::Warning,
                EventKind::SystemFault,
                format!(
                    "{} signature(s) loaded but the kernel module does not report the dpi \
                     capability; no payload inspection will happen",
                    daemon.signatures().len()
                ),
            );
        }
    }

    // --- policy ----------------------------------------------------------
    let control = Arc::new(Supervisor {
        state: Arc::clone(&daemon),
        channel: channel.clone(),
        config: config.clone(),
    });

    match control.reload_policy() {
        Ok(summary) => logs.note(
            &config.daemon.host_id,
            Severity::Notice,
            EventKind::PolicyChange,
            summary,
        ),
        Err(e) => {
            let message = format!("initial policy load failed: {}", e.message);
            logs.note(
                &config.daemon.host_id,
                Severity::Critical,
                EventKind::SystemFault,
                message.clone(),
            );
            eprintln!("ufwd: {message}");
            // A daemon with no policy installed enforces nothing, so this is
            // fatal for the same reason a missing kernel module is.
            if config.daemon.require_kernel_module {
                logger.shutdown();
                return Err(message);
            }
        }
    }

    // A DPI rule naming a signature nobody shipped installs cleanly and never
    // fires, while the operator who wrote it believes the traffic is being
    // inspected. Nothing else in the system would ever complain, so this is
    // the only place it gets said.
    let dangling = daemon.dangling_signature_refs();
    if !dangling.is_empty() {
        let message = format!(
            "{} DPI signature reference(s) in the installed policy match no loaded \
             signature, so those rules can never fire; run `ufwctl debug signatures` \
             to see which",
            dangling.len()
        );
        logs.note(
            &config.daemon.host_id,
            Severity::Warning,
            EventKind::PolicyChange,
            message.clone(),
        );
        eprintln!("ufwd: {message}");
    }

    // --- management APIs -------------------------------------------------
    let router = Arc::new(Router::new(Arc::clone(&daemon), control.clone()));
    let mut workers = Vec::new();

    {
        let router = Arc::clone(&router);
        let state = Arc::clone(&daemon);
        let path = config.api.cli_socket.clone();
        let logs = logs.clone();
        let host = config.daemon.host_id.clone();
        workers.push(std::thread::spawn(move || {
            if let Err(e) = cli::serve(router, path, state) {
                logs.note(
                    &host,
                    Severity::Error,
                    EventKind::SystemFault,
                    format!("control socket failed: {e}"),
                );
            }
        }));
    }

    if config.api.rest_bind.is_some() {
        let router = Arc::clone(&router);
        let state = Arc::clone(&daemon);
        let api = config.api.clone();
        let logs = logs.clone();
        let host = config.daemon.host_id.clone();
        workers.push(std::thread::spawn(move || {
            if let Err(e) = rest::serve(router, api, state) {
                logs.note(
                    &host,
                    Severity::Error,
                    EventKind::SystemFault,
                    format!("REST listener failed: {e}"),
                );
            }
        }));
    }

    // --- main loop -------------------------------------------------------
    let mut watcher = policy_loader::watcher_for(&config.policy);
    let interval = policy_loader::watch_interval(&config.policy);

    logs.note(
        &config.daemon.host_id,
        Severity::Notice,
        EventKind::PolicyChange,
        format!(
            "ready: {} rules at revision {}, watching {} ({})",
            daemon.rule_count(),
            daemon.active_revision(),
            config.policy.dir.display(),
            watcher.name()
        ),
    );

    while !daemon.is_shutting_down() {
        // Kernel events first: log batches and identity queries are latency
        // sensitive in a way a policy reload is not.
        if let Some(events) = &events {
            drain_kernel_events(events, &daemon, channel.as_deref(), interval);
        } else {
            std::thread::sleep(interval);
        }

        if watcher.poll() {
            match control.reload_policy() {
                Ok(summary) => logs.note(
                    &config.daemon.host_id,
                    Severity::Notice,
                    EventKind::PolicyChange,
                    summary,
                ),
                Err(e) => logs.note(
                    &config.daemon.host_id,
                    Severity::Error,
                    EventKind::SystemFault,
                    format!(
                        "policy reload failed, keeping the installed policy: {}",
                        e.message
                    ),
                ),
            }
        }
    }

    // --- shutdown --------------------------------------------------------
    daemon.set_health(Health::Stopping);
    logs.note(
        &config.daemon.host_id,
        Severity::Notice,
        EventKind::PolicyChange,
        "shutting down; the installed policy stays in the kernel until the module is unloaded",
    );
    logs.flush();

    for worker in workers {
        let _ = worker.join();
    }
    if let Some(channel) = channel {
        if let Ok(mut channel) = Arc::try_unwrap(channel) {
            channel.shutdown();
        }
    }
    logger.shutdown();
    Ok(())
}

/// `--check`: validate configuration and policy without touching the kernel.
/// Pin the eBPF programs and maps, or remove those pins.
///
/// # Why this shells out to bpftool
///
/// Loading a BPF program means the `bpf(2)` syscall, and reaching it from Rust
/// means either `libc` or a hand-written syscall wrapper per architecture.
/// This workspace takes no dependencies, and hand-rolling architecture-
/// specific syscall stubs to save one exec is a poor trade: `bpftool` ships
/// with the kernel's own tooling, is versioned with it, and reports verifier
/// rejections in the form the kernel meant them.
///
/// The daemon still owns *where* things are pinned, because the pin paths are
/// also what `fast_path_available` looks for, and two places that both know
/// the layout is one place too many.
fn ebpf(action: EbpfAction) -> Result<(), String> {
    use std::process::Command;

    let pin_dir = constants::LINUX_BPF_PIN_DIR;

    if action == EbpfAction::Unload {
        // Removing a pin does not stop a program that is still attached; it
        // drops this reference to it. Detaching is the module's business, and
        // an unload that also detached would leave the machine unfiltered
        // during a package upgrade.
        let mut removed = 0usize;
        for path in ufw_daemon::ipc::linux::bpf_pin_paths() {
            if std::path::Path::new(&path).exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("cannot remove pin {path}: {e}"))?;
                removed += 1;
            }
        }
        // Not an error when there was nothing to remove: `ExecStop` runs on
        // every stop, including after a start that never got this far, and a
        // failing stop leaves the unit in a state an operator has to clear by
        // hand.
        println!("removed {removed} pin(s) under {pin_dir}");
        return Ok(());
    }

    let object_dir = std::path::Path::new(constants::LINUX_BPF_OBJECT_DIR);
    if !object_dir.exists() {
        return Err(format!(
            "{} does not exist; the eBPF objects are part of the kernel-module \
             package, so this usually means only the userland half is installed",
            object_dir.display()
        ));
    }

    std::fs::create_dir_all(pin_dir)
        .map_err(|e| format!("cannot create {pin_dir}: {e} (is /sys/fs/bpf mounted?)"))?;

    let object = object_dir.join("packet_filter.o");
    if !object.exists() {
        return Err(format!("{} is missing", object.display()));
    }

    let output = Command::new("bpftool")
        .arg("prog")
        .arg("loadall")
        .arg(&object)
        .arg(pin_dir)
        .arg("pinmaps")
        .arg(pin_dir)
        .output()
        .map_err(|e| {
            format!(
                "cannot run bpftool: {e}. It ships with the kernel's tooling \
                     (linux-tools on Debian, bpftool on Fedora)"
            )
        })?;

    if !output.status.success() {
        // The verifier's own words. Summarising them would throw away the
        // instruction number, which is the only part that locates the problem.
        return Err(format!(
            "bpftool refused {}:\n{}",
            object.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    println!("pinned the eBPF fast path under {pin_dir}");
    Ok(())
}

fn check(config: &Config) -> Result<(), String> {
    println!("configuration: ok");
    println!("  host id        : {}", config.daemon.host_id);
    println!("  mode           : {}", config.daemon.mode.as_str());
    println!("  policy dir     : {}", config.policy.dir.display());
    println!(
        "  kernel endpoint: {}",
        if config.ipc.endpoint.is_empty() {
            ipc::default_endpoint().to_string()
        } else {
            config.ipc.endpoint.clone()
        }
    );

    match policy_loader::load(&config.policy) {
        Ok(loaded) => {
            println!("policy: ok");
            println!("  source         : {}", loaded.source.display());
            println!("  rules          : {}", loaded.policy.rules.len());
            println!(
                "  ruleset        : sha256:{}",
                ufw_shared::hash::hex(&loaded.policy.ruleset_hash)
            );
            println!("  warnings       : {}", loaded.warning_count);
            println!("  rules removed  : {} (optimizer)", loaded.rules_removed);
            println!("  ebpf eligible  : {}", loaded.ebpf_eligible);
            println!(
                "  equivalence    : verified across {} scenarios",
                loaded.equivalence_scenarios
            );
            if !loaded.diagnostics.is_empty() {
                println!("\n{}", loaded.diagnostics);
            }
            Ok(())
        }
        Err(e) => Err(format!("policy: FAILED\n{e}")),
    }
}

/// Consume kernel events for up to `budget`.
fn drain_kernel_events(
    events: &std::sync::mpsc::Receiver<KernelEvent>,
    state: &Arc<DaemonState>,
    channel: Option<&KernelChannel>,
    budget: Duration,
) {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match events.recv_timeout(remaining) {
            Ok(KernelEvent::Logs(batch)) => state.logs.submit(batch),
            Ok(KernelEvent::IdentityQuery { seq, query }) => {
                state.note_identity_query();
                let identity = state.identity.answer(&query);
                if let Some(channel) = channel {
                    let _ = channel.answer_identity(seq, &identity);
                }
            }
            Ok(KernelEvent::Error { code, detail }) => state.logs.note(
                &state.host_id,
                Severity::Error,
                EventKind::SystemFault,
                format!("kernel module reported error {code}: {detail}"),
            ),
            Ok(KernelEvent::Disconnected(reason)) => {
                state.set_kernel_disconnected(reason.clone());
                state.logs.note(
                    &state.host_id,
                    Severity::Critical,
                    EventKind::SystemFault,
                    format!(
                        "kernel module disconnected{}; nothing is being filtered",
                        reason.map(|r| format!(": {r}")).unwrap_or_default()
                    ),
                );
                return;
            }
            Err(RecvTimeoutError::Timeout) => return,
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The control plane behind the management API.
struct Supervisor {
    state: Arc<DaemonState>,
    channel: Option<Arc<KernelChannel>>,
    config: Config,
}

impl Supervisor {
    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.ipc.connect_timeout_ms)
    }

    /// Compile, verify, install. Every failure leaves the previous policy in
    /// place.
    fn install(&self, origin: &str) -> Result<String, ApiError> {
        let loaded = policy_loader::load(&self.config.policy)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;

        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|store| store.stage(loaded.policy.clone(), origin, now));

        let Some(staged) = staged else {
            return Ok(ufw_daemon::management_api::simple(
                "policy is unchanged; nothing to install",
            ));
        };

        // A module that does not advertise incremental updates gets the whole
        // table. Nothing checked this before, so the capability bit was
        // advertised, reported by `ufwctl status`, and never consulted — and a
        // module that answered a delta with "unsupported" would have failed
        // every reload after the first.
        let incremental = self
            .state
            .kernel()
            .capabilities
            .has(Capabilities::INCREMENTAL_UPDATE);

        // Then check the daemon's own arithmetic before trusting the delta: if
        // applying it to the installed policy does not reproduce what was
        // compiled, send the whole thing instead.
        let use_full = !incremental || staged.prefers_full_install() || {
            match self.state.active_policy() {
                Some(active) => {
                    let rebuilt = ufw_daemon::policy_store::apply(&active, &staged.delta);
                    rebuilt.ruleset_hash != staged.revision.policy.ruleset_hash
                }
                None => true,
            }
        };

        if let Some(channel) = &self.channel {
            let result = if use_full {
                channel.install_policy(&staged.revision.policy, self.timeout())
            } else {
                channel.update_policy(&staged.delta, self.timeout())
            };
            match result {
                Ok(ack) => {
                    for warning in &ack.warnings {
                        self.state.logs.note(
                            &self.state.host_id,
                            Severity::Warning,
                            EventKind::PolicyChange,
                            format!("kernel module: {warning}"),
                        );
                    }
                }
                Err(e) => {
                    self.state.note_reload(false);
                    return Err(ApiError::internal(format!(
                        "kernel module rejected the policy, keeping revision {}: {e}",
                        self.state.active_revision()
                    )));
                }
            }
        }

        let summary = match self.state.active_policy() {
            Some(old) => describe(&staged.delta, &old),
            None => format!("installed {} rules", staged.revision.policy.rules.len()),
        };
        let revision = staged.revision.revision();
        let profile = staged.revision.policy.network_profile.clone();
        self.state.with_policies(|store| store.commit(staged));
        self.state.note_reload(true);

        self.state.logs.set_enrichment(Enrichment {
            host_id: self.state.host_id.clone(),
            policy_revision: revision,
            profile,
        });

        Ok(ufw_daemon::management_api::simple(&format!(
            "revision {revision} installed from {}: {summary}{}",
            loaded.source.display(),
            if loaded.warning_count > 0 {
                format!(" ({} warning(s))", loaded.warning_count)
            } else {
                String::new()
            }
        )))
    }
}

impl ControlPlane for Supervisor {
    fn reload_policy(&self) -> Result<String, ApiError> {
        self.install("policy directory")
    }

    fn validate_policy(&self) -> Result<String, ApiError> {
        let loaded = policy_loader::load(&self.config.policy)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        Ok(ufw_daemon::management_api::simple(&format!(
            "{} compiles: {} rules, {} warning(s), equivalence verified across {} scenarios",
            loaded.source.display(),
            loaded.policy.rules.len(),
            loaded.warning_count,
            loaded.equivalence_scenarios
        )))
    }

    fn diff_policy(&self) -> Result<String, ApiError> {
        let loaded = policy_loader::load(&self.config.policy)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let Some(active) = self.state.active_policy() else {
            return Ok(ufw_daemon::management_api::simple(&format!(
                "no policy is installed; {} would install {} rules",
                loaded.source.display(),
                loaded.policy.rules.len()
            )));
        };
        let delta = ufw_daemon::policy_store::diff(&active, &loaded.policy);
        Ok(ufw_daemon::management_api::simple(&describe(
            &delta, &active,
        )))
    }

    fn rollback(&self, revision: u64) -> Result<String, ApiError> {
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|store| store.prepare_rollback(revision, now))
            .map_err(|e| ApiError::not_found(e.to_string()))?;

        if let Some(channel) = &self.channel {
            channel
                .install_policy(&staged.revision.policy, self.timeout())
                .map_err(|e| ApiError::internal(format!("rollback rejected by the module: {e}")))?;
        }
        let new_revision = staged.revision.revision();
        self.state.with_policies(|store| store.commit(staged));
        Ok(ufw_daemon::management_api::simple(&format!(
            "rolled back to revision {revision}, now active as revision {new_revision}"
        )))
    }

    fn flush_policy(&self) -> Result<String, ApiError> {
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|store| store.prepare_flush(now))
            .ok_or_else(|| ApiError::conflict("no policy is installed"))?;

        if let Some(channel) = &self.channel {
            channel
                .flush(self.timeout())
                .map_err(|e| ApiError::internal(format!("flush rejected by the module: {e}")))?;
        }
        let default = staged.revision.policy.default_action;
        self.state.with_policies(|store| store.commit(staged));
        self.state.logs.note(
            &self.state.host_id,
            Severity::Critical,
            EventKind::PolicyChange,
            format!("policy flushed; only the default action ({default}) remains"),
        );
        Ok(ufw_daemon::management_api::simple(&format!(
            "all rules removed; the default action ({default}) still applies"
        )))
    }

    fn set_mode(&self, mode: EnforcementMode) -> Result<String, ApiError> {
        if let Some(channel) = &self.channel {
            channel
                .set_mode(mode, self.timeout())
                .map_err(|e| ApiError::internal(format!("the module refused the mode: {e}")))?;
        }
        self.state.set_mode(mode);
        // Emergency mode disables enforcement entirely, so it is recorded at
        // the highest severity available.
        let severity = match mode {
            EnforcementMode::EmergencyAllow => Severity::Critical,
            EnforcementMode::Monitor => Severity::Warning,
            EnforcementMode::Enforce => Severity::Notice,
        };
        self.state.logs.note(
            &self.state.host_id,
            severity,
            EventKind::PolicyChange,
            format!("enforcement mode is now {}", mode.as_str()),
        );
        Ok(ufw_daemon::management_api::simple(&format!(
            "enforcement mode is now {}",
            mode.as_str()
        )))
    }

    fn refresh_stats(&self) -> Result<(), ApiError> {
        let Some(channel) = &self.channel else {
            return Ok(());
        };
        match channel.stats(self.timeout()) {
            Ok(stats) => {
                self.state.set_kernel_stats(stats);
                Ok(())
            }
            Err(e) => Err(ApiError::unavailable(format!(
                "the kernel module did not answer: {e}"
            ))),
        }
    }
}
