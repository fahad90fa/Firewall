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

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ufw_daemon::audit::{AuditCategory, AuditLog};
use ufw_daemon::config::Config;
use ufw_daemon::failsafe::{self, EnforcementPosture, PathHealth};
use ufw_daemon::identity::TrustDatabase;
use ufw_daemon::ipc::{self, KernelEvent};
use ufw_daemon::logging::{Enrichment, Logger};
use ufw_daemon::management_api::{cli, rest, ApiError, ControlPlane, Router};
use ufw_daemon::policy_loader;
use ufw_daemon::policy_store::describe;
use ufw_daemon::signatures;
use ufw_daemon::state::{self, DaemonState, Health};
use ufw_daemon::watchdog::Watchdog;
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
        --verify-audit <PATH>
                            Verify a tamper-evident audit log, then exit
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
    /// Verify a tamper-evident audit log and exit. Reads the file, checks the
    /// hash chain, and reports the first break (or that it is intact).
    verify_audit: Option<PathBuf>,
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
        verify_audit: None,
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
            "--verify-audit" => {
                args.verify_audit = Some(PathBuf::from(
                    argv.next()
                        .ok_or_else(|| "--verify-audit needs a path".to_string())?,
                ));
            }
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
    } else if args.config == Path::new(constants::DEFAULT_CONFIG_PATH_UNIX) {
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

    if let Some(path) = args.verify_audit {
        return verify_audit(&path);
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

    // The tamper-evident audit log, opened before anything that would write to
    // it. Verified on open, so a start onto a tampered log is a loud failure.
    let audit = open_audit(&config, &logs);

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

    // --- fleet -----------------------------------------------------------
    //
    // A configured secret is what turns the fleet control surface on. Without
    // it, the daemon is a single host with no distribution point, and the
    // fleet endpoints report themselves disabled rather than trusting an
    // unauthenticated bundle.
    if let Some(secret) = &config.api.fleet_secret {
        daemon.set_fleet_verifier(ufw_daemon::fleet::Verifier::new(secret.clone()));
        logs.note(
            &config.daemon.host_id,
            Severity::Notice,
            EventKind::PolicyChange,
            "fleet control enabled: policy bundles are authenticated before install",
        );
    }

    // --- kernel ----------------------------------------------------------
    let connection = ipc::establish(
        &config.ipc.endpoint,
        &config.daemon.host_id,
        Duration::from_millis(config.ipc.connect_timeout_ms),
    );

    let mut events: Option<std::sync::mpsc::Receiver<KernelEvent>> = match connection {
        Ok(conn) => {
            let endpoint = conn.channel.endpoint().to_string();
            daemon.set_kernel_connected(
                endpoint.clone(),
                conn.handshake.module_version.clone(),
                conn.handshake.platform.clone(),
                conn.handshake.capabilities,
                conn.handshake.installed_revision,
            );
            // The channel lives in shared state from here on, so the management
            // plane and a later reconnect both see one current channel rather
            // than a clone captured at startup.
            daemon.set_channel(Some(Arc::new(conn.channel)));
            logs.note(
                &config.daemon.host_id,
                Severity::Notice,
                EventKind::PolicyChange,
                format!(
                    "kernel module {} on {} at {} (capabilities: {})",
                    conn.handshake.module_version,
                    conn.handshake.platform,
                    endpoint,
                    conn.handshake.capabilities.names().join(", ")
                ),
            );
            Some(conn.events)
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
            // Running on with no kernel path: nothing is resident to enforce, so
            // `fail_mode` decides the posture. `closed` (the default) must not
            // leave the host silently open — it installs the emergency barrier;
            // `open` keeps the host reachable and unfiltered, and says so.
            match failsafe::posture(config.daemon.fail_mode, PathHealth::Unavailable) {
                EnforcementPosture::FailClosedBarrier => {
                    match failsafe::install_fail_closed_barrier(&failsafe_mgmt_ports(&config)) {
                        Ok(()) => {
                            audit_note(
                                &audit,
                                &logs,
                                &config.daemon.host_id,
                                AuditCategory::FailSafe,
                                "system",
                                "installed the emergency fail-closed barrier \
                                 (enforcement unavailable, fail_mode=closed)",
                            );
                            logs.note(
                                &config.daemon.host_id,
                                Severity::Critical,
                                EventKind::SystemFault,
                                "enforcement unavailable; fail_mode=closed — installed the emergency \
                                 default-deny barrier (loopback, established flows and management \
                                 ports kept reachable). Restore the kernel module and remove \
                                 `table inet ufw_failsafe`.",
                            )
                        }
                        Err(why) => logs.note(
                            &config.daemon.host_id,
                            Severity::Critical,
                            EventKind::SystemFault,
                            format!(
                                "enforcement unavailable and the fail-closed barrier could NOT be \
                                 installed ({why}) — the host may be unprotected; install nft or \
                                 fix privileges"
                            ),
                        ),
                    }
                }
                EnforcementPosture::FailOpenUnprotected => {
                    logs.note(
                        &config.daemon.host_id,
                        Severity::Critical,
                        EventKind::SystemFault,
                        "enforcement unavailable; fail_mode=open — the host is reachable and \
                         UNFILTERED until the kernel module is restored",
                    );
                    eprintln!("ufwd: {message} — continuing without enforcement (fail_mode=open)");
                }
                // The other postures presume a resident path; not reachable here.
                other => eprintln!("ufwd: {message} — posture {}", other.as_str()),
            }
            None
        }
    };
    // Whether the daemon ever reached a module. A daemon deliberately started
    // without one (require_kernel_module = false) is not something the watchdog
    // supervises — there is nothing to reconnect to — so it keeps the quiet
    // idle loop instead.
    let had_kernel = events.is_some();

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
    if let Some(channel) = daemon.channel() {
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
        config: config.clone(),
        audit: audit.clone(),
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
    let mut watchdog = Watchdog::new(config.watchdog.engine());
    let supervise = had_kernel && config.ipc.reconnect;

    // Publish a compact status file for the read-only ufw-nft console. Best
    // effort and off the enforcement path: its own thread, errors ignored.
    let _telemetry = ufw_daemon::telemetry::spawn(Arc::clone(&daemon), Duration::from_secs(3));

    logs.note(
        &config.daemon.host_id,
        Severity::Notice,
        EventKind::PolicyChange,
        format!(
            "ready: {} rules at revision {}, watching {} ({}); data-path supervision {}",
            daemon.rule_count(),
            daemon.active_revision(),
            config.policy.dir.display(),
            watcher.name(),
            if config.watchdog.enabled && supervise {
                "on"
            } else {
                "off"
            }
        ),
    );

    while !daemon.is_shutting_down() {
        if daemon.kernel().connected {
            // A stable connection lets the watchdog forget old faults, so a
            // crash-loop that later settles gets a clean slate.
            if config.watchdog.enabled && watchdog.on_healthy(ufw_shared::now_us()) {
                publish_watchdog(&daemon, &watchdog);
            }
            // Kernel events first: log batches and identity queries are latency
            // sensitive in a way a policy reload is not.
            match &events {
                Some(rx) => {
                    if !drain_kernel_events(rx, &daemon, interval) {
                        // The receiver died without a Disconnected event (the
                        // sender was dropped). Stop reading it — a dead receiver
                        // returns instantly, which is what spun the old loop.
                        events = None;
                        if daemon.kernel().connected {
                            daemon.set_kernel_disconnected(Some("kernel channel closed".into()));
                        }
                    }
                }
                None => interruptible_sleep(&daemon, interval),
            }
        } else if supervise {
            // Lost the module. Recover under the watchdog's pacing instead of
            // hammering: back off, and after a crash-loop stop retrying at speed
            // and get loud, so the host stays reachable.
            events = supervise_reconnect(&daemon, &config, &control, &mut watchdog, &logs);
            if events.is_none() && !daemon.is_shutting_down() {
                // supervise_reconnect only returns None on shutdown; guard the
                // loop condition regardless.
                break;
            }
        } else {
            // Not supervising (no module at startup, or reconnect disabled):
            // idle quietly rather than spinning on a dead receiver.
            events = None;
            interruptible_sleep(&daemon, interval);
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
    if let Some(channel) = daemon.set_channel(None) {
        if let Ok(mut channel) = Arc::try_unwrap(channel) {
            channel.shutdown();
        }
    }
    logger.shutdown();
    Ok(())
}

/// Copy the watchdog's current state into shared state, so `ufwctl status` and
/// the REST surface can report it. Cheap; called on every transition.
fn publish_watchdog(daemon: &DaemonState, watchdog: &Watchdog) {
    daemon.set_watchdog_report(state::WatchdogReport {
        state: watchdog.state().as_str(),
        faults_in_window: watchdog.faults_in_window(),
        total_faults: watchdog.total_faults(),
        safe_mode_entries: watchdog.safe_mode_entries(),
    });
}

/// Sleep for `dur`, but wake early to notice a shutdown request. A watchdog
/// backoff can be minutes; a daemon that ignored `ufwctl shutdown` for that long
/// would be a worse bug than the one the backoff is managing.
fn interruptible_sleep(daemon: &DaemonState, dur: Duration) {
    let slice = Duration::from_millis(250);
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        if daemon.is_shutting_down() {
            return;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        std::thread::sleep(remaining.min(slice));
    }
}

/// Drive one reconnection episode under the watchdog. Returns the new event
/// receiver once the data path is back up and fully reinstalled, or `None` if
/// the daemon is shutting down.
///
/// The invariant this protects: the daemon returns to `Enforcing` only after a
/// *successful full reinstall* into the reconnected module. A module that has
/// just (re)loaded has empty tables; reporting Enforcing before repopulating
/// them would be the one fail-open this supervision exists to prevent, so a
/// reinstall failure drops the fresh channel and counts as another fault rather
/// than proceeding.
fn supervise_reconnect(
    daemon: &Arc<DaemonState>,
    config: &Config,
    control: &Supervisor,
    watchdog: &mut Watchdog,
    logs: &ufw_daemon::logging::LogHandle,
) -> Option<std::sync::mpsc::Receiver<KernelEvent>> {
    let endpoint = if config.ipc.endpoint.is_empty() {
        ipc::default_endpoint().to_string()
    } else {
        config.ipc.endpoint.clone()
    };
    let timeout = Duration::from_millis(config.ipc.connect_timeout_ms);

    loop {
        if daemon.is_shutting_down() {
            return None;
        }

        match ipc::establish(&endpoint, &config.daemon.host_id, timeout) {
            Ok(conn) => {
                let ep = conn.channel.endpoint().to_string();
                let handshake = conn.handshake.clone();
                daemon.set_kernel_connected(
                    ep,
                    handshake.module_version.clone(),
                    handshake.platform.clone(),
                    handshake.capabilities,
                    handshake.installed_revision,
                );
                let previous = daemon.set_channel(Some(Arc::new(conn.channel)));

                match control.bring_up_data_path() {
                    Ok(note) => {
                        drop(previous);
                        if config.watchdog.enabled {
                            watchdog.on_healthy(ufw_shared::now_us());
                        }
                        publish_watchdog(daemon, watchdog);
                        logs.note(
                            &config.daemon.host_id,
                            Severity::Notice,
                            EventKind::PolicyChange,
                            format!(
                                "kernel module reconnected on {}; {}",
                                handshake.platform, note
                            ),
                        );
                        return Some(conn.events);
                    }
                    Err(e) => {
                        // Do not run with a module we could not repopulate.
                        daemon.set_channel(None);
                        drop(previous);
                        daemon.set_kernel_disconnected(Some(e.clone()));
                        logs.note(
                            &config.daemon.host_id,
                            Severity::Error,
                            EventKind::SystemFault,
                            format!("reconnect reinstall failed, staying degraded: {e}"),
                        );
                        fault_and_wait(daemon, config, watchdog, logs);
                    }
                }
            }
            Err(e) => {
                daemon.set_kernel_disconnected(Some(e.to_string()));
                fault_and_wait(daemon, config, watchdog, logs);
            }
        }
    }
}

/// Record a reconnect failure with the watchdog and wait the prescribed time.
/// The one place safe mode is entered and announced.
fn fault_and_wait(
    daemon: &Arc<DaemonState>,
    config: &Config,
    watchdog: &mut Watchdog,
    logs: &ufw_daemon::logging::LogHandle,
) {
    use ufw_daemon::watchdog::FaultResponse;

    let response = if config.watchdog.enabled {
        watchdog.on_fault(ufw_shared::now_us())
    } else {
        FaultResponse::Backoff {
            attempt: 0,
            delay: Duration::from_millis(config.ipc.reconnect_backoff_ms),
        }
    };

    match response {
        FaultResponse::EnterSafeMode { faults } => {
            daemon.set_health(Health::SafeMode);
            logs.note(
                &config.daemon.host_id,
                Severity::Critical,
                EventKind::SystemFault,
                format!(
                    "watchdog: the data path faulted {faults} times in the fault window; \
                     entering safe mode. The kernel module's last-installed policy stays \
                     resident, reconnect attempts slow down, and the host stays reachable \
                     for an operator to intervene"
                ),
            );
        }
        FaultResponse::HoldSafe { .. } => {}
        FaultResponse::Backoff { attempt, delay } => {
            if config.watchdog.enabled {
                logs.note(
                    &config.daemon.host_id,
                    Severity::Warning,
                    EventKind::SystemFault,
                    format!(
                        "watchdog: reconnect attempt {attempt} pending; backing off {} ms",
                        delay.as_millis()
                    ),
                );
            }
        }
    }

    publish_watchdog(daemon, watchdog);
    interruptible_sleep(daemon, response.delay());
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

/// The tamper-evident audit log, shared across the daemon's threads (the API
/// plane appends from its own thread; startup appends from the main one).
type SharedAudit = Option<Arc<Mutex<AuditLog>>>;

/// Open the audit log under the state directory. A failure to open it is loud
/// but not fatal: an audit trail that cannot be written is a serious problem to
/// surface, not a reason to stop filtering traffic.
fn open_audit(config: &Config, logs: &ufw_daemon::logging::LogHandle) -> SharedAudit {
    let _ = std::fs::create_dir_all(&config.daemon.state_dir);
    let path = config.daemon.state_dir.join("audit.jsonl");
    match AuditLog::open(&path, None) {
        Ok(log) => Some(Arc::new(Mutex::new(log))),
        Err(e) => {
            logs.note(
                &config.daemon.host_id,
                Severity::Error,
                EventKind::SystemFault,
                format!("tamper-evident audit log unavailable ({e}); continuing without it"),
            );
            None
        }
    }
}

/// Append a security-relevant change to the audit log, best-effort, and emit its
/// new chain head to the event log so a remote sink anchors it — which is what
/// makes tail truncation of the local file detectable. Never fails the caller.
fn audit_note(
    audit: &SharedAudit,
    logs: &ufw_daemon::logging::LogHandle,
    host_id: &str,
    category: AuditCategory,
    actor: &str,
    detail: impl Into<String>,
) {
    let Some(audit) = audit else { return };
    let detail = detail.into();
    // A poisoned lock still holds a valid log; recover it rather than losing the
    // audit trail because an unrelated thread panicked.
    let mut guard = audit.lock().unwrap_or_else(|p| p.into_inner());
    match guard.append(category, actor, detail.clone(), ufw_shared::now_us()) {
        Ok(rec) => logs.note(
            host_id,
            Severity::Notice,
            EventKind::PolicyChange,
            format!(
                "audit[{}] {} — {} (chain head sha256:{})",
                rec.seq,
                category.as_str(),
                detail,
                ufw_shared::hash::hex(&rec.hash)
            ),
        ),
        Err(e) => logs.note(
            host_id,
            Severity::Error,
            EventKind::SystemFault,
            format!("could not write the audit record: {e}"),
        ),
    }
}

/// Management ports the fail-closed barrier must keep reachable, beyond the SSH
/// port it always keeps and the loopback the barrier accepts unconditionally.
///
/// Only a *routable* management bind needs a rule — a loopback-bound console is
/// already reached through the barrier's `iif "lo"` accept, so it is not added.
/// This keeps a remote operator who manages over the web console (bound to a
/// real address, with a token and TLS) from being locked out by the barrier.
fn failsafe_mgmt_ports(config: &Config) -> Vec<u16> {
    let mut ports = Vec::new();
    for addr in [&config.api.rest_bind, &config.api.grpc_bind]
        .into_iter()
        .flatten()
    {
        if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
            if !sa.ip().is_loopback() {
                ports.push(sa.port());
            }
        }
    }
    ports
}

/// Verify a tamper-evident audit log from the command line and report.
fn verify_audit(path: &Path) -> Result<(), String> {
    let records = ufw_daemon::audit::read_records(path)?;
    match ufw_daemon::audit::verify_chain(&records, None) {
        Ok(()) => {
            println!("audit log: intact");
            println!("  {}", ufw_daemon::audit::summarize(&records));
            println!(
                "  note: this proves internal consistency. Tail truncation is only\n\
                 \x20       detectable against a head captured off-box — compare the head above\n\
                 \x20       with the `audit[...] chain head` values your SIEM recorded."
            );
            Ok(())
        }
        Err(brk) => Err(format!("audit log: TAMPERED — {}", brk.describe())),
    }
}

fn check(config: &Config) -> Result<(), String> {
    println!("configuration: ok");
    println!("  host id        : {}", config.daemon.host_id);
    println!("  mode           : {}", config.daemon.mode.as_str());
    println!("  fail mode      : {}", config.daemon.fail_mode.as_str());
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

/// Consume kernel events for up to `budget`. Returns `true` while the channel
/// is still alive, and `false` the moment it drops — either through an explicit
/// `Disconnected` event or through the sender being dropped (a dead `mpsc`
/// receiver, which would otherwise return instantly on every call and turn the
/// main loop into a busy spin).
fn drain_kernel_events(
    events: &std::sync::mpsc::Receiver<KernelEvent>,
    state: &Arc<DaemonState>,
    budget: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        match events.recv_timeout(remaining) {
            Ok(KernelEvent::Logs(batch)) => state.logs.submit(batch),
            Ok(KernelEvent::IdentityQuery { seq, query }) => {
                state.note_identity_query();
                let identity = state.identity.answer(&query);
                if let Some(channel) = state.channel() {
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
                return false;
            }
            Err(RecvTimeoutError::Timeout) => return true,
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

/// The control plane behind the management API.
struct Supervisor {
    state: Arc<DaemonState>,
    config: Config,
    audit: SharedAudit,
}

impl Supervisor {
    /// Record a security-relevant change to the tamper-evident audit log.
    fn record_audit(&self, category: AuditCategory, actor: &str, detail: impl Into<String>) {
        audit_note(
            &self.audit,
            &self.state.logs,
            &self.state.host_id,
            category,
            actor,
            detail,
        );
    }
}

impl Supervisor {
    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.ipc.connect_timeout_ms)
    }

    /// (Re)install the full data path — signatures, then the active policy —
    /// into whatever channel is currently published in state. Used on
    /// reconnect, where the module on the other end has just (re)loaded and its
    /// tables are empty. Every step is fail-closed: any error returns and the
    /// caller drops the fresh channel rather than presenting an empty module as
    /// if it were enforcing.
    fn bring_up_data_path(&self) -> Result<String, String> {
        let Some(channel) = self.state.channel() else {
            return Err("no channel to bring up".into());
        };
        let timeout = self.timeout();
        let mut installed_signatures = 0u32;

        // Signatures before the policy, for the same reason startup does it:
        // a DPI rule that reached the module before the signature it names
        // would scan against an empty set until the gap closed.
        if self.state.kernel().capabilities.has(Capabilities::DPI) {
            let payload = self.state.signatures().encode();
            let ack = channel
                .install_signatures(&payload, timeout)
                .map_err(|e| format!("signature reinstall failed: {e}"))?;
            installed_signatures = ack.signatures_installed;
        }

        // Then the active policy, forced full — not a delta against what this
        // module holds, because it holds nothing.
        let rules = match self.state.active_policy() {
            Some(active) => {
                let n = active.rules.len();
                channel
                    .install_policy(&active, timeout)
                    .map_err(|e| format!("policy reinstall failed: {e}"))?;
                n
            }
            None => 0,
        };

        Ok(format!(
            "reinstalled {rules} rule(s) and {installed_signatures} signature(s)"
        ))
    }

    /// Compile, verify, install. Every failure leaves the previous policy in
    /// place.
    fn install(&self, origin: &str) -> Result<String, ApiError> {
        let loaded = policy_loader::load(&self.config.policy)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let source = loaded.source.display().to_string();
        self.install_compiled(loaded.policy, origin, &source, loaded.warning_count)
    }

    /// Stage, install over IPC, and commit an already-compiled policy. Shared
    /// by the disk reload path ([`install`](Self::install)) and the fleet
    /// bundle push, so a pushed bundle installs through exactly the same
    /// fail-closed pipeline as a local reload.
    fn install_compiled(
        &self,
        policy: ufw_shared::policy_types::CompiledPolicy,
        origin: &str,
        source_desc: &str,
        warning_count: usize,
    ) -> Result<String, ApiError> {
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|store| store.stage(policy.clone(), origin, now));

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

        if let Some(channel) = self.state.channel() {
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
            "revision {revision} installed from {source_desc}: {summary}{}",
            if warning_count > 0 {
                format!(" ({warning_count} warning(s))")
            } else {
                String::new()
            }
        )))
    }

    /// Authenticate a signed fleet bundle and, if this host is in the rollout,
    /// install it through the shared pipeline. A bundle that fails
    /// authentication, is stale, or does not compile is refused without
    /// touching the installed policy — fail-closed, exactly like a bad reload.
    fn install_signed_bundle(
        &self,
        bundle: &ufw_daemon::fleet::Bundle,
    ) -> Result<String, ApiError> {
        let verifier = self.state.fleet_verifier().ok_or_else(|| {
            ApiError::bad_request("fleet is not configured; set `api.fleet_secret`")
        })?;
        verifier
            .accept(bundle, self.state.active_revision())
            .map_err(|e| match e {
                ufw_daemon::fleet::BundleError::NotAuthentic => ApiError::forbidden(e.to_string()),
                _ => ApiError::conflict(e.to_string()),
            })?;

        // The host compiles the bundle's source itself, so it validates what it
        // is about to run rather than trusting the distribution point.
        let compiled = ufw_policy_lang::compile_str(
            "fleet-bundle",
            &bundle.source,
            &ufw_policy_lang::CompileOptions::default(),
        );
        let Some(policy) = compiled.policy.clone() else {
            return Err(ApiError::bad_request(format!(
                "bundle revision {} does not compile:\n{}",
                bundle.revision,
                compiled.render()
            )));
        };

        // Record the rollout target and this host's canary membership.
        let in_canary = ufw_daemon::fleet::in_canary(
            &self.state.host_id,
            bundle.revision,
            bundle.canary_percent,
        );
        self.state.with_fleet(|f| {
            f.set_target(bundle.revision, bundle.canary_percent);
            f.record(
                &self.state.host_id,
                self.state.active_revision(),
                ufw_shared::now_us(),
            );
        });

        // A host outside the canary group holds off until the rollout widens;
        // it has authenticated and validated the bundle, it just does not apply
        // it yet. This is what makes a staged rollout staged.
        if !in_canary {
            return Ok(ufw_daemon::management_api::simple(&format!(
                "bundle revision {} authenticated; this host is not in the {}% canary, holding at \
                 revision {}",
                bundle.revision,
                bundle.canary_percent,
                self.state.active_revision()
            )));
        }

        let origin = format!("fleet bundle revision {}", bundle.revision);
        self.install_compiled(
            policy,
            &origin,
            &origin,
            compiled.diagnostics.warning_count(),
        )
    }
}

impl ControlPlane for Supervisor {
    fn reload_policy(&self) -> Result<String, ApiError> {
        let result = self.install("policy directory");
        if let Ok(summary) = &result {
            // "unchanged" is a no-op reload, not a policy change worth a record.
            if !summary.contains("unchanged") {
                self.record_audit(AuditCategory::PolicyChange, "api", summary.clone());
            }
        }
        result
    }

    fn install_bundle(&self, bundle: &ufw_daemon::fleet::Bundle) -> Result<String, ApiError> {
        let result = self.install_signed_bundle(bundle);
        if let Ok(summary) = &result {
            self.record_audit(
                AuditCategory::Fleet,
                "fleet",
                format!("installed signed bundle rev {}: {summary}", bundle.revision),
            );
        }
        result
    }

    fn distribute_bundle(
        &self,
        members: &[String],
        bundle: &ufw_daemon::fleet::Bundle,
    ) -> Result<String, ApiError> {
        let verifier = self.state.fleet_verifier().ok_or_else(|| {
            ApiError::bad_request("fleet is not configured; set `api.fleet_secret`")
        })?;
        // Sign here, once, and reuse the same bearer token the operator gave
        // the local API to authenticate to each member's.
        let poster = ufw_daemon::fleet_client::HttpPoster {
            auth_token: self.config.api.auth_token.clone(),
            timeout: self.timeout(),
        };
        let results =
            ufw_daemon::fleet_client::distribute(&verifier, bundle.clone(), members, &poster);
        Ok(ufw_daemon::fleet_client::results_json(
            bundle.revision,
            &results,
        ))
    }

    fn reload_signatures(&self) -> Result<String, ApiError> {
        // Reload the whole set from disk. A malformed file is logged and
        // skipped, never fatal — the same posture as startup, because one bad
        // entry in a threat-intel drop must not disarm inspection entirely.
        let (set, problems) = signatures::load_dir(&self.config.policy.signature_dir);
        for problem in &problems {
            self.state.logs.note(
                &self.config.daemon.host_id,
                Severity::Error,
                EventKind::SystemFault,
                format!("signature: {problem}"),
            );
        }

        let count = set.len();
        let patterns = set.patterns().len();

        // Fail-closed ordering: install into the kernel *before* swapping the
        // in-memory set, so a set the module rejects leaves the previously
        // installed one resident in both the kernel and the daemon — exactly
        // as a failed policy reload keeps the previous policy.
        if let Some(channel) = self.state.channel() {
            if self.state.kernel().capabilities.has(Capabilities::DPI) {
                let payload = set.encode();
                channel
                    .install_signatures(&payload, self.timeout())
                    .map_err(|e| {
                        ApiError::internal(format!("signature reload rejected by the module: {e}"))
                    })?;
            }
        }

        let skipped = if problems.is_empty() {
            String::new()
        } else {
            format!(", {} skipped", problems.len())
        };
        match self.state.refresh_signatures(set) {
            None => Ok(ufw_daemon::management_api::simple(
                "signatures unchanged; nothing to reload",
            )),
            Some(revision) => Ok(ufw_daemon::management_api::simple(&format!(
                "signatures reloaded: revision {revision}, {count} signature(s), \
                 {patterns} pattern(s){skipped}"
            ))),
        }
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

        if let Some(channel) = self.state.channel() {
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

        if let Some(channel) = self.state.channel() {
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
        if let Some(channel) = self.state.channel() {
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
        self.record_audit(
            AuditCategory::ModeChange,
            "api",
            format!("enforcement mode set to {}", mode.as_str()),
        );
        Ok(ufw_daemon::management_api::simple(&format!(
            "enforcement mode is now {}",
            mode.as_str()
        )))
    }

    fn refresh_stats(&self) -> Result<(), ApiError> {
        let Some(channel) = self.state.channel() else {
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
