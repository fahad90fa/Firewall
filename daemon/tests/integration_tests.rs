//! The daemon's subsystems composed the way `ufwd` composes them.
//!
//! Config -> policy compilation -> staging -> install over IPC -> hot reload
//! -> rollback, with a real mock kernel module on the other end of the
//! channel. The supervisor itself lives in the binary, so this test builds an
//! equivalent one; what it exercises is the interaction between the library
//! pieces, which is where the interesting failures live.

use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ufw_daemon::config::{Config, LoggingConfig, PolicyConfig};
use ufw_daemon::identity::{IdentityService, NullResolver, ResolverOptions, TrustDatabase};
use ufw_daemon::ipc::loopback::{self, MockKernelModule};
use ufw_daemon::ipc::{KernelChannel, KernelEvent};
use ufw_daemon::logging::sink::MemorySink;
use ufw_daemon::logging::{Enrichment, Logger};
use ufw_daemon::management_api::{ApiError, Authority, ControlPlane, Request, Response, Router};
use ufw_daemon::policy_loader;
use ufw_daemon::policy_store::{apply, describe, diff};
use ufw_daemon::state::DaemonState;
use ufw_shared::log_types::Severity;
use ufw_shared::policy_types::Decision;
use ufw_shared::protocol::EnforcementMode;

const TIMEOUT: Duration = Duration::from_secs(5);

const BASE_POLICY: &str = "\
version: 1
metadata:
  name: integration
defaults:
  action: deny
address_groups:
  dns: [1.1.1.1/32, 8.8.8.8/32]
network_profile:
  internal: [10.0.0.0/8]
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
            "ufw-int-{}-{}-{name}",
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

    fn policy_config(&self) -> PolicyConfig {
        PolicyConfig {
            dir: self.dir.clone(),
            files: Vec::new(),
            signature_dir: self.dir.clone(),
            hot_reload: true,
            watch_interval_ms: 50,
            deny_warnings: false,
            verify_equivalence: true,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn logging_config() -> LoggingConfig {
    LoggingConfig {
        level: Severity::Debug,
        log_allowed: true,
        file: None,
        syslog: None,
        siem: None,
        stdout: false,
        correlation: true,
        correlation_window_secs: 300,
        correlation_threshold: 3,
    }
}

/// The supervisor, rebuilt over the library pieces.
struct TestSupervisor {
    state: Arc<DaemonState>,
    channel: Arc<KernelChannel>,
    policy: PolicyConfig,
    /// Recorded so a test can assert which path an install took.
    last_install_was_full: Mutex<bool>,
}

impl TestSupervisor {
    fn install(&self, origin: &str) -> Result<String, ApiError> {
        let loaded =
            policy_loader::load(&self.policy).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|s| s.stage(loaded.policy.clone(), origin, now));
        let Some(staged) = staged else {
            return Ok("unchanged".into());
        };

        let use_full = staged.prefers_full_install()
            || match self.state.active_policy() {
                Some(active) => {
                    apply(&active, &staged.delta).ruleset_hash
                        != staged.revision.policy.ruleset_hash
                }
                None => true,
            };
        *self.last_install_was_full.lock().unwrap() = use_full;

        if use_full {
            self.channel
                .install_policy(&staged.revision.policy, TIMEOUT)
                .map_err(|e| ApiError::internal(e.to_string()))?;
        } else {
            self.channel
                .update_policy(&staged.delta, TIMEOUT)
                .map_err(|e| ApiError::internal(e.to_string()))?;
        }

        let summary = match self.state.active_policy() {
            Some(old) => describe(&staged.delta, &old),
            None => format!("installed {} rules", staged.revision.policy.rules.len()),
        };
        let revision = staged.revision.revision();
        self.state.with_policies(|s| s.commit(staged));
        self.state.note_reload(true);
        Ok(format!("revision {revision}: {summary}"))
    }
}

impl ControlPlane for TestSupervisor {
    fn reload_policy(&self) -> Result<String, ApiError> {
        self.install("watcher")
    }
    fn validate_policy(&self) -> Result<String, ApiError> {
        policy_loader::load(&self.policy)
            .map(|l| format!("{} rules", l.policy.rules.len()))
            .map_err(|e| ApiError::bad_request(e.to_string()))
    }
    fn diff_policy(&self) -> Result<String, ApiError> {
        let loaded =
            policy_loader::load(&self.policy).map_err(|e| ApiError::bad_request(e.to_string()))?;
        let active = self
            .state
            .active_policy()
            .ok_or_else(|| ApiError::conflict("nothing installed"))?;
        Ok(describe(&diff(&active, &loaded.policy), &active))
    }
    fn rollback(&self, revision: u64) -> Result<String, ApiError> {
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|s| s.prepare_rollback(revision, now))
            .map_err(|e| ApiError::not_found(e.to_string()))?;
        self.channel
            .install_policy(&staged.revision.policy, TIMEOUT)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let new_revision = staged.revision.revision();
        self.state.with_policies(|s| s.commit(staged));
        Ok(format!("now revision {new_revision}"))
    }
    fn flush_policy(&self) -> Result<String, ApiError> {
        let now = ufw_shared::now_us();
        let staged = self
            .state
            .with_policies(|s| s.prepare_flush(now))
            .ok_or_else(|| ApiError::conflict("nothing installed"))?;
        self.channel
            .flush(TIMEOUT)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        self.state.with_policies(|s| s.commit(staged));
        Ok("flushed".into())
    }
    fn set_mode(&self, mode: EnforcementMode) -> Result<String, ApiError> {
        self.channel
            .set_mode(mode, TIMEOUT)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        self.state.set_mode(mode);
        Ok(mode.as_str().into())
    }
    fn refresh_stats(&self) -> Result<(), ApiError> {
        let stats = self
            .channel
            .stats(TIMEOUT)
            .map_err(|e| ApiError::unavailable(e.to_string()))?;
        self.state.set_kernel_stats(stats);
        Ok(())
    }
}

struct Daemon {
    router: Router,
    control: Arc<TestSupervisor>,
    state: Arc<DaemonState>,
    module: MockKernelModule,
    sink: MemorySink,
    _events: std::sync::mpsc::Receiver<KernelEvent>,
    _logger: Logger,
}

fn boot(policy_config: PolicyConfig) -> Daemon {
    let sink = MemorySink::new();
    let logger = Logger::with_sinks(
        &logging_config(),
        Enrichment {
            host_id: "int-host".into(),
            ..Default::default()
        },
        vec![Box::new(sink.clone())],
    );

    let identity = Arc::new(IdentityService::new(
        Box::new(NullResolver::new(ResolverOptions::default())),
        TrustDatabase::new(),
        ResolverOptions::default(),
        64,
    ));
    let state = Arc::new(DaemonState::new(
        "int-host",
        EnforcementMode::Enforce,
        identity,
        logger.handle(),
    ));

    let (daemon_side, module_side) = loopback::pair();
    let module = MockKernelModule::spawn(module_side);
    let (tx, events) = channel();
    let (channel, handshake) =
        KernelChannel::open(daemon_side, tx, "int-host", TIMEOUT).expect("handshake");
    state.set_kernel_connected(
        channel.endpoint().to_string(),
        handshake.module_version.clone(),
        handshake.platform.clone(),
        handshake.capabilities,
        handshake.installed_revision,
    );

    let control = Arc::new(TestSupervisor {
        state: Arc::clone(&state),
        channel: Arc::new(channel),
        policy: policy_config,
        last_install_was_full: Mutex::new(false),
    });
    let router = Router::new(Arc::clone(&state), control.clone());

    Daemon {
        router,
        control,
        state,
        module,
        sink,
        _events: events,
        _logger: logger,
    }
}

#[test]
fn a_cold_start_compiles_installs_and_reports() {
    let f = Fixture::new("cold");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());

    let summary = d.control.reload_policy().expect("install");
    assert!(summary.contains("revision 1"), "{summary}");
    assert_eq!(d.module.installed_rule_count(), 2);
    assert_eq!(d.state.active_revision(), 1);
    assert!(
        *d.control.last_install_was_full.lock().unwrap(),
        "the first install has nothing to diff against"
    );

    // Status reflects what actually happened.
    let response = d
        .router
        .dispatch(Request::Status, Authority::ReadOnly)
        .unwrap();
    let v = ufw_shared::json::parse(&response.body).unwrap();
    assert_eq!(v.get("health").unwrap().as_str(), Some("enforcing"));
    assert_eq!(
        v.get("policy").unwrap().get("rules").unwrap().as_u64(),
        Some(2)
    );

    d.module.stop();
}

#[test]
fn editing_one_rule_produces_an_incremental_update() {
    let f = Fixture::new("incremental");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    // Add a third rule; the other two are untouched.
    f.write(
        "base.yaml",
        &format!(
            "{BASE_POLICY}\
             \x20 - id: allow-ntp\n    priority: 110\n    action: allow\n    protocol: udp\n\
             \x20   destination:\n      ports: [123]\n"
        ),
    );

    let summary = d.control.reload_policy().unwrap();
    assert!(summary.contains("+ allow-ntp"), "{summary}");
    assert!(
        !*d.control.last_install_was_full.lock().unwrap(),
        "a one-rule change must not become a full reinstall"
    );
    assert_eq!(d.module.installed_rule_count(), 3);
    assert_eq!(d.state.active_revision(), 2);

    d.module.stop();
}

#[test]
fn recompiling_an_untouched_policy_changes_nothing() {
    let f = Fixture::new("noop");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();
    let revision = d.state.active_revision();

    assert_eq!(d.control.reload_policy().unwrap(), "unchanged");
    assert_eq!(d.state.active_revision(), revision, "no revision churn");

    d.module.stop();
}

#[test]
fn a_broken_edit_leaves_the_previous_policy_enforcing() {
    let f = Fixture::new("broken");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();
    let good_revision = d.state.active_revision();

    // Break it: an unresolvable address group.
    f.write(
        "base.yaml",
        "version: 1\ndefaults:\n  action: deny\n\
         rules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [nonexistent]\n",
    );

    let err = d.control.reload_policy().unwrap_err();
    assert_eq!(err.status, 400);
    assert!(err.message.contains("E0204"), "{}", err.message);

    // The kernel still holds the working policy.
    assert_eq!(d.state.active_revision(), good_revision);
    assert_eq!(d.module.installed_rule_count(), 2);

    d.module.stop();
}

#[test]
fn the_watcher_and_reload_path_work_together() {
    let f = Fixture::new("watch");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    let mut watcher = policy_loader::watcher_for(&f.policy_config());
    assert!(!watcher.poll(), "the first poll only primes");

    f.write(
        "extra.yaml",
        "version: 1\nrules:\n  - id: from-extra\n    priority: 60\n    action: deny\n\
         \x20   protocol: tcp\n    destination:\n      ports: [445]\n",
    );
    assert!(watcher.poll(), "a new policy file must be noticed");

    // The reload composes both files.
    let summary = d.control.reload_policy().unwrap();
    assert!(summary.contains("revision 2"), "{summary}");
    assert!(summary.contains("+ from-extra"), "{summary}");
    assert_eq!(d.module.installed_rule_count(), 3);

    d.module.stop();
}

#[test]
fn rollback_restores_earlier_content_under_a_new_revision() {
    let f = Fixture::new("rollback");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    f.write(
        "base.yaml",
        "version: 1\ndefaults:\n  action: deny\n\
         rules:\n  - id: only-one\n    action: deny\n    protocol: tcp\n\
         \x20   destination:\n      ports: [23]\n",
    );
    d.control.reload_policy().unwrap();
    assert_eq!(d.module.installed_rule_count(), 1);

    let result = d
        .router
        .dispatch(Request::Rollback { revision: 1 }, Authority::Admin)
        .unwrap();
    assert!(result.body.contains("revision 3"), "{}", result.body);
    // The original two rules are back, under a *new* revision number.
    assert_eq!(d.module.installed_rule_count(), 2);
    assert_eq!(d.state.active_revision(), 3);

    d.module.stop();
}

#[test]
fn rolling_back_to_an_unretained_revision_is_refused() {
    let f = Fixture::new("norollback");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    let err = d
        .router
        .dispatch(Request::Rollback { revision: 99 }, Authority::Admin)
        .unwrap_err();
    assert_eq!(err.status, 404);
    // Nothing changed.
    assert_eq!(d.state.active_revision(), 1);

    d.module.stop();
}

#[test]
fn a_flush_removes_every_rule_but_keeps_the_default() {
    let f = Fixture::new("flush");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    d.router
        .dispatch(Request::FlushPolicy, Authority::Admin)
        .unwrap();
    assert_eq!(d.module.installed_rule_count(), 0);
    assert_eq!(
        d.state.active_policy().unwrap().default_action,
        Decision::Deny,
        "a flush must not turn a default-deny policy into an open host"
    );

    d.module.stop();
}

#[test]
fn kernel_log_events_flow_through_enrichment_to_the_sink() {
    let f = Fixture::new("logs");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    d.module.push_log_event("blocked something");
    // Pump the event loop the way the daemon's main loop does.
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut delivered = false;
    while std::time::Instant::now() < deadline && !delivered {
        if let Ok(KernelEvent::Logs(batch)) = d._events.recv_timeout(Duration::from_millis(100)) {
            d.state.logs.submit(batch);
            delivered = true;
        }
    }
    assert!(delivered);

    d.state.logs.flush();
    std::thread::sleep(Duration::from_millis(200));
    let events = d.sink.take();
    assert!(!events.is_empty());
    // Enrichment fills in what the module left blank and leaves what it
    // supplied: the module stamped its own host id, so that one stands.
    assert_eq!(events[0].host_id, "mock-host");
    assert!(
        events[0].sequence > 0,
        "the logger assigns a sequence number"
    );
    assert_eq!(events[0].message.as_deref(), Some("blocked something"));

    // An event with no host id gets the daemon's.
    let mut bare = ufw_shared::log_types::LogEvent::new(
        ufw_shared::now_us(),
        "",
        Decision::Deny,
        0,
        Default::default(),
    );
    bare.rule_name = "synthetic".into();
    d.state.logs.event(bare);
    d.state.logs.flush();
    std::thread::sleep(Duration::from_millis(200));
    let events = d.sink.take();
    assert_eq!(events.last().unwrap().host_id, "int-host");

    d.module.stop();
}

#[test]
fn enforcement_mode_changes_propagate_to_state_and_module() {
    let f = Fixture::new("mode");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());

    d.router
        .dispatch(
            Request::SetMode {
                mode: EnforcementMode::Monitor,
            },
            Authority::Admin,
        )
        .unwrap();
    assert_eq!(d.state.mode(), EnforcementMode::Monitor);
    assert_eq!(d.module.mode(), EnforcementMode::Monitor);

    d.module.stop();
}

#[test]
fn losing_the_module_moves_health_to_degraded() {
    let f = Fixture::new("degraded");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();
    assert_eq!(d.state.health().as_str(), "enforcing");

    d.module.stop();
    let deadline = std::time::Instant::now() + TIMEOUT;
    while std::time::Instant::now() < deadline {
        if let Ok(KernelEvent::Disconnected(reason)) =
            d._events.recv_timeout(Duration::from_millis(100))
        {
            d.state.set_kernel_disconnected(reason);
            break;
        }
    }
    // The daemon is still up, and says plainly that nothing is filtering.
    assert_eq!(d.state.health().as_str(), "degraded");
    assert!(!d.state.kernel().connected);
}

#[test]
fn the_default_configuration_is_a_working_default_deny_deployment() {
    // A daemon started with no configuration file at all must land on a
    // conservative posture rather than an open one.
    let config = Config::default();
    assert_eq!(config.daemon.mode, EnforcementMode::Enforce);
    assert!(config.daemon.require_kernel_module);
    assert!(config.policy.verify_equivalence);
    assert!(config.api.rest_bind.is_none());
    assert!(config.logging.file.is_some());
}

#[test]
fn a_read_only_caller_cannot_reach_any_mutating_operation() {
    let f = Fixture::new("authz");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();
    let before = d.module.installed_rule_count();

    for request in [
        Request::FlushPolicy,
        Request::Rollback { revision: 1 },
        Request::SetMode {
            mode: EnforcementMode::EmergencyAllow,
        },
        Request::ReloadPolicy,
    ] {
        assert_eq!(
            d.router
                .dispatch(request, Authority::ReadOnly)
                .unwrap_err()
                .status,
            403
        );
    }
    assert_eq!(d.module.installed_rule_count(), before);
    assert_eq!(d.state.mode(), EnforcementMode::Enforce);

    d.module.stop();
}

#[test]
fn every_read_only_endpoint_answers_with_parseable_json() {
    let f = Fixture::new("json");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    for request in [
        Request::Status,
        Request::Stats,
        Request::ListRules { filter: None },
        Request::GetRule {
            key: "allow-dns".into(),
        },
        Request::ListRevisions,
        Request::ListTrust,
        Request::Ping,
    ] {
        let name = request.name();
        let Response { status, body } = d
            .router
            .dispatch(request, Authority::ReadOnly)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(status, 200, "{name}");
        ufw_shared::json::parse(&body).unwrap_or_else(|e| panic!("{name}: {e}\n{body}"));
    }

    d.module.stop();
}

#[test]
fn a_policy_directory_that_disappears_is_a_clean_failure() {
    let f = Fixture::new("gone");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    std::fs::remove_dir_all(&f.dir).unwrap();
    let err = d.control.reload_policy().unwrap_err();
    assert_eq!(err.status, 400);
    // The installed policy is untouched.
    assert_eq!(d.module.installed_rule_count(), 2);

    // Recreate so the fixture's cleanup does not report an error.
    std::fs::create_dir_all(&f.dir).unwrap();
    d.module.stop();
}

/// The composed pipeline has to produce a policy that actually decides flows
/// the way the source said it would.
#[test]
fn the_installed_policy_decides_flows_as_written() {
    use ufw_shared::policy_types::{Direction, FlowContext, Protocol};

    let f = Fixture::new("decisions");
    f.write("base.yaml", BASE_POLICY);
    let d = boot(f.policy_config());
    d.control.reload_policy().unwrap();

    let policy = d.state.active_policy().unwrap();
    let profile = &policy.network_profile;
    let check = |protocol, dst: &str, port, expected| {
        let ctx = FlowContext::new(
            profile,
            Direction::Outbound,
            protocol,
            ("10.0.0.5".parse().unwrap(), 40000),
            (dst.parse().unwrap(), port),
        );
        assert_eq!(
            policy.evaluate(&ctx).decision,
            expected,
            "{protocol:?} -> {dst}:{port}"
        );
    };

    check(Protocol::Udp, "8.8.8.8", 53, Decision::Allow);
    check(Protocol::Udp, "9.9.9.9", 53, Decision::Deny);
    check(Protocol::Tcp, "8.8.8.8", 23, Decision::Deny);
    check(Protocol::Tcp, "8.8.8.8", 443, Decision::Deny);

    d.module.stop();
}

/// Guard against a policy directory path that is a file rather than a
/// directory, which `read_dir` reports in a way worth handling explicitly.
#[test]
fn a_policy_path_that_is_not_a_directory_fails_cleanly() {
    let f = Fixture::new("notadir");
    let file = f.write("base.yaml", BASE_POLICY);
    let mut config = f.policy_config();
    config.dir = file;
    assert!(policy_loader::load(&config).is_err());
}

fn _unused(_: &Path) {}
