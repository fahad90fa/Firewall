//! Global daemon state.
//!
//! One structure, behind one set of locks, holding everything the management
//! API, the policy loader and the IPC supervisor all need to see. Splitting it
//! per subsystem was tried and produced lock-ordering questions with no good
//! answer; a single owner with narrow accessors is easier to reason about and
//! the contention is nil at this scale.
//!
//! Locks are never held across an IPC round trip. The pattern everywhere is:
//! take what you need under the lock, drop it, do the slow thing, then take it
//! again to record the result.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use ufw_shared::identity_types::TrustLevel;
use ufw_shared::json::JsonWriter;
use ufw_shared::policy_types::CompiledPolicy;
use ufw_shared::protocol::{Capabilities, EnforcementMode, KernelStats};

use crate::fleet::{FleetRegistry, Verifier};
use crate::identity::IdentityService;
use crate::logging::LogHandle;
use crate::policy_store::PolicyStore;
use crate::signatures::SignatureSet;

/// What the daemon is currently able to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Connected to a kernel module with a policy installed.
    Enforcing,
    /// Running, but the kernel module is unreachable. No filtering is
    /// happening; this is the state that must be loud.
    Degraded,
    /// The data path has faulted repeatedly and the watchdog has stopped fast
    /// retries to keep the host reachable. The kernel module's last-installed
    /// policy remains resident; the daemon is retrying at a slow cadence and
    /// this is recorded at the highest severity. Distinct from `Degraded` so an
    /// operator can tell "briefly disconnected, retrying" from "crash-looped,
    /// held down on purpose". See [`crate::watchdog`].
    SafeMode,
    /// Starting up.
    Starting,
    /// Shutting down.
    Stopping,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Enforcing => "enforcing",
            Health::Degraded => "degraded",
            Health::SafeMode => "safe-mode",
            Health::Starting => "starting",
            Health::Stopping => "stopping",
        }
    }
}

/// A snapshot of the data-path watchdog, for `status`. The watchdog itself
/// lives in the daemon's supervision loop; this is what it publishes so
/// monitoring can distinguish "up" from "up, but has been crash-looping".
#[derive(Debug, Clone, Copy)]
pub struct WatchdogReport {
    /// `nominal`, `recovering`, or `safe-mode`.
    pub state: &'static str,
    /// Faults currently counted inside the fault window.
    pub faults_in_window: u32,
    /// Faults ever seen, since the daemon started.
    pub total_faults: u64,
    /// Times safe mode has been entered.
    pub safe_mode_entries: u64,
}

impl Default for WatchdogReport {
    fn default() -> Self {
        WatchdogReport {
            state: "nominal",
            faults_in_window: 0,
            total_faults: 0,
            safe_mode_entries: 0,
        }
    }
}

/// Connection state to the kernel module.
#[derive(Debug, Clone, Default)]
pub struct KernelState {
    pub connected: bool,
    pub endpoint: String,
    pub module_version: String,
    pub platform: String,
    pub capabilities: Capabilities,
    pub installed_revision: u64,
    /// Consecutive failed connection attempts, for backoff and reporting.
    pub reconnect_attempts: u32,
    pub last_error: Option<String>,
}

/// Daemon-wide shared state.
pub struct DaemonState {
    pub host_id: String,
    started_at: Instant,
    started_at_us: u64,

    health: RwLock<Health>,
    mode: RwLock<EnforcementMode>,
    kernel: RwLock<KernelState>,
    /// The live control channel to the kernel module, or `None` when the daemon
    /// is running without enforcement (module never reached, or lost). Held here
    /// rather than in the supervisor so a reconnect swaps it in exactly one
    /// place and every management operation reads the current channel instead of
    /// a clone captured at startup that a reconnect would leave stale.
    kernel_channel: RwLock<Option<Arc<crate::ipc::KernelChannel>>>,
    watchdog: RwLock<WatchdogReport>,
    policies: Mutex<PolicyStore>,
    kernel_stats: RwLock<KernelStats>,

    pub identity: Arc<IdentityService>,
    pub logs: LogHandle,
    /// The loaded DPI signatures. Held here rather than in the policy store
    /// because signatures outlive any one policy revision: a threat-intel
    /// update replaces these without touching the installed rules.
    signatures: RwLock<Arc<SignatureSet>>,
    /// Monotonic version of the loaded signature set. 0 means none loaded yet;
    /// startup sets it to 1, and each *changed* runtime refresh bumps it.
    signature_revision: AtomicU64,
    /// Content digest of the loaded set, so a refresh that changes nothing is
    /// recognised as a no-op rather than a churned revision.
    signature_digest: RwLock<[u8; 32]>,
    signature_loaded_at_us: AtomicU64,

    /// Fleet control state. Present only when a fleet secret is configured;
    /// the registry is the in-memory roster of members that have checked in,
    /// and the verifier authenticates pushed bundles. Lazily initialised so
    /// the common single-host daemon pays nothing for it.
    fleet: Mutex<FleetRegistry>,
    fleet_verifier: RwLock<Option<Verifier>>,

    shutdown: AtomicBool,
    policy_reloads: AtomicU64,
    failed_reloads: AtomicU64,
    identity_queries: AtomicU64,
}

impl std::fmt::Debug for DaemonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonState")
            .field("host_id", &self.host_id)
            .field("health", &self.health())
            .field("mode", &self.mode())
            .field("revision", &self.active_revision())
            .finish()
    }
}

impl DaemonState {
    pub fn new(
        host_id: impl Into<String>,
        mode: EnforcementMode,
        identity: Arc<IdentityService>,
        logs: LogHandle,
    ) -> Self {
        DaemonState {
            host_id: host_id.into(),
            started_at: Instant::now(),
            started_at_us: ufw_shared::now_us(),
            health: RwLock::new(Health::Starting),
            mode: RwLock::new(mode),
            kernel: RwLock::new(KernelState::default()),
            kernel_channel: RwLock::new(None),
            watchdog: RwLock::new(WatchdogReport::default()),
            policies: Mutex::new(PolicyStore::new()),
            kernel_stats: RwLock::new(KernelStats::default()),
            identity,
            logs,
            signatures: RwLock::new(Arc::new(SignatureSet::default())),
            signature_revision: AtomicU64::new(0),
            signature_digest: RwLock::new([0u8; 32]),
            signature_loaded_at_us: AtomicU64::new(0),
            fleet: Mutex::new(FleetRegistry::default()),
            fleet_verifier: RwLock::new(None),
            shutdown: AtomicBool::new(false),
            policy_reloads: AtomicU64::new(0),
            failed_reloads: AtomicU64::new(0),
            identity_queries: AtomicU64::new(0),
        }
    }

    // --- lifecycle ------------------------------------------------------

    pub fn health(&self) -> Health {
        *self.health.read().unwrap()
    }

    pub fn set_health(&self, health: Health) {
        *self.health.write().unwrap() = health;
    }

    pub fn mode(&self) -> EnforcementMode {
        *self.mode.read().unwrap()
    }

    pub fn set_mode(&self, mode: EnforcementMode) {
        *self.mode.write().unwrap() = mode;
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn started_at_us(&self) -> u64 {
        self.started_at_us
    }

    /// Ask the daemon to stop. Every long-running loop polls this.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.set_health(Health::Stopping);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    // --- kernel ---------------------------------------------------------

    pub fn kernel(&self) -> KernelState {
        self.kernel.read().unwrap().clone()
    }

    pub fn set_kernel_connected(
        &self,
        endpoint: String,
        module_version: String,
        platform: String,
        capabilities: Capabilities,
        installed_revision: u64,
    ) {
        let mut k = self.kernel.write().unwrap();
        *k = KernelState {
            connected: true,
            endpoint,
            module_version,
            platform,
            capabilities,
            installed_revision,
            reconnect_attempts: 0,
            last_error: None,
        };
        drop(k);
        self.set_health(Health::Enforcing);
    }

    /// Record a lost connection. Health drops to `Degraded`, which is the
    /// state operators must be able to see: the daemon is up but nothing is
    /// being filtered.
    pub fn set_kernel_disconnected(&self, error: Option<String>) {
        let mut k = self.kernel.write().unwrap();
        k.connected = false;
        k.reconnect_attempts = k.reconnect_attempts.saturating_add(1);
        k.last_error = error;
        drop(k);
        // Do not downgrade a louder state. A disconnect that arrives while the
        // watchdog holds the daemon in SafeMode (a crash-loop it deliberately
        // stopped chasing) must not be repainted as a run-of-the-mill Degraded
        // blip; and a shutdown-time disconnect is expected, not a fault.
        if !self.is_shutting_down() && self.health() != Health::SafeMode {
            self.set_health(Health::Degraded);
        }
    }

    /// The live channel, if any. Callers clone the `Arc` and use it without
    /// holding the lock, so a concurrent reconnect that swaps the channel never
    /// blocks a management operation — the operation simply finishes against the
    /// channel it took, which at worst errors if that channel is mid-teardown.
    pub fn channel(&self) -> Option<Arc<crate::ipc::KernelChannel>> {
        self.kernel_channel.read().unwrap().clone()
    }

    /// Publish a (re)connected channel. The previous one, if any, is returned so
    /// the caller can tear it down after the swap rather than under the lock.
    pub fn set_channel(
        &self,
        channel: Option<Arc<crate::ipc::KernelChannel>>,
    ) -> Option<Arc<crate::ipc::KernelChannel>> {
        std::mem::replace(&mut *self.kernel_channel.write().unwrap(), channel)
    }

    pub fn watchdog_report(&self) -> WatchdogReport {
        *self.watchdog.read().unwrap()
    }

    pub fn set_watchdog_report(&self, report: WatchdogReport) {
        *self.watchdog.write().unwrap() = report;
    }

    pub fn set_kernel_stats(&self, stats: KernelStats) {
        *self.kernel_stats.write().unwrap() = stats;
    }

    pub fn kernel_stats(&self) -> KernelStats {
        self.kernel_stats.read().unwrap().clone()
    }

    // --- policy ---------------------------------------------------------

    /// Run `f` with the policy store locked. Callers must not perform IPC
    /// inside the closure.
    pub fn with_policies<R>(&self, f: impl FnOnce(&mut PolicyStore) -> R) -> R {
        let mut store = self.policies.lock().unwrap();
        f(&mut store)
    }

    pub fn active_policy(&self) -> Option<CompiledPolicy> {
        self.policies.lock().unwrap().active_policy().cloned()
    }

    pub fn active_revision(&self) -> u64 {
        self.policies.lock().unwrap().active_revision()
    }

    pub fn rule_count(&self) -> usize {
        self.policies
            .lock()
            .unwrap()
            .active_policy()
            .map(|p| p.rules.len())
            .unwrap_or(0)
    }

    pub fn note_reload(&self, ok: bool) {
        if ok {
            self.policy_reloads.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_reloads.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn note_identity_query(&self) {
        self.identity_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn counters(&self) -> Counters {
        Counters {
            policy_reloads: self.policy_reloads.load(Ordering::Relaxed),
            failed_reloads: self.failed_reloads.load(Ordering::Relaxed),
            identity_queries: self.identity_queries.load(Ordering::Relaxed),
        }
    }

    // --- signatures -----------------------------------------------------

    pub fn signatures(&self) -> Arc<SignatureSet> {
        Arc::clone(&self.signatures.read().unwrap())
    }

    /// Install the initial signature set at startup: revision 1, digest seeded.
    pub fn set_signatures(&self, set: SignatureSet) {
        *self.signature_digest.write().unwrap() = set.version();
        *self.signatures.write().unwrap() = Arc::new(set);
        self.signature_revision.store(1, Ordering::SeqCst);
        self.signature_loaded_at_us
            .store(ufw_shared::now_us(), Ordering::Relaxed);
    }

    /// Swap in a refreshed signature set, but only if it actually differs.
    ///
    /// Returns the new revision when the set changed, or `None` when it was
    /// byte-identical to the resident one — so a periodic reload of an
    /// unchanged directory is a genuine no-op, not a churned revision and a
    /// needless kernel reinstall. Mirrors the policy store's "stage returns
    /// nothing when the compile is unchanged".
    pub fn refresh_signatures(&self, set: SignatureSet) -> Option<u64> {
        let new_digest = set.version();
        {
            let current = self.signature_digest.read().unwrap();
            if *current == new_digest {
                return None;
            }
        }
        *self.signature_digest.write().unwrap() = new_digest;
        *self.signatures.write().unwrap() = Arc::new(set);
        let revision = self.signature_revision.fetch_add(1, Ordering::SeqCst) + 1;
        self.signature_loaded_at_us
            .store(ufw_shared::now_us(), Ordering::Relaxed);
        Some(revision)
    }

    pub fn signature_revision(&self) -> u64 {
        self.signature_revision.load(Ordering::SeqCst)
    }

    pub fn signature_loaded_at_us(&self) -> u64 {
        self.signature_loaded_at_us.load(Ordering::Relaxed)
    }

    /// Hex of the loaded set's content digest, for status and diagnostics.
    pub fn signature_digest_hex(&self) -> String {
        ufw_shared::hash::hex(&*self.signature_digest.read().unwrap())
    }

    // --- fleet ----------------------------------------------------------

    /// Install the bundle verifier built from the configured fleet secret.
    /// Its presence is what enables the fleet control surface.
    pub fn set_fleet_verifier(&self, verifier: Verifier) {
        *self.fleet_verifier.write().unwrap() = Some(verifier);
    }

    pub fn fleet_verifier(&self) -> Option<Verifier> {
        self.fleet_verifier.read().unwrap().clone()
    }

    pub fn fleet_enabled(&self) -> bool {
        self.fleet_verifier.read().unwrap().is_some()
    }

    /// Operate on the fleet registry under its lock.
    pub fn with_fleet<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut FleetRegistry) -> R,
    {
        f(&mut self.fleet.lock().unwrap())
    }

    /// The fleet roster as JSON, for `fleet-status`.
    pub fn fleet_status_json(&self) -> String {
        let mut w = ufw_shared::json::JsonWriter::with_capacity(2048);
        w.begin_object();
        w.bool_field("ok", true);
        w.bool_field("enabled", self.fleet_enabled());
        w.str_field("host", &self.host_id);
        let fleet = self.fleet.lock().unwrap();
        w.u64_field("target_revision", fleet.target_revision());
        w.u64_field(
            "target_canary_percent",
            fleet.target_canary_percent() as u64,
        );
        w.u64_field("members", fleet.len() as u64);
        w.u64_field("converged", fleet.converged() as u64);
        w.begin_array_field("roster");
        for m in fleet.members() {
            w.begin_object();
            w.str_field("host_id", &m.host_id);
            w.u64_field("revision", m.revision);
            w.bool_field("in_canary", m.in_canary);
            w.u64_field("last_seen", m.last_seen_us);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        w.finish()
    }

    /// Signatures the active policy names that no loaded file defines.
    ///
    /// A DPI rule referencing a signature nobody shipped compiles, installs,
    /// and never fires — while the operator who wrote it believes the traffic
    /// is being inspected. Surfacing it is the point of deriving signature ids
    /// from names rather than letting each file assign its own.
    pub fn dangling_signature_refs(&self) -> Vec<u32> {
        let Some(policy) = self.active_policy() else {
            return Vec::new();
        };
        let mut referenced: Vec<u32> = policy
            .rules
            .iter()
            .filter_map(|r| r.dpi.as_ref())
            .flat_map(|d| d.signatures.iter().copied())
            .collect();
        referenced.sort_unstable();
        referenced.dedup();
        self.signatures().missing(&referenced)
    }

    // --- reporting ------------------------------------------------------

    /// The `status` payload, shared by the CLI, REST and gRPC surfaces so all
    /// three cannot drift.
    pub fn status_json(&self) -> String {
        let kernel = self.kernel();
        let stats = self.kernel_stats();
        let counters = self.counters();
        let logs = self.logs.stats();
        let cache = self.identity.cache_stats();

        let mut w = JsonWriter::with_capacity(1024);
        w.begin_object();
        w.str_field("host_id", &self.host_id);
        w.str_field("version", ufw_shared::constants::VERSION);
        w.str_field("health", self.health().as_str());
        w.str_field("mode", self.mode().as_str());
        w.u64_field("uptime_secs", self.uptime_secs());
        w.u64_field("started_at_us", self.started_at_us);

        w.begin_object_field("kernel");
        w.bool_field("connected", kernel.connected);
        w.str_field("endpoint", &kernel.endpoint);
        w.str_field("module_version", &kernel.module_version);
        w.str_field("platform", &kernel.platform);
        w.str_array_field("capabilities", kernel.capabilities.names());
        w.u64_field("installed_revision", kernel.installed_revision);
        w.u64_field("reconnect_attempts", kernel.reconnect_attempts as u64);
        w.opt_str_field("last_error", kernel.last_error.as_deref());
        w.end_object();

        let wd = self.watchdog_report();
        w.begin_object_field("watchdog");
        w.str_field("state", wd.state);
        w.u64_field("faults_in_window", wd.faults_in_window as u64);
        w.u64_field("total_faults", wd.total_faults);
        w.u64_field("safe_mode_entries", wd.safe_mode_entries);
        w.end_object();

        w.begin_object_field("policy");
        w.u64_field("revision", self.active_revision());
        w.u64_field("rules", self.rule_count() as u64);
        w.u64_field("reloads", counters.policy_reloads);
        w.u64_field("failed_reloads", counters.failed_reloads);
        match self.with_policies(|s| s.active().map(|r| (r.origin.clone(), r.activated_at_us))) {
            Some((origin, at)) => {
                w.str_field("origin", &origin);
                w.str_field(
                    "activated_at",
                    &ufw_shared::log_types::format_rfc3339_micros(at),
                );
            }
            None => {
                w.null_field("origin");
                w.null_field("activated_at");
            }
        }
        w.end_object();

        w.begin_object_field("identity");
        w.str_field("resolver", self.identity.resolver_name());
        w.u64_field("trust_anchors", self.identity.trust_len() as u64);
        w.u64_field("queries", counters.identity_queries);
        w.u64_field("cache_entries", cache.entries as u64);
        w.u64_field("cache_hits", cache.hits);
        w.u64_field("cache_misses", cache.misses);
        w.f64_field("cache_hit_rate", cache.hit_rate());
        w.end_object();

        w.begin_object_field("logging");
        w.u64_field("received", logs.received);
        w.u64_field("written", logs.written);
        w.u64_field("filtered", logs.filtered);
        w.u64_field("dropped_queue_full", logs.dropped_queue_full);
        w.u64_field("sink_errors", logs.sink_errors);
        w.u64_field("correlations", logs.correlations);
        w.u64_field("anomalies", logs.anomalies);
        w.end_object();

        w.begin_object_field("traffic");
        w.u64_field("flows_seen", stats.flows_seen);
        w.u64_field("flows_allowed", stats.flows_allowed);
        w.u64_field("flows_denied", stats.flows_denied);
        w.u64_field("packets_seen", stats.packets_seen);
        w.u64_field("dpi_scans", stats.dpi_scans);
        w.u64_field("dpi_hits", stats.dpi_hits);
        w.u64_field("conntrack_entries", stats.conntrack_entries);
        w.u64_field("ebpf_fastpath_decisions", stats.ebpf_fastpath_decisions);
        w.u64_field("log_events_dropped", stats.log_events_dropped);
        w.end_object();

        w.end_object();
        w.finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub policy_reloads: u64,
    pub failed_reloads: u64,
    pub identity_queries: u64,
}

/// Convenience for building the identity service from configuration.
pub fn build_identity_service(config: &crate::config::IdentityConfig) -> Arc<IdentityService> {
    let options = crate::identity::ResolverOptions {
        max_hash_bytes: config.max_hash_bytes,
        default_signed_trust: config.default_signed_trust,
        ttl_secs: config.cache_ttl_secs,
    };
    let trust = crate::identity::TrustDatabase::from_entries(&config.trust_anchors);
    Arc::new(IdentityService::new(
        crate::identity::platform_resolver(options.clone()),
        trust,
        options,
        config.cache_capacity,
    ))
}

/// Default trust anchors for the host platform.
///
/// These are the publishers whose signatures the operating system itself
/// depends on. Shipping them means a default-deny policy written against
/// `trust: [system]` works out of the box instead of requiring every operator
/// to rediscover the same three strings.
pub fn platform_trust_anchors() -> Vec<(String, TrustLevel)> {
    #[cfg(target_os = "windows")]
    {
        return vec![
            ("Microsoft Windows".into(), TrustLevel::System),
            ("Microsoft Corporation".into(), TrustLevel::System),
            ("Microsoft Windows Publisher".into(), TrustLevel::System),
        ];
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return vec![
            ("Software Signing".into(), TrustLevel::System),
            (
                "Apple Mac OS Application Signing".into(),
                TrustLevel::System,
            ),
        ];
    }
    #[allow(unreachable_code)]
    {
        // Linux has no platform signer to anchor on; provenance there comes
        // from the package manager, which the resolver handles separately.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LoggingConfig;
    use crate::identity::{ResolverOptions, TrustDatabase};
    use crate::logging::{Enrichment, Logger};
    use ufw_shared::log_types::Severity;
    use ufw_shared::policy_types::{Action, CompiledRule, Decision, Layer};

    fn logging_config() -> LoggingConfig {
        LoggingConfig {
            level: Severity::Debug,
            log_allowed: true,
            file: None,
            syslog: None,
            siem: None,
            stdout: false,
            correlation: false,
            correlation_window_secs: 300,
            correlation_threshold: 3,
            anomaly: false,
            anomaly_learning_secs: 3600,
        }
    }

    fn state() -> (DaemonState, Logger) {
        let logger = Logger::with_sinks(&logging_config(), Enrichment::default(), Vec::new());
        let identity = Arc::new(IdentityService::new(
            Box::new(crate::identity::NullResolver::new(
                ResolverOptions::default(),
            )),
            TrustDatabase::new(),
            ResolverOptions::default(),
            16,
        ));
        let state = DaemonState::new(
            "host-a",
            EnforcementMode::Enforce,
            identity,
            logger.handle(),
        );
        (state, logger)
    }

    fn policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        p.rules
            .push(CompiledRule::new(1, "a", Layer::Packet, Action::Allow));
        p.finalize();
        p
    }

    #[test]
    fn a_new_daemon_starts_in_the_starting_state() {
        let (s, _l) = state();
        assert_eq!(s.health(), Health::Starting);
        assert_eq!(s.active_revision(), 0);
        assert!(!s.is_shutting_down());
    }

    #[test]
    fn connecting_and_losing_the_kernel_moves_health_both_ways() {
        let (s, _l) = state();
        s.set_kernel_connected(
            "/dev/ufw-control".into(),
            "0.1.0".into(),
            "linux".into(),
            Capabilities(Capabilities::DPI),
            0,
        );
        assert_eq!(s.health(), Health::Enforcing);
        assert!(s.kernel().connected);

        s.set_kernel_disconnected(Some("module unloaded".into()));
        // Degraded, not stopped: the daemon is up but nothing is filtering,
        // and that has to be visible.
        assert_eq!(s.health(), Health::Degraded);
        assert_eq!(s.kernel().reconnect_attempts, 1);
        assert_eq!(s.kernel().last_error.as_deref(), Some("module unloaded"));
    }

    #[test]
    fn a_disconnect_during_shutdown_does_not_report_degraded() {
        let (s, _l) = state();
        s.request_shutdown();
        s.set_kernel_disconnected(None);
        assert_eq!(s.health(), Health::Stopping);
    }

    #[test]
    fn policy_state_is_reflected_in_status() {
        let (s, _l) = state();
        s.with_policies(|store| {
            let staged = store
                .stage(policy(), "test.yaml", 1_700_000_000_000_000)
                .unwrap();
            store.commit(staged);
        });
        s.note_reload(true);

        let json = s.status_json();
        let v = ufw_shared::json::parse(&json).expect("status must be valid JSON");
        let p = v.get("policy").unwrap();
        assert_eq!(p.get("revision").unwrap().as_u64(), Some(1));
        assert_eq!(p.get("rules").unwrap().as_u64(), Some(1));
        assert_eq!(p.get("reloads").unwrap().as_u64(), Some(1));
        assert_eq!(p.get("origin").unwrap().as_str(), Some("test.yaml"));
    }

    #[test]
    fn status_is_valid_json_before_anything_has_happened() {
        let (s, _l) = state();
        let json = s.status_json();
        let v = ufw_shared::json::parse(&json).expect("valid JSON from a cold daemon");
        assert_eq!(v.get("health").unwrap().as_str(), Some("starting"));
        assert_eq!(
            v.get("policy").unwrap().get("origin"),
            Some(&ufw_shared::json::Json::Null)
        );
    }

    #[test]
    fn status_carries_kernel_capabilities_and_traffic_counters() {
        let (s, _l) = state();
        s.set_kernel_connected(
            "ep".into(),
            "0.1.0".into(),
            "linux".into(),
            Capabilities(Capabilities::DPI | Capabilities::EBPF_FASTPATH),
            3,
        );
        s.set_kernel_stats(KernelStats {
            flows_seen: 100,
            flows_denied: 7,
            ..Default::default()
        });

        let v = ufw_shared::json::parse(&s.status_json()).unwrap();
        let caps = v.get("kernel").unwrap().get("capabilities").unwrap();
        let names: Vec<&str> = caps
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert!(names.contains(&"dpi"));
        assert!(names.contains(&"ebpf-fastpath"));
        assert_eq!(
            v.get("traffic")
                .unwrap()
                .get("flows_denied")
                .unwrap()
                .as_u64(),
            Some(7)
        );
    }

    #[test]
    fn status_reports_the_watchdog_state() {
        let (s, _l) = state();
        // Cold: nominal, nothing seen.
        let v = ufw_shared::json::parse(&s.status_json()).unwrap();
        let wd = v.get("watchdog").unwrap();
        assert_eq!(wd.get("state").unwrap().as_str(), Some("nominal"));
        assert_eq!(wd.get("total_faults").unwrap().as_u64(), Some(0));

        // After the supervision loop publishes a safe-mode snapshot, status
        // reflects it — the signal a headless server's monitoring watches for.
        s.set_watchdog_report(WatchdogReport {
            state: "safe-mode",
            faults_in_window: 5,
            total_faults: 12,
            safe_mode_entries: 1,
        });
        let v = ufw_shared::json::parse(&s.status_json()).unwrap();
        let wd = v.get("watchdog").unwrap();
        assert_eq!(wd.get("state").unwrap().as_str(), Some("safe-mode"));
        assert_eq!(wd.get("faults_in_window").unwrap().as_u64(), Some(5));
        assert_eq!(wd.get("total_faults").unwrap().as_u64(), Some(12));
        assert_eq!(wd.get("safe_mode_entries").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn shutdown_is_observable_from_every_loop() {
        let (s, _l) = state();
        let s = Arc::new(s);
        let watcher = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let mut ticks = 0;
                while !s.is_shutting_down() && ticks < 1000 {
                    ticks += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                s.is_shutting_down()
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.request_shutdown();
        assert!(watcher.join().unwrap());
    }

    #[test]
    fn refreshing_signatures_bumps_on_change_and_is_a_no_op_otherwise() {
        let (s, _l) = state();
        // Before any load the digest is zero and the revision is 0.
        assert_eq!(s.signature_revision(), 0);

        // The first refresh registers as a change (the empty set's real digest
        // differs from the zero seed) and lands at revision 1.
        assert_eq!(s.refresh_signatures(SignatureSet::default()), Some(1));
        assert_eq!(s.signature_revision(), 1);

        // Reloading a byte-identical set is a genuine no-op: no swap, no bump.
        assert_eq!(s.refresh_signatures(SignatureSet::default()), None);
        assert_eq!(s.signature_revision(), 1);
    }

    #[test]
    fn the_startup_load_seeds_revision_one_and_a_digest() {
        let (s, _l) = state();
        s.set_signatures(SignatureSet::default());
        assert_eq!(s.signature_revision(), 1);
        assert_ne!(s.signature_digest_hex(), "0".repeat(64));
        // A subsequent reload of the same set is then correctly a no-op.
        assert_eq!(s.refresh_signatures(SignatureSet::default()), None);
    }
}
