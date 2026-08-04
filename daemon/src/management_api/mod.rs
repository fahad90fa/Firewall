//! The management interface.
//!
//! Three surfaces — a local CLI socket, a REST API and a gRPC-Web API — all
//! dispatch through the single [`Router`] below. That is the point: an
//! operation available over one surface behaves identically over the others,
//! and adding an operation cannot accidentally expose it on one surface with
//! different semantics.
//!
//! # Authority is per-surface, not per-operation
//!
//! The local socket is filesystem-permission-protected and gets full
//! authority. The network surfaces get authority only when a bearer token is
//! configured, and the configuration layer refuses to bind them to a
//! non-loopback address without one. So the router takes an [`Authority`] and
//! each operation declares the minimum it needs, rather than every surface
//! re-deriving the rules.

pub mod cli;
pub mod grpc;
pub mod rest;

use std::sync::Arc;

use ufw_shared::json::{self, Json, JsonWriter};
use ufw_shared::protocol::EnforcementMode;

use crate::state::DaemonState;

/// What a caller is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    /// Status and rule listing.
    ReadOnly,
    /// Everything, including policy replacement and emergency mode.
    Admin,
}

/// A management operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Daemon status.
    Status,
    /// Installed rules, optionally filtered by a substring of the rule name or
    /// a tag.
    ListRules { filter: Option<String> },
    /// One rule by name or numeric id.
    GetRule { key: String },
    /// Retained policy revisions.
    ListRevisions,
    /// Recompile from disk and install.
    ReloadPolicy,
    /// Validate the on-disk policy without installing it.
    ValidatePolicy,
    /// Diff the on-disk policy against what is installed.
    DiffPolicy,
    /// Roll back to a retained revision.
    Rollback { revision: u64 },
    /// Remove every rule, leaving the default action.
    FlushPolicy,
    /// Change enforcement mode.
    SetMode { mode: EnforcementMode },
    /// Kernel counters.
    Stats,
    /// Resolve an application identity for a pid.
    ResolveIdentity { pid: u32 },
    /// Trust database contents.
    ListTrust,
    /// Loaded DPI signatures, and any the policy names but nobody defines.
    ListSignatures,
    /// Ask the daemon to exit.
    Shutdown,
    /// Liveness probe.
    Ping,
}

impl Request {
    /// The minimum authority this operation requires.
    pub fn required_authority(&self) -> Authority {
        match self {
            Request::Status
            | Request::ListRules { .. }
            | Request::GetRule { .. }
            | Request::ListRevisions
            | Request::ValidatePolicy
            | Request::DiffPolicy
            | Request::Stats
            | Request::ListTrust
            | Request::ListSignatures
            | Request::Ping => Authority::ReadOnly,

            Request::ReloadPolicy
            | Request::Rollback { .. }
            | Request::FlushPolicy
            | Request::SetMode { .. }
            | Request::ResolveIdentity { .. }
            | Request::Shutdown => Authority::Admin,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::ListRules { .. } => "list-rules",
            Request::GetRule { .. } => "get-rule",
            Request::ListRevisions => "list-revisions",
            Request::ReloadPolicy => "reload-policy",
            Request::ValidatePolicy => "validate-policy",
            Request::DiffPolicy => "diff-policy",
            Request::Rollback { .. } => "rollback",
            Request::FlushPolicy => "flush-policy",
            Request::SetMode { .. } => "set-mode",
            Request::Stats => "stats",
            Request::ResolveIdentity { .. } => "resolve-identity",
            Request::ListTrust => "list-trust",
            Request::ListSignatures => "list-signatures",
            Request::Shutdown => "shutdown",
            Request::Ping => "ping",
        }
    }

    /// Parse the wire form used by the CLI socket and gRPC-Web.
    pub fn from_json(value: &Json) -> Result<Self, ApiError> {
        let op = value
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::bad_request("missing `op`"))?;
        let arg = |k: &str| value.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let num = |k: &str| value.get(k).and_then(|v| v.as_u64());

        Ok(match op {
            "status" => Request::Status,
            "list-rules" => Request::ListRules { filter: arg("filter") },
            "get-rule" => Request::GetRule {
                key: arg("key").ok_or_else(|| ApiError::bad_request("missing `key`"))?,
            },
            "list-revisions" => Request::ListRevisions,
            "reload-policy" => Request::ReloadPolicy,
            "validate-policy" => Request::ValidatePolicy,
            "diff-policy" => Request::DiffPolicy,
            "rollback" => Request::Rollback {
                revision: num("revision")
                    .ok_or_else(|| ApiError::bad_request("missing `revision`"))?,
            },
            "flush-policy" => Request::FlushPolicy,
            "set-mode" => {
                let text = arg("mode").ok_or_else(|| ApiError::bad_request("missing `mode`"))?;
                Request::SetMode {
                    mode: EnforcementMode::parse(&text).ok_or_else(|| {
                        ApiError::bad_request(format!("`{text}` is not an enforcement mode"))
                    })?,
                }
            }
            "stats" => Request::Stats,
            "resolve-identity" => Request::ResolveIdentity {
                pid: num("pid").ok_or_else(|| ApiError::bad_request("missing `pid`"))? as u32,
            },
            "list-trust" => Request::ListTrust,
            "list-signatures" => Request::ListSignatures,
            "shutdown" => Request::Shutdown,
            "ping" => Request::Ping,
            other => return Err(ApiError::not_found(format!("unknown operation `{other}`"))),
        })
    }
}

/// A failed operation, with an HTTP-compatible status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError { status: 400, message: message.into() }
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        ApiError { status: 401, message: message.into() }
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        ApiError { status: 403, message: message.into() }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        ApiError { status: 404, message: message.into() }
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        ApiError { status: 409, message: message.into() }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        ApiError { status: 500, message: message.into() }
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        ApiError { status: 503, message: message.into() }
    }

    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", false);
        w.u64_field("status", self.status as u64);
        w.str_field("error", &self.message);
        w.end_object();
        w.finish()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.status)
    }
}

/// A successful response body, already serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn ok(body: String) -> Self {
        Response { status: 200, body }
    }
}

/// Actions the router cannot perform itself because they need the IPC channel
/// or the policy loader, which the supervisor owns.
///
/// The router returns one of these instead of reaching across into the
/// supervisor's state, which keeps every lock inside the router short and
/// non-reentrant.
pub trait ControlPlane: Send + Sync {
    fn reload_policy(&self) -> Result<String, ApiError>;
    fn validate_policy(&self) -> Result<String, ApiError>;
    fn diff_policy(&self) -> Result<String, ApiError>;
    fn rollback(&self, revision: u64) -> Result<String, ApiError>;
    fn flush_policy(&self) -> Result<String, ApiError>;
    fn set_mode(&self, mode: EnforcementMode) -> Result<String, ApiError>;
    fn refresh_stats(&self) -> Result<(), ApiError>;
}

/// Dispatches requests against daemon state.
pub struct Router {
    state: Arc<DaemonState>,
    control: Arc<dyn ControlPlane>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish()
    }
}

impl Router {
    pub fn new(state: Arc<DaemonState>, control: Arc<dyn ControlPlane>) -> Self {
        Router { state, control }
    }

    pub fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    pub fn dispatch(&self, request: Request, authority: Authority) -> Result<Response, ApiError> {
        if authority < request.required_authority() {
            return Err(ApiError::forbidden(format!(
                "`{}` requires administrative authority",
                request.name()
            )));
        }

        match request {
            Request::Ping => Ok(Response::ok(simple("pong"))),
            Request::Status => Ok(Response::ok(self.state.status_json())),
            Request::Stats => {
                self.control.refresh_stats()?;
                Ok(Response::ok(self.stats_json()))
            }
            Request::ListRules { filter } => Ok(Response::ok(self.rules_json(filter.as_deref()))),
            Request::GetRule { key } => self.rule_json(&key).map(Response::ok),
            Request::ListRevisions => Ok(Response::ok(self.revisions_json())),
            Request::ListTrust => Ok(Response::ok(self.trust_json())),
            Request::ListSignatures => Ok(Response::ok(self.signatures_json())),
            Request::ResolveIdentity { pid } => Ok(Response::ok(self.identity_json(pid))),
            Request::ReloadPolicy => self.control.reload_policy().map(Response::ok),
            Request::ValidatePolicy => self.control.validate_policy().map(Response::ok),
            Request::DiffPolicy => self.control.diff_policy().map(Response::ok),
            Request::Rollback { revision } => self.control.rollback(revision).map(Response::ok),
            Request::FlushPolicy => self.control.flush_policy().map(Response::ok),
            Request::SetMode { mode } => self.control.set_mode(mode).map(Response::ok),
            Request::Shutdown => {
                self.state.request_shutdown();
                Ok(Response::ok(simple("shutting down")))
            }
        }
    }

    /// The loaded signature set, plus the references the active policy makes
    /// that nothing defines. The dangling list is the part worth reading: a
    /// DPI rule naming a signature nobody shipped installs cleanly and never
    /// fires, so nothing else in the system would ever complain about it.
    fn signatures_json(&self) -> String {
        let set = self.state.signatures();
        let dangling = self.state.dangling_signature_refs();

        let mut w = JsonWriter::with_capacity(4096);
        w.begin_object();
        w.bool_field("ok", true);
        w.u64_field("count", set.len() as u64);
        w.begin_array_field("signatures");
        for sig in set.signatures.values() {
            sig.write_json(&mut w);
        }
        w.end_array();
        // Ids rather than names, because by definition there is no name to
        // report: nothing defines them. `ufwctl` cross-references these
        // against the policy's own rule list to say which rule is affected.
        w.begin_array_field("dangling_references");
        for id in &dangling {
            w.u64_element(*id as u64);
        }
        w.end_array();
        w.bool_field("complete", dangling.is_empty());
        w.end_object();
        w.finish()
    }

    fn rules_json(&self, filter: Option<&str>) -> String {
        let policy = self.state.active_policy();
        let mut w = JsonWriter::with_capacity(4096);
        w.begin_object();
        w.bool_field("ok", true);
        w.u64_field("revision", self.state.active_revision());
        w.begin_array_field("rules");
        if let Some(policy) = &policy {
            for rule in &policy.rules {
                let keep = match filter {
                    None => true,
                    Some(f) => {
                        rule.name.contains(f)
                            || rule.tags.iter().any(|t| t == f)
                            || rule.id.to_string() == f
                    }
                };
                if keep {
                    rule.write_json(&mut w);
                }
            }
        }
        w.end_array();
        w.end_object();
        w.finish()
    }

    fn rule_json(&self, key: &str) -> Result<String, ApiError> {
        let policy = self
            .state
            .active_policy()
            .ok_or_else(|| ApiError::unavailable("no policy is installed"))?;
        let rule = policy
            .rules
            .iter()
            .find(|r| r.name == key || r.id.to_string() == key)
            .ok_or_else(|| ApiError::not_found(format!("no rule `{key}`")))?;

        // `write_json` emits a complete object, so it is rendered separately
        // and spliced in as an already-serialized value.
        let mut inner = JsonWriter::new();
        rule.write_json(&mut inner);

        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.raw_field("rule", &inner.finish());
        w.end_object();
        Ok(w.finish())
    }

    fn revisions_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.begin_array_field("revisions");
        self.state.with_policies(|store| {
            let mut emit = |r: &crate::policy_store::PolicyRevision, active: bool| {
                w.begin_object();
                w.u64_field("revision", r.revision());
                w.str_field("name", &r.policy.name);
                w.u64_field("rules", r.policy.rules.len() as u64);
                w.str_field("origin", &r.origin);
                w.str_field(
                    "activated_at",
                    &ufw_shared::log_types::format_rfc3339_micros(r.activated_at_us),
                );
                w.str_field(
                    "ruleset_sha256",
                    &ufw_shared::hash::hex(&r.policy.ruleset_hash),
                );
                w.bool_field("active", active);
                w.end_object();
            };
            if let Some(active) = store.active() {
                emit(active, true);
            }
            for r in store.history() {
                emit(r, false);
            }
        });
        w.end_array();
        w.end_object();
        w.finish()
    }

    fn trust_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.str_field("resolver", self.state.identity.resolver_name());
        w.u64_field("anchors", self.state.identity.trust_len() as u64);
        let cache = self.state.identity.cache_stats();
        w.begin_object_field("cache");
        w.u64_field("entries", cache.entries as u64);
        w.u64_field("capacity", cache.capacity as u64);
        w.u64_field("hits", cache.hits);
        w.u64_field("misses", cache.misses);
        w.u64_field("evictions", cache.evictions);
        w.f64_field("hit_rate", cache.hit_rate());
        w.end_object();
        w.end_object();
        w.finish()
    }

    fn identity_json(&self, pid: u32) -> String {
        let query = ufw_shared::identity_types::IdentityQuery {
            pid,
            start_time_us: 0,
            hint_path: None,
            platform_token: Vec::new(),
        };
        let identity = self.state.identity.answer(&query);
        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.begin_object_field("identity");
        identity.write_json(&mut w);
        w.end_object();
        w.end_object();
        w.finish()
    }

    fn stats_json(&self) -> String {
        let stats = self.state.kernel_stats();
        let mut w = JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        for (name, value) in [
            ("packets_seen", stats.packets_seen),
            ("packets_allowed", stats.packets_allowed),
            ("packets_denied", stats.packets_denied),
            ("flows_seen", stats.flows_seen),
            ("flows_allowed", stats.flows_allowed),
            ("flows_denied", stats.flows_denied),
            ("identity_cache_hits", stats.identity_cache_hits),
            ("identity_cache_misses", stats.identity_cache_misses),
            ("identity_queries_timed_out", stats.identity_queries_timed_out),
            ("dpi_scans", stats.dpi_scans),
            ("dpi_hits", stats.dpi_hits),
            ("reassembly_contexts", stats.reassembly_contexts),
            ("reassembly_truncated", stats.reassembly_truncated),
            ("conntrack_entries", stats.conntrack_entries),
            ("log_events_dropped", stats.log_events_dropped),
            ("ebpf_fastpath_decisions", stats.ebpf_fastpath_decisions),
        ] {
            w.u64_field(name, value);
        }
        let policy = self.state.active_policy();
        w.begin_array_field("rule_hits");
        for (id, hits) in &stats.rule_hits {
            w.begin_object();
            w.u64_field("rule_id", *id as u64);
            let name = policy
                .as_ref()
                .and_then(|p| p.find(*id))
                .map(|r| r.name.as_str())
                .unwrap_or("<unknown>");
            w.str_field("rule", name);
            w.u64_field("hits", *hits);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        w.finish()
    }
}

/// A one-field success body.
pub fn simple(message: &str) -> String {
    let mut w = JsonWriter::new();
    w.begin_object();
    w.bool_field("ok", true);
    w.str_field("message", message);
    w.end_object();
    w.finish()
}

/// Parse a JSON request body.
pub fn parse_body(body: &str) -> Result<Request, ApiError> {
    let value = json::parse(body).map_err(|e| ApiError::bad_request(e.to_string()))?;
    Request::from_json(&value)
}

/// Constant-time-ish comparison for bearer tokens.
///
/// Not truly constant time — that needs care the standard library does not
/// offer — but it does not return early on the first differing byte, which
/// removes the trivially exploitable timing signal.
pub fn token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(provided.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// A control plane that records what it was asked to do.
    #[derive(Debug, Default)]
    pub struct RecordingControl {
        pub calls: Mutex<Vec<String>>,
        pub fail: Mutex<Option<ApiError>>,
    }

    impl RecordingControl {
        fn record(&self, name: &str) -> Result<String, ApiError> {
            self.calls.lock().unwrap().push(name.to_string());
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(simple(name))
        }

        pub fn called(&self, name: &str) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c == name)
        }
    }

    impl ControlPlane for RecordingControl {
        fn reload_policy(&self) -> Result<String, ApiError> {
            self.record("reload")
        }
        fn validate_policy(&self) -> Result<String, ApiError> {
            self.record("validate")
        }
        fn diff_policy(&self) -> Result<String, ApiError> {
            self.record("diff")
        }
        fn rollback(&self, revision: u64) -> Result<String, ApiError> {
            self.record(&format!("rollback:{revision}"))
        }
        fn flush_policy(&self) -> Result<String, ApiError> {
            self.record("flush")
        }
        fn set_mode(&self, mode: EnforcementMode) -> Result<String, ApiError> {
            self.record(&format!("set-mode:{}", mode.as_str()))
        }
        fn refresh_stats(&self) -> Result<(), ApiError> {
            self.record("stats").map(|_| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::RecordingControl;
    use super::*;
    use crate::config::LoggingConfig;
    use crate::identity::{IdentityService, NullResolver, ResolverOptions, TrustDatabase};
    use crate::logging::{Enrichment, Logger};
    use ufw_shared::log_types::Severity;
    use ufw_shared::policy_types::{Action, CompiledPolicy, CompiledRule, Decision, Layer};

    pub(crate) struct Harness {
        pub router: Router,
        pub control: Arc<RecordingControl>,
        pub state: Arc<DaemonState>,
        _logger: Logger,
    }

    pub(crate) fn harness() -> Harness {
        let logging = LoggingConfig {
            level: Severity::Debug,
            log_allowed: true,
            file: None,
            syslog: None,
            siem: None,
            stdout: false,
            correlation: false,
            correlation_window_secs: 300,
            correlation_threshold: 3,
        };
        let logger = Logger::with_sinks(&logging, Enrichment::default(), Vec::new());
        let identity = Arc::new(IdentityService::new(
            Box::new(NullResolver::new(ResolverOptions::default())),
            TrustDatabase::new(),
            ResolverOptions::default(),
            16,
        ));
        let state = Arc::new(DaemonState::new(
            "host-a",
            EnforcementMode::Enforce,
            identity,
            logger.handle(),
        ));

        let mut policy = CompiledPolicy::new("test", Decision::Deny);
        let mut rule = CompiledRule::new(101, "allow-dns", Layer::Packet, Action::Allow);
        rule.tags = vec!["baseline".into()];
        policy.rules.push(rule);
        policy
            .rules
            .push(CompiledRule::new(202, "block-telnet", Layer::Packet, Action::Deny));
        policy.finalize();
        state.with_policies(|s| {
            let staged = s.stage(policy, "test.yaml", 1).unwrap();
            s.commit(staged);
        });

        let control = Arc::new(RecordingControl::default());
        let router = Router::new(Arc::clone(&state), control.clone());
        Harness { router, control, state, _logger: logger }
    }

    #[test]
    fn read_only_callers_cannot_change_anything() {
        let h = harness();
        for request in [
            Request::ReloadPolicy,
            Request::FlushPolicy,
            Request::Rollback { revision: 1 },
            Request::SetMode { mode: EnforcementMode::EmergencyAllow },
            Request::Shutdown,
        ] {
            let err = h
                .router
                .dispatch(request.clone(), Authority::ReadOnly)
                .unwrap_err();
            assert_eq!(err.status, 403, "{} should be admin-only", request.name());
        }
        assert!(
            h.control.calls.lock().unwrap().is_empty(),
            "a rejected request must not reach the control plane"
        );
    }

    #[test]
    fn read_only_callers_can_still_observe() {
        let h = harness();
        for request in [
            Request::Status,
            Request::ListRules { filter: None },
            Request::ListRevisions,
            Request::Stats,
            Request::Ping,
        ] {
            let response = h
                .router
                .dispatch(request.clone(), Authority::ReadOnly)
                .unwrap_or_else(|e| panic!("{} rejected: {e}", request.name()));
            assert_eq!(response.status, 200);
            assert!(json::parse(&response.body).is_ok());
        }
    }

    #[test]
    fn admin_requests_reach_the_control_plane() {
        let h = harness();
        h.router.dispatch(Request::ReloadPolicy, Authority::Admin).unwrap();
        h.router
            .dispatch(Request::Rollback { revision: 3 }, Authority::Admin)
            .unwrap();
        h.router
            .dispatch(
                Request::SetMode { mode: EnforcementMode::Monitor },
                Authority::Admin,
            )
            .unwrap();
        assert!(h.control.called("reload"));
        assert!(h.control.called("rollback:3"));
        assert!(h.control.called("set-mode:monitor"));
    }

    #[test]
    fn rules_can_be_filtered_by_name_id_or_tag() {
        let h = harness();
        let all = h
            .router
            .dispatch(Request::ListRules { filter: None }, Authority::ReadOnly)
            .unwrap();
        let v = json::parse(&all.body).unwrap();
        assert_eq!(v.get("rules").unwrap().as_array().unwrap().len(), 2);

        for filter in ["dns", "baseline", "101"] {
            let filtered = h
                .router
                .dispatch(
                    Request::ListRules { filter: Some(filter.into()) },
                    Authority::ReadOnly,
                )
                .unwrap();
            let v = json::parse(&filtered.body).unwrap();
            let rules = v.get("rules").unwrap().as_array().unwrap();
            assert_eq!(rules.len(), 1, "filter `{filter}` matched {} rules", rules.len());
            assert_eq!(rules[0].get("name").unwrap().as_str(), Some("allow-dns"));
        }
    }

    #[test]
    fn an_unknown_rule_is_a_404() {
        let h = harness();
        let err = h
            .router
            .dispatch(Request::GetRule { key: "nope".into() }, Authority::ReadOnly)
            .unwrap_err();
        assert_eq!(err.status, 404);
    }

    #[test]
    fn revisions_include_the_active_one_flagged() {
        let h = harness();
        let response = h
            .router
            .dispatch(Request::ListRevisions, Authority::ReadOnly)
            .unwrap();
        let v = json::parse(&response.body).unwrap();
        let revisions = v.get("revisions").unwrap().as_array().unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].get("active").unwrap().as_bool(), Some(true));
        assert_eq!(revisions[0].get("origin").unwrap().as_str(), Some("test.yaml"));
    }

    #[test]
    fn shutdown_is_recorded_on_the_daemon_state() {
        let h = harness();
        assert!(!h.state.is_shutting_down());
        h.router.dispatch(Request::Shutdown, Authority::Admin).unwrap();
        assert!(h.state.is_shutting_down());
    }

    #[test]
    fn control_plane_failures_surface_with_their_status() {
        let h = harness();
        *h.control.fail.lock().unwrap() = Some(ApiError::conflict("policy is being reloaded"));
        let err = h
            .router
            .dispatch(Request::ReloadPolicy, Authority::Admin)
            .unwrap_err();
        assert_eq!(err.status, 409);
        assert!(err.to_json().contains("being reloaded"));
    }

    #[test]
    fn request_parsing_covers_every_operation() {
        let cases = [
            (r#"{"op":"status"}"#, Request::Status),
            (
                r#"{"op":"list-rules","filter":"dns"}"#,
                Request::ListRules { filter: Some("dns".into()) },
            ),
            (r#"{"op":"get-rule","key":"a"}"#, Request::GetRule { key: "a".into() }),
            (r#"{"op":"rollback","revision":4}"#, Request::Rollback { revision: 4 }),
            (
                r#"{"op":"set-mode","mode":"monitor"}"#,
                Request::SetMode { mode: EnforcementMode::Monitor },
            ),
            (
                r#"{"op":"resolve-identity","pid":42}"#,
                Request::ResolveIdentity { pid: 42 },
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(parse_body(body).unwrap(), expected, "for {body}");
        }
    }

    #[test]
    fn malformed_requests_are_rejected_with_a_reason() {
        for (body, status) in [
            ("not json", 400),
            (r#"{"nope":1}"#, 400),
            (r#"{"op":"rollback"}"#, 400),
            (r#"{"op":"set-mode","mode":"sideways"}"#, 400),
            (r#"{"op":"teleport"}"#, 404),
        ] {
            let err = parse_body(body).unwrap_err();
            assert_eq!(err.status, status, "for {body}");
        }
    }

    #[test]
    fn token_comparison_rejects_wrong_lengths_and_wrong_bytes() {
        assert!(token_matches("abcdef", "abcdef"));
        assert!(!token_matches("abcdef", "abcdeg"));
        assert!(!token_matches("abcdef", "abcde"));
        assert!(!token_matches("", "x"));
    }
}
