//! Daemon configuration: a TOML subset parser and the configuration model.
//!
//! The parser accepts tables, dotted table headers, arrays of tables, and
//! scalar values (string, integer, float, boolean, array). It does not accept
//! inline tables, multi-line strings, or datetimes — none of which this
//! configuration needs, and each of which is another way for a config file to
//! parse differently than it reads.
//!
//! Unknown keys are **errors**, not warnings. A typo'd `bind_addres` that
//! silently leaves the management API on its default is exactly the kind of
//! quiet misconfiguration this product exists to prevent elsewhere.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use ufw_shared::constants;
use ufw_shared::identity_types::TrustLevel;
use ufw_shared::log_types::Severity;

// ===========================================================================
// TOML subset
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::String(_) => "string",
            Value::Integer(_) => "integer",
            Value::Float(_) => "float",
            Value::Boolean(_) => "boolean",
            Value::Array(_) => "array",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line > 0 {
            write!(f, "line {}: {}", self.line, self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(line: usize, message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError { line, message: message.into() })
}

/// A parsed document: fully-qualified key (`"logging.file.path"`) to value.
///
/// Flattening rather than nesting keeps lookup and unknown-key detection to
/// one pass each, and the configuration is shallow enough that nothing is lost.
#[derive(Debug, Clone, Default)]
pub struct Toml {
    pub values: BTreeMap<String, (Value, usize)>,
}

impl Toml {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut doc = Toml::default();
        let mut prefix = String::new();

        for (i, raw) in text.lines().enumerate() {
            let line_no = i + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(header) = line.strip_prefix('[') {
                let Some(name) = header.strip_suffix(']') else {
                    return err(line_no, "unterminated table header");
                };
                let name = name.trim();
                if name.is_empty() {
                    return err(line_no, "empty table header");
                }
                if name.starts_with('[') {
                    return err(line_no, "arrays of tables are not supported");
                }
                for part in name.split('.') {
                    if !is_bare_key(part.trim()) {
                        return err(line_no, format!("invalid table name `{name}`"));
                    }
                }
                prefix = name.split('.').map(str::trim).collect::<Vec<_>>().join(".");
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return err(line_no, "expected `key = value`");
            };
            let key = key.trim();
            if !is_bare_key(key) && !(key.starts_with('"') && key.ends_with('"')) {
                return err(line_no, format!("invalid key `{key}`"));
            }
            let key = key.trim_matches('"');
            let full = if prefix.is_empty() {
                key.to_string()
            } else {
                format!("{prefix}.{key}")
            };
            let value = parse_value(value.trim(), line_no)?;
            if let Some((_, first)) = doc.values.get(&full) {
                return err(line_no, format!("`{full}` was already set on line {first}"));
            }
            doc.values.insert(full, (value, line_no));
        }

        Ok(doc)
    }

    fn get(&self, key: &str) -> Option<&(Value, usize)> {
        self.values.get(key)
    }

    pub fn string(&self, key: &str) -> Result<Option<String>, ConfigError> {
        match self.get(key) {
            None => Ok(None),
            Some((Value::String(s), _)) => Ok(Some(s.clone())),
            Some((v, line)) => err(*line, format!("`{key}` must be a string, found {}", v.type_name())),
        }
    }

    pub fn bool(&self, key: &str) -> Result<Option<bool>, ConfigError> {
        match self.get(key) {
            None => Ok(None),
            Some((Value::Boolean(b), _)) => Ok(Some(*b)),
            Some((v, line)) => err(*line, format!("`{key}` must be a boolean, found {}", v.type_name())),
        }
    }

    pub fn integer(&self, key: &str) -> Result<Option<i64>, ConfigError> {
        match self.get(key) {
            None => Ok(None),
            Some((Value::Integer(n), _)) => Ok(Some(*n)),
            Some((v, line)) => err(*line, format!("`{key}` must be an integer, found {}", v.type_name())),
        }
    }

    pub fn u64(&self, key: &str) -> Result<Option<u64>, ConfigError> {
        match self.integer(key)? {
            None => Ok(None),
            Some(n) if n >= 0 => Ok(Some(n as u64)),
            Some(n) => {
                let line = self.get(key).map(|(_, l)| *l).unwrap_or(0);
                err(line, format!("`{key}` must not be negative (found {n})"))
            }
        }
    }

    pub fn string_array(&self, key: &str) -> Result<Vec<String>, ConfigError> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some((Value::Array(items), line)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::String(s) => out.push(s.clone()),
                        other => {
                            return err(
                                *line,
                                format!("`{key}` must be an array of strings, found {}", other.type_name()),
                            )
                        }
                    }
                }
                Ok(out)
            }
            Some((v, line)) => err(*line, format!("`{key}` must be an array, found {}", v.type_name())),
        }
    }

    /// Keys present in the document that are not in `known`.
    pub fn unknown_keys(&self, known: &[&str]) -> Vec<(String, usize)> {
        self.values
            .iter()
            .filter(|(k, _)| !known.contains(&k.as_str()))
            .map(|(k, (_, line))| (k.clone(), *line))
            .collect()
    }
}

fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\\' if in_string => escaped = !escaped,
            b'"' if !escaped => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            _ => escaped = false,
        }
    }
    line
}

fn is_bare_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn parse_value(text: &str, line: usize) -> Result<Value, ConfigError> {
    if text.is_empty() {
        return err(line, "missing value");
    }
    match text.as_bytes()[0] {
        b'"' => parse_string(text, line).map(Value::String),
        b'\'' => {
            let inner = text
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .ok_or_else(|| ConfigError { line, message: "unterminated literal string".into() })?;
            Ok(Value::String(inner.to_string()))
        }
        b'[' => parse_array(text, line),
        _ => {
            if text == "true" {
                return Ok(Value::Boolean(true));
            }
            if text == "false" {
                return Ok(Value::Boolean(false));
            }
            // TOML allows `_` as a digit separator.
            let cleaned = text.replace('_', "");
            if let Ok(n) = cleaned.parse::<i64>() {
                return Ok(Value::Integer(n));
            }
            if let Ok(f) = cleaned.parse::<f64>() {
                return Ok(Value::Float(f));
            }
            err(line, format!("cannot parse `{text}` as a value"))
        }
    }
}

fn parse_string(text: &str, line: usize) -> Result<String, ConfigError> {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' {
        return err(line, "unterminated string");
    }
    let mut out = String::new();
    let mut chars = text[1..].chars();
    loop {
        let Some(c) = chars.next() else {
            return err(line, "unterminated string");
        };
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => return err(line, format!("unknown escape `\\{other}`")),
                None => return err(line, "unterminated escape"),
            },
            c => out.push(c),
        }
    }
    Ok(out)
}

fn parse_array(text: &str, line: usize) -> Result<Value, ConfigError> {
    let inner = text
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| ConfigError { line, message: "unterminated array".into() })?;
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;

    for (i, c) in inner.char_indices() {
        match c {
            '\\' if in_string => escaped = !escaped,
            '"' if !escaped => {
                in_string = !in_string;
                escaped = false;
            }
            '[' if !in_string => depth += 1,
            ']' if !in_string => depth = depth.saturating_sub(1),
            ',' if !in_string && depth == 0 => {
                let piece = inner[start..i].trim();
                if !piece.is_empty() {
                    out.push(parse_value(piece, line)?);
                }
                start = i + 1;
                escaped = false;
            }
            _ => escaped = false,
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() {
        out.push(parse_value(last, line)?);
    }
    Ok(Value::Array(out))
}

// ===========================================================================
// Configuration model
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub policy: PolicyConfig,
    pub ipc: IpcConfig,
    pub identity: IdentityConfig,
    pub logging: LoggingConfig,
    pub api: ApiConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Stable identifier for this host, stamped on every log event. Defaults
    /// to the machine's hostname when the platform can supply one.
    pub host_id: String,
    /// Where the daemon keeps its runtime state.
    pub state_dir: PathBuf,
    /// Enforcement mode at startup.
    pub mode: ufw_shared::protocol::EnforcementMode,
    /// Refuse to start if the kernel module is missing, rather than running
    /// with no enforcement. Default true, because a firewall that silently
    /// isn't one is worse than a firewall that failed loudly.
    pub require_kernel_module: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Directory watched for policy files.
    pub dir: PathBuf,
    /// Files to load, relative to `dir`. Empty means every `*.yaml` in `dir`.
    pub files: Vec<String>,
    /// Directory of DPI signature definitions.
    pub signature_dir: PathBuf,
    /// Reload policy when a watched file changes.
    pub hot_reload: bool,
    /// Interval between filesystem polls, in milliseconds.
    pub watch_interval_ms: u64,
    /// Fail a reload when the new policy produces warnings.
    pub deny_warnings: bool,
    /// Run the cross-platform equivalence check on every reload.
    pub verify_equivalence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcConfig {
    /// Endpoint the kernel module exposes. Empty means the platform default.
    pub endpoint: String,
    pub connect_timeout_ms: u64,
    /// Reconnect automatically if the module goes away.
    pub reconnect: bool,
    pub reconnect_backoff_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityConfig {
    pub cache_ttl_secs: u64,
    pub cache_capacity: usize,
    /// Largest executable that will be hashed. Above this, `sha256` is left
    /// unset and hash-constrained rules cannot match it.
    pub max_hash_bytes: u64,
    /// Trust level assigned to a validly-signed binary whose signer is not in
    /// the trust database.
    pub default_signed_trust: TrustLevel,
    /// Trust anchors: `"signer or team-id or sha256:... = trust-level"`.
    pub trust_anchors: Vec<(String, TrustLevel)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub level: Severity,
    /// Emit an event for permitted flows as well as denied ones.
    pub log_allowed: bool,
    pub file: Option<FileSinkConfig>,
    pub syslog: Option<SyslogSinkConfig>,
    pub siem: Option<SiemSinkConfig>,
    pub stdout: bool,
    /// Enable the cross-host correlation engine.
    pub correlation: bool,
    pub correlation_window_secs: u64,
    pub correlation_threshold: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSinkConfig {
    pub path: PathBuf,
    pub max_bytes: u64,
    pub keep: usize,
    pub format: LogFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogSinkConfig {
    pub address: String,
    pub facility: u8,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiemSinkConfig {
    pub address: String,
    pub format: LogFormat,
    /// Events buffered while the receiver is unreachable. When full, the
    /// oldest are dropped and the drop is itself logged locally: a SIEM
    /// outage must not become a packet-processing stall.
    pub buffer: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Text,
    Cef,
}

impl LogFormat {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "json" | "jsonl" => LogFormat::Json,
            "text" => LogFormat::Text,
            "cef" => LogFormat::Cef,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LogFormat::Json => "json",
            LogFormat::Text => "text",
            LogFormat::Cef => "cef",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// Local control socket for the CLI.
    pub cli_socket: PathBuf,
    /// REST bind address, if enabled.
    pub rest_bind: Option<String>,
    /// gRPC-Web bind address, if enabled.
    pub grpc_bind: Option<String>,
    /// Addresses allowed to reach the network-facing APIs. Empty means
    /// loopback only, which is also the default bind.
    pub allow_from: Vec<IpAddr>,
    /// Bearer token required by the network-facing APIs. Absent means those
    /// APIs refuse to start on a non-loopback address.
    pub auth_token: Option<String>,
    pub max_body_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            daemon: DaemonConfig {
                host_id: default_host_id(),
                state_dir: PathBuf::from(constants::DEFAULT_STATE_DIR_UNIX),
                mode: ufw_shared::protocol::EnforcementMode::Enforce,
                require_kernel_module: true,
            },
            policy: PolicyConfig {
                dir: PathBuf::from(constants::DEFAULT_POLICY_DIR_UNIX),
                files: Vec::new(),
                signature_dir: PathBuf::from(constants::DEFAULT_SIGNATURE_DIR_UNIX),
                hot_reload: true,
                watch_interval_ms: 500,
                deny_warnings: false,
                verify_equivalence: true,
            },
            ipc: IpcConfig {
                endpoint: String::new(),
                connect_timeout_ms: constants::HANDSHAKE_TIMEOUT_MS,
                reconnect: true,
                reconnect_backoff_ms: 1000,
            },
            identity: IdentityConfig {
                cache_ttl_secs: constants::IDENTITY_CACHE_TTL_SECS,
                cache_capacity: constants::IDENTITY_CACHE_CAPACITY,
                max_hash_bytes: 256 * 1024 * 1024,
                default_signed_trust: TrustLevel::Known,
                trust_anchors: Vec::new(),
            },
            logging: LoggingConfig {
                level: Severity::Info,
                log_allowed: true,
                file: Some(FileSinkConfig {
                    path: PathBuf::from(constants::DEFAULT_LOG_PATH_UNIX),
                    max_bytes: 64 * 1024 * 1024,
                    keep: 5,
                    format: LogFormat::Json,
                }),
                syslog: None,
                siem: None,
                stdout: false,
                correlation: true,
                correlation_window_secs: 300,
                correlation_threshold: 3,
            },
            api: ApiConfig {
                cli_socket: PathBuf::from(constants::DEFAULT_CLI_SOCKET_UNIX),
                rest_bind: None,
                grpc_bind: None,
                allow_from: Vec::new(),
                auth_token: None,
                max_body_bytes: constants::MAX_API_BODY,
            },
        }
    }
}

/// Every key the daemon understands. Anything else in a config file is an
/// error, with a suggestion when one is close.
const KNOWN_KEYS: &[&str] = &[
    "daemon.host_id",
    "daemon.state_dir",
    "daemon.mode",
    "daemon.require_kernel_module",
    "policy.dir",
    "policy.files",
    "policy.signature_dir",
    "policy.hot_reload",
    "policy.watch_interval_ms",
    "policy.deny_warnings",
    "policy.verify_equivalence",
    "ipc.endpoint",
    "ipc.connect_timeout_ms",
    "ipc.reconnect",
    "ipc.reconnect_backoff_ms",
    "identity.cache_ttl_secs",
    "identity.cache_capacity",
    "identity.max_hash_bytes",
    "identity.default_signed_trust",
    "identity.trust_anchors",
    "logging.level",
    "logging.log_allowed",
    "logging.stdout",
    "logging.correlation",
    "logging.correlation_window_secs",
    "logging.correlation_threshold",
    "logging.file.enabled",
    "logging.file.path",
    "logging.file.max_bytes",
    "logging.file.keep",
    "logging.file.format",
    "logging.syslog.enabled",
    "logging.syslog.address",
    "logging.syslog.facility",
    "logging.syslog.tag",
    "logging.siem.enabled",
    "logging.siem.address",
    "logging.siem.format",
    "logging.siem.buffer",
    "api.cli_socket",
    "api.rest_bind",
    "api.grpc_bind",
    "api.allow_from",
    "api.auth_token",
    "api.max_body_bytes",
];

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let doc = Toml::parse(text)?;

        let unknown = doc.unknown_keys(KNOWN_KEYS);
        if let Some((key, line)) = unknown.first() {
            let suggestion = closest(key, KNOWN_KEYS)
                .map(|s| format!("; did you mean `{s}`?"))
                .unwrap_or_default();
            return err(*line, format!("unknown configuration key `{key}`{suggestion}"));
        }

        let mut c = Config::default();

        // --- daemon -------------------------------------------------------
        if let Some(v) = doc.string("daemon.host_id")? {
            c.daemon.host_id = v;
        }
        if let Some(v) = doc.string("daemon.state_dir")? {
            c.daemon.state_dir = PathBuf::from(v);
        }
        if let Some(v) = doc.string("daemon.mode")? {
            c.daemon.mode = ufw_shared::protocol::EnforcementMode::parse(&v).ok_or(ConfigError {
                line: 0,
                message: format!("`{v}` is not a mode (enforce, monitor, emergency-allow)"),
            })?;
        }
        if let Some(v) = doc.bool("daemon.require_kernel_module")? {
            c.daemon.require_kernel_module = v;
        }

        // --- policy -------------------------------------------------------
        if let Some(v) = doc.string("policy.dir")? {
            c.policy.dir = PathBuf::from(v);
        }
        c.policy.files = doc.string_array("policy.files")?;
        if let Some(v) = doc.string("policy.signature_dir")? {
            c.policy.signature_dir = PathBuf::from(v);
        }
        if let Some(v) = doc.bool("policy.hot_reload")? {
            c.policy.hot_reload = v;
        }
        if let Some(v) = doc.u64("policy.watch_interval_ms")? {
            // A sub-50ms poll interval burns CPU walking the policy directory
            // for no operational benefit; a reload that lands 50ms later is
            // not a reload anyone notices.
            c.policy.watch_interval_ms = v.max(50);
        }
        if let Some(v) = doc.bool("policy.deny_warnings")? {
            c.policy.deny_warnings = v;
        }
        if let Some(v) = doc.bool("policy.verify_equivalence")? {
            c.policy.verify_equivalence = v;
        }

        // --- ipc ----------------------------------------------------------
        if let Some(v) = doc.string("ipc.endpoint")? {
            c.ipc.endpoint = v;
        }
        if let Some(v) = doc.u64("ipc.connect_timeout_ms")? {
            c.ipc.connect_timeout_ms = v;
        }
        if let Some(v) = doc.bool("ipc.reconnect")? {
            c.ipc.reconnect = v;
        }
        if let Some(v) = doc.u64("ipc.reconnect_backoff_ms")? {
            c.ipc.reconnect_backoff_ms = v.max(100);
        }

        // --- identity -----------------------------------------------------
        if let Some(v) = doc.u64("identity.cache_ttl_secs")? {
            c.identity.cache_ttl_secs = v;
        }
        if let Some(v) = doc.u64("identity.cache_capacity")? {
            c.identity.cache_capacity = v as usize;
        }
        if let Some(v) = doc.u64("identity.max_hash_bytes")? {
            c.identity.max_hash_bytes = v;
        }
        if let Some(v) = doc.string("identity.default_signed_trust")? {
            c.identity.default_signed_trust = TrustLevel::parse(&v).ok_or(ConfigError {
                line: 0,
                message: format!("`{v}` is not a trust level"),
            })?;
        }
        for entry in doc.string_array("identity.trust_anchors")? {
            let (subject, level) = entry.rsplit_once('=').ok_or(ConfigError {
                line: 0,
                message: format!("trust anchor `{entry}` must be written `subject = level`"),
            })?;
            let level = TrustLevel::parse(level.trim()).ok_or(ConfigError {
                line: 0,
                message: format!("`{}` is not a trust level", level.trim()),
            })?;
            c.identity
                .trust_anchors
                .push((subject.trim().to_string(), level));
        }

        // --- logging ------------------------------------------------------
        if let Some(v) = doc.string("logging.level")? {
            c.logging.level = Severity::parse(&v).ok_or(ConfigError {
                line: 0,
                message: format!("`{v}` is not a log level"),
            })?;
        }
        if let Some(v) = doc.bool("logging.log_allowed")? {
            c.logging.log_allowed = v;
        }
        if let Some(v) = doc.bool("logging.stdout")? {
            c.logging.stdout = v;
        }
        if let Some(v) = doc.bool("logging.correlation")? {
            c.logging.correlation = v;
        }
        if let Some(v) = doc.u64("logging.correlation_window_secs")? {
            c.logging.correlation_window_secs = v.max(1);
        }
        if let Some(v) = doc.u64("logging.correlation_threshold")? {
            c.logging.correlation_threshold = (v as usize).max(2);
        }

        if doc.bool("logging.file.enabled")? == Some(false) {
            c.logging.file = None;
        } else if let Some(file) = c.logging.file.as_mut() {
            if let Some(v) = doc.string("logging.file.path")? {
                file.path = PathBuf::from(v);
            }
            if let Some(v) = doc.u64("logging.file.max_bytes")? {
                file.max_bytes = v;
            }
            if let Some(v) = doc.u64("logging.file.keep")? {
                file.keep = v as usize;
            }
            if let Some(v) = doc.string("logging.file.format")? {
                file.format = LogFormat::parse(&v).ok_or(ConfigError {
                    line: 0,
                    message: format!("`{v}` is not a log format (json, text, cef)"),
                })?;
            }
        }

        if doc.bool("logging.syslog.enabled")? == Some(true) {
            c.logging.syslog = Some(SyslogSinkConfig {
                address: doc
                    .string("logging.syslog.address")?
                    .unwrap_or_else(|| "127.0.0.1:514".into()),
                facility: doc.u64("logging.syslog.facility")?.unwrap_or(16) as u8,
                tag: doc
                    .string("logging.syslog.tag")?
                    .unwrap_or_else(|| constants::PRODUCT_NAME.into()),
            });
        }

        if doc.bool("logging.siem.enabled")? == Some(true) {
            let address = doc.string("logging.siem.address")?.ok_or(ConfigError {
                line: 0,
                message: "`logging.siem.address` is required when the SIEM sink is enabled".into(),
            })?;
            c.logging.siem = Some(SiemSinkConfig {
                address,
                format: doc
                    .string("logging.siem.format")?
                    .as_deref()
                    .map(|s| {
                        LogFormat::parse(s).ok_or(ConfigError {
                            line: 0,
                            message: format!("`{s}` is not a log format"),
                        })
                    })
                    .transpose()?
                    .unwrap_or(LogFormat::Json),
                buffer: doc.u64("logging.siem.buffer")?.unwrap_or(10_000) as usize,
            });
        }

        // --- api ----------------------------------------------------------
        if let Some(v) = doc.string("api.cli_socket")? {
            c.api.cli_socket = PathBuf::from(v);
        }
        c.api.rest_bind = doc.string("api.rest_bind")?;
        c.api.grpc_bind = doc.string("api.grpc_bind")?;
        for a in doc.string_array("api.allow_from")? {
            c.api.allow_from.push(a.parse::<IpAddr>().map_err(|_| ConfigError {
                line: 0,
                message: format!("`{a}` is not an IP address"),
            })?);
        }
        c.api.auth_token = doc.string("api.auth_token")?;
        if let Some(v) = doc.u64("api.max_body_bytes")? {
            c.api.max_body_bytes = (v as usize).min(constants::MAX_API_BODY);
        }

        c.validate()?;
        Ok(c)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError {
            line: 0,
            message: format!("cannot read {}: {e}", path.display()),
        })?;
        Config::parse(&text)
    }

    /// Reject configurations that would silently weaken the deployment.
    fn validate(&self) -> Result<(), ConfigError> {
        for (name, bind) in [("rest", &self.api.rest_bind), ("grpc", &self.api.grpc_bind)] {
            let Some(bind) = bind else { continue };
            let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
            let host = host.trim_matches(['[', ']']);
            let is_loopback = host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
            if !is_loopback && self.api.auth_token.is_none() {
                return err(
                    0,
                    format!(
                        "`api.{name}_bind` listens on {bind}, which is not loopback, but no \
                         `api.auth_token` is set; an unauthenticated management plane can \
                         rewrite the firewall policy"
                    ),
                );
            }
        }
        if let Some(token) = &self.api.auth_token {
            if token.len() < 32 {
                return err(
                    0,
                    "`api.auth_token` must be at least 32 characters; it is the only thing \
                     standing between the network and policy write access",
                );
            }
        }
        if self.identity.cache_capacity == 0 {
            return err(0, "`identity.cache_capacity` must be greater than zero");
        }
        Ok(())
    }
}

fn default_host_id() -> String {
    // `hostname` is not in std. Read the conventional files first, then fall
    // back to an environment variable, then to a fixed placeholder that is at
    // least obviously a placeholder in a log line.
    for path in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(s) = std::env::var(var) {
            if !s.is_empty() {
                return s;
            }
        }
    }
    "unknown-host".into()
}

fn closest<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    ufw_policy_lang::error::closest_match(input, candidates.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_configuration() {
        let text = r#"
# Unified Firewall daemon configuration
[daemon]
host_id = "web-01"
state_dir = "/var/lib/ufw"
mode = "monitor"
require_kernel_module = false

[policy]
dir = "/etc/ufw/policies"
files = ["base.yaml", "app.yaml"]
hot_reload = true
watch_interval_ms = 250

[identity]
cache_ttl_secs = 60
default_signed_trust = "trusted"
trust_anchors = ["Contoso Ltd = trusted", "ABCDE12345 = system"]

[logging]
level = "notice"
log_allowed = false

[logging.file]
path = "/var/log/ufw/events.jsonl"
max_bytes = 1048576
keep = 3
format = "cef"

[logging.syslog]
enabled = true
address = "10.0.0.9:514"
facility = 20

[api]
cli_socket = "/run/ufw.sock"
"#;
        let c = Config::parse(text).expect("parses");
        assert_eq!(c.daemon.host_id, "web-01");
        assert_eq!(c.daemon.mode, ufw_shared::protocol::EnforcementMode::Monitor);
        assert!(!c.daemon.require_kernel_module);
        assert_eq!(c.policy.files, vec!["base.yaml", "app.yaml"]);
        assert_eq!(c.policy.watch_interval_ms, 250);
        assert_eq!(c.identity.cache_ttl_secs, 60);
        assert_eq!(c.identity.default_signed_trust, TrustLevel::Trusted);
        assert_eq!(
            c.identity.trust_anchors,
            vec![
                ("Contoso Ltd".to_string(), TrustLevel::Trusted),
                ("ABCDE12345".to_string(), TrustLevel::System),
            ]
        );
        assert_eq!(c.logging.level, Severity::Notice);
        assert!(!c.logging.log_allowed);
        let file = c.logging.file.as_ref().unwrap();
        assert_eq!(file.format, LogFormat::Cef);
        assert_eq!(file.keep, 3);
        let syslog = c.logging.syslog.as_ref().unwrap();
        assert_eq!(syslog.address, "10.0.0.9:514");
        assert_eq!(syslog.facility, 20);
    }

    #[test]
    fn defaults_are_conservative() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.daemon.mode, ufw_shared::protocol::EnforcementMode::Enforce);
        assert!(c.daemon.require_kernel_module);
        assert!(c.policy.verify_equivalence);
        assert!(c.api.rest_bind.is_none());
        assert!(c.api.grpc_bind.is_none());
        assert!(c.api.auth_token.is_none());
    }

    #[test]
    fn unknown_keys_are_errors_with_a_suggestion() {
        let e = Config::parse("[api]\nrest_bindd = \"127.0.0.1:1\"\n").unwrap_err();
        assert!(e.message.contains("unknown configuration key"));
        assert!(e.message.contains("did you mean `api.rest_bind`?"), "{}", e.message);
        assert_eq!(e.line, 2);
    }

    #[test]
    fn a_network_management_api_without_a_token_is_rejected() {
        let e = Config::parse("[api]\nrest_bind = \"0.0.0.0:8443\"\n").unwrap_err();
        assert!(e.message.contains("auth_token"), "{}", e.message);

        // Loopback needs no token.
        assert!(Config::parse("[api]\nrest_bind = \"127.0.0.1:8443\"\n").is_ok());

        // With a strong token, a network bind is fine.
        let ok = Config::parse(
            "[api]\nrest_bind = \"0.0.0.0:8443\"\nauth_token = \"0123456789abcdef0123456789abcdef\"\n",
        );
        assert!(ok.is_ok(), "{:?}", ok.err());
    }

    #[test]
    fn short_tokens_are_rejected() {
        let e = Config::parse("[api]\nauth_token = \"hunter2\"\n").unwrap_err();
        assert!(e.message.contains("at least 32 characters"));
    }

    #[test]
    fn type_errors_name_the_key_and_the_line() {
        let e = Config::parse("[policy]\nhot_reload = \"yes\"\n").unwrap_err();
        assert!(e.message.contains("policy.hot_reload"));
        assert!(e.message.contains("boolean"));
        assert_eq!(e.line, 2);
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let e = Config::parse("[daemon]\nhost_id = \"a\"\nhost_id = \"b\"\n").unwrap_err();
        assert!(e.message.contains("already set on line 2"));
    }

    #[test]
    fn comments_and_quoting_do_not_confuse_the_parser() {
        let c = Config::parse(
            "[daemon]\nhost_id = \"a#b\"  # trailing comment\n# whole-line comment\n",
        )
        .unwrap();
        assert_eq!(c.daemon.host_id, "a#b");
    }

    #[test]
    fn arrays_parse_with_and_without_trailing_commas() {
        let doc = Toml::parse("a = [\"x\", \"y\",]\nb = []\nc = [1, 2, 3]\n").unwrap();
        assert_eq!(doc.string_array("a").unwrap(), vec!["x", "y"]);
        assert!(doc.string_array("b").unwrap().is_empty());
        assert!(doc.string_array("c").is_err());
    }

    #[test]
    fn escapes_are_handled_in_strings() {
        let doc = Toml::parse(r#"a = "line\nnext\t\"quoted\"""#).unwrap();
        assert_eq!(doc.string("a").unwrap().unwrap(), "line\nnext\t\"quoted\"");
    }

    #[test]
    fn literal_strings_do_not_interpret_escapes() {
        let doc = Toml::parse(r"a = 'C:\Users\x'").unwrap();
        assert_eq!(doc.string("a").unwrap().unwrap(), r"C:\Users\x");
    }

    #[test]
    fn malformed_input_is_reported_not_ignored() {
        for (src, needle) in [
            ("[unterminated\n", "unterminated table header"),
            ("no_equals_here\n", "expected `key = value`"),
            ("[a]\nk = \n", "missing value"),
            ("[a]\nk = notavalue\n", "cannot parse"),
            ("[a]\nk = \"unterminated\n", "unterminated string"),
            ("[]\n", "empty table header"),
        ] {
            let e = Toml::parse(src).unwrap_err();
            assert!(
                e.message.contains(needle),
                "for {src:?} expected {needle:?}, got {:?}",
                e.message
            );
        }
    }

    #[test]
    fn poll_interval_has_a_floor() {
        let c = Config::parse("[policy]\nwatch_interval_ms = 1\n").unwrap();
        assert_eq!(c.policy.watch_interval_ms, 50);
    }

    #[test]
    fn disabling_the_file_sink_removes_it() {
        let c = Config::parse("[logging.file]\nenabled = false\n").unwrap();
        assert!(c.logging.file.is_none());
    }

    #[test]
    fn siem_sink_requires_an_address() {
        let e = Config::parse("[logging.siem]\nenabled = true\n").unwrap_err();
        assert!(e.message.contains("address"));
    }
}
