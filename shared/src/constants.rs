//! Magic numbers, version strings, limits and well-known endpoint names.
//!
//! Every constant in this file that crosses the kernel/user boundary has a
//! mirror in `kernel/windows/inc/ipc_ioctl.h`, `kernel/linux/inc/policy_structs.h`
//! and `kernel/macos/NetworkExtension/IPCBridge.swift`. Changing one without
//! changing the others is an ABI break; `UFW_ABI_REVISION` exists to make that
//! break loud instead of silent.

// ---------------------------------------------------------------------------
// Identity of the build
// ---------------------------------------------------------------------------

/// Semantic version of the whole distribution (workspace version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ABI revision of the kernel/user shared structures. Reported in `Hello`
/// and rejected by the peer on mismatch.
///
/// 2: a content condition carries its automaton pattern id, the signature
/// payload gained a trailing multi-pattern table, and `SignatureInstall`
/// exists as a message type. A revision-1 module decoding a revision-2
/// signature payload would read the pattern id as the pattern length.
pub const ABI_REVISION: u32 = 2;

/// Product name used in logs, syslog tags and User-Agent strings.
pub const PRODUCT_NAME: &str = "unified-firewall";

// ---------------------------------------------------------------------------
// Wire framing
// ---------------------------------------------------------------------------

/// Framing magic, little-endian on the wire: `b"UFW\x01"`.
pub const PROTOCOL_MAGIC: u32 = 0x0157_4655;

/// IPC protocol version. Incremented on any incompatible message change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Version tag embedded in a serialized [`crate::policy_types::CompiledPolicy`].
pub const POLICY_WIRE_VERSION: u16 = 1;

/// Length of the fixed message header in bytes.
pub const HEADER_LEN: usize = 16;

/// Largest payload the daemon will emit or accept in a single IPC message.
/// Policies larger than this are split into `PolicyUpdate` batches.
pub const MAX_MESSAGE_PAYLOAD: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Policy limits
//
// These bound the kernel-side allocations. The compiler enforces them so a
// policy that cannot possibly be installed fails at compile time with a source
// span rather than at install time with an opaque errno.
// ---------------------------------------------------------------------------

/// Maximum number of rules in a single compiled policy.
pub const MAX_RULES: usize = 65_536;

/// Maximum length of a rule identifier.
pub const MAX_RULE_NAME_LEN: usize = 64;

/// Maximum CIDR entries on one side of one rule.
pub const MAX_CIDRS_PER_RULE: usize = 256;

/// Maximum port ranges on one side of one rule.
pub const MAX_PORT_RANGES_PER_RULE: usize = 64;

/// Maximum application patterns (paths + hashes + signers) per rule.
pub const MAX_APP_PATTERNS_PER_RULE: usize = 64;

/// Maximum DPI signature references per rule.
pub const MAX_SIGNATURES_PER_RULE: usize = 256;

/// Ceiling on one signature-install payload.
///
/// The set itself is bounded by the module's own limits (1024 signatures, and
/// an automaton of at most 16384 states), and 4 MiB is comfortably above what
/// those produce. The bound exists so a malformed length prefix cannot make a
/// kernel module try to allocate whatever a `u32` can express.
pub const MAX_SIGNATURE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum length of any single string field on the wire.
pub const MAX_STRING_LEN: usize = 4096;

/// Rule priority bounds. Lower numeric priority is evaluated first.
pub const MIN_PRIORITY: u16 = 0;
pub const MAX_PRIORITY: u16 = 65_535;

/// Priority assigned to a rule that does not declare one.
pub const DEFAULT_PRIORITY: u16 = 1000;

// ---------------------------------------------------------------------------
// Runtime caches
// ---------------------------------------------------------------------------

/// Default time-to-live for a resolved application identity, in seconds.
///
/// Identity is keyed by (pid, path, inode-generation) so the TTL is a bound on
/// how long a *revocation* takes to become visible, not a correctness window
/// for PID reuse.
pub const IDENTITY_CACHE_TTL_SECS: u64 = 300;

/// Number of identities the daemon keeps resolved in memory.
pub const IDENTITY_CACHE_CAPACITY: usize = 4096;

/// Number of identities the kernel module keeps (much smaller: kernel memory).
pub const KERNEL_IDENTITY_CACHE_CAPACITY: usize = 1024;

/// Connection tracking table capacity (entries), shared between the eBPF
/// conntrack map and the daemon's mirror.
pub const CONNTRACK_CAPACITY: usize = 262_144;

/// Idle timeout before an established TCP conntrack entry is reaped.
pub const CONNTRACK_TCP_IDLE_SECS: u64 = 3600;

/// Idle timeout for UDP pseudo-connections.
pub const CONNTRACK_UDP_IDLE_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Stream reassembly / DPI
// ---------------------------------------------------------------------------

/// Maximum bytes buffered per connection for reassembly before the engine
/// gives up and lets the flow through uninspected (recording a `TruncatedScan`
/// annotation on the log event).
pub const STREAM_REASSEMBLY_MAX_BYTES: usize = 256 * 1024;

/// Maximum out-of-order holes tracked per direction per connection.
pub const STREAM_REASSEMBLY_MAX_GAPS: usize = 32;

/// macOS Network Extensions run inside a memory-constrained sandbox, so the
/// reassembly budget there is deliberately an order of magnitude smaller.
pub const STREAM_REASSEMBLY_MAX_BYTES_MACOS: usize = 32 * 1024;

/// How long a reassembly context lives without progress before being freed.
pub const STREAM_REASSEMBLY_IDLE_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Verdict timing
// ---------------------------------------------------------------------------

/// The macOS `NEFilterDataProvider` must answer `handleNewFlow` before the
/// system's own timeout or the flow is dropped. We answer well inside it.
pub const FLOW_VERDICT_BUDGET_MS: u64 = 250;

/// How long the kernel module waits for the daemon to answer an identity
/// query before falling back to the unresolved-identity policy path.
pub const IDENTITY_QUERY_TIMEOUT_MS: u64 = 100;

/// Handshake timeout when the daemon first connects to the kernel module.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Entries in the kernel -> daemon log ring buffer.
pub const LOG_RING_CAPACITY: usize = 8192;

/// Maximum events coalesced into one `LogEventBatch` message.
pub const LOG_BATCH_MAX_EVENTS: usize = 256;

/// How long the daemon waits to fill a batch before flushing a partial one.
pub const LOG_BATCH_LINGER_MS: u64 = 50;

/// Schema version stamped on every emitted log event.
pub const LOG_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Platform endpoints
// ---------------------------------------------------------------------------

/// Windows: symbolic link the daemon opens to reach the WFP callout driver.
pub const WINDOWS_DEVICE_LINK: &str = r"\\.\UnifiedFirewall";

/// Windows: named pipe used for the log ring-buffer notification channel.
pub const WINDOWS_LOG_PIPE: &str = r"\\.\pipe\unified-firewall-log";

/// Windows: service names registered by the installer.
pub const WINDOWS_DRIVER_SERVICE: &str = "ufwflt";
pub const WINDOWS_DAEMON_SERVICE: &str = "UnifiedFirewallDaemon";

/// Linux: generic netlink family name registered by the kernel module.
pub const LINUX_GENL_FAMILY: &str = "ufw_policy";

/// Linux: generic netlink multicast group carrying asynchronous log events.
pub const LINUX_GENL_LOG_GROUP: &str = "ufw_log";

/// Linux: bpffs directory the daemon pins eBPF programs and maps under.
pub const LINUX_BPF_PIN_DIR: &str = "/sys/fs/bpf/unified-firewall";

/// macOS: XPC mach service shared by the daemon and the Network Extension.
pub const MACOS_XPC_SERVICE: &str = "com.unifiedfirewall.policy.xpc";

/// macOS: application group both processes are members of.
pub const MACOS_APP_GROUP: &str = "group.com.unifiedfirewall";

/// Local management socket for the CLI. Windows uses a named pipe with the
/// same trailing component.
pub const DEFAULT_CLI_SOCKET_UNIX: &str = "/var/run/unified-firewall/cli.sock";
pub const DEFAULT_CLI_PIPE_WINDOWS: &str = r"\\.\pipe\unified-firewall-cli";

/// Default filesystem locations.
pub const DEFAULT_CONFIG_PATH_UNIX: &str = "/etc/unified-firewall/daemon.toml";
pub const DEFAULT_POLICY_DIR_UNIX: &str = "/etc/unified-firewall/policies";
pub const DEFAULT_SIGNATURE_DIR_UNIX: &str = "/etc/unified-firewall/sig-rules";
pub const DEFAULT_LOG_PATH_UNIX: &str = "/var/log/unified-firewall/events.jsonl";
pub const DEFAULT_STATE_DIR_UNIX: &str = "/var/lib/unified-firewall";

// ---------------------------------------------------------------------------
// Management API
// ---------------------------------------------------------------------------

/// Default bind address for the REST management API. Loopback by default:
/// exposing the management plane to the network is an explicit opt-in.
pub const DEFAULT_REST_BIND: &str = "127.0.0.1:8443";

/// Default bind address for the gRPC management API.
pub const DEFAULT_GRPC_BIND: &str = "127.0.0.1:8444";

/// Maximum size of a management API request body.
pub const MAX_API_BODY: usize = 8 * 1024 * 1024;

/// Number of historical policy revisions retained for `policy rollback`.
pub const POLICY_HISTORY_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Well-known rule identifiers
// ---------------------------------------------------------------------------

/// Synthetic rule id reported when no rule matched and the policy default
/// action was applied.
pub const RULE_ID_DEFAULT: u32 = 0;

/// Synthetic rule id reported when the emergency allow-all mode is engaged.
pub const RULE_ID_EMERGENCY_ALLOW: u32 = 0xFFFF_FFFE;

/// Synthetic rule id reported when a decision was forced by a failure in the
/// enforcement path itself (fail-closed).
pub const RULE_ID_FAIL_CLOSED: u32 = 0xFFFF_FFFF;

/// First rule id handed out by the compiler. Ids below this are reserved for
/// the synthetic values above.
pub const RULE_ID_BASE: u32 = 1;
