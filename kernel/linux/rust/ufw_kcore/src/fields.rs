//! Field and protocol identifiers, matching `daemon/src/signatures.rs` and the
//! `#define`s in `kernel/linux/inc/dpi_decoders.h`.
//!
//! These are ABI: the kernel-side evaluator switches on them, so the values
//! are never reused. They are duplicated here rather than generated because a
//! generated constant is one more thing that can be out of step, and
//! `ufw_kcore`'s whole point is to be checkable against the C without a build
//! system in between — the differential test asserts every one of these
//! matches its C counterpart.

// DNS
pub const DNS_MAX_LABEL_LEN: usize = 1;
pub const DNS_NAME_LEN: usize = 2;
pub const DNS_LABEL_COUNT: usize = 3;
pub const DNS_QUERY_TYPE: usize = 4;
pub const DNS_ANSWER_COUNT: usize = 5;

// HTTP
pub const HTTP_METHOD: usize = 20;
pub const HTTP_URI_LEN: usize = 21;
pub const HTTP_HEADER_COUNT: usize = 22;
pub const HTTP_BODY_LEN: usize = 23;
pub const HTTP_HOST_LEN: usize = 24;

// TLS
pub const TLS_VERSION: usize = 40;
pub const TLS_SNI_LEN: usize = 41;
pub const TLS_CIPHER_COUNT: usize = 42;
pub const TLS_EXT_COUNT: usize = 43;
pub const TLS_HANDSHAKE: usize = 44;
pub const TLS_CIPHER_HASH: usize = 45;
pub const TLS_EXT_HASH: usize = 46;
pub const TLS_ALPN_HASH: usize = 47;
pub const TLS_JA4: usize = 48;
pub const TLS_GREASE_COUNT: usize = 49;
pub const TLS_SUPPORTED_VER: usize = 50;
pub const TLS_ECH: usize = 51;

// SSH
pub const SSH_PROTO_VERSION: usize = 60;
pub const SSH_BANNER_LEN: usize = 61;

// Generic
pub const PAYLOAD_LEN: usize = 100;
pub const PAYLOAD_PRINTABLE: usize = 101;

// Application protocols, matching `L7Protocol` in `shared/src/policy_types.rs`.
pub const L7_UNKNOWN: u8 = 0;
pub const L7_HTTP: u8 = 1;
pub const L7_TLS: u8 = 2;
pub const L7_DNS: u8 = 3;
pub const L7_SSH: u8 = 4;
pub const L7_SMTP: u8 = 5;
pub const L7_QUIC: u8 = 6;
