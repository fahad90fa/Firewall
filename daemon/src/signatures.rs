//! DPI signature definitions: the format, the loader, and the wire encoding.
//!
//! A policy names signatures; this module is what those names mean. The
//! separation matters because the two change on different schedules and by
//! different people: a policy is a statement about *this deployment*, revised
//! when the deployment changes, while a signature is a statement about an
//! attack, revised when the attack changes. Coupling them would mean every
//! threat-intelligence update rewrote every policy.
//!
//! # The format
//!
//! ```yaml
//! version: 1
//! signatures:
//!   - id: dns-tunnel-long-label
//!     protocol: dns
//!     severity: high
//!     description: "..."
//!     conditions:
//!       - field: dns.max_label_length
//!         op: ">="
//!         value: 40
//!       - entropy: dns.qname
//!         min: 3.5
//! ```
//!
//! Conditions are a *conjunction*: every one must hold. There is deliberately
//! no `or`, no grouping and no regular expressions. That is a restriction on
//! what can be expressed, and it is the point:
//!
//!   - Every condition kind here evaluates in bounded time against a bounded
//!     window. A signature language with backtracking gives an attacker a way
//!     to spend the kernel's time on a packet they chose, which is a denial of
//!     service with extra steps.
//!   - The evaluator has to exist three times over, in C for two kernels and
//!     in Swift for a sandboxed extension. Every construct is paid for three
//!     times, and every construct is a place the three can disagree.
//!
//! Disjunction is still available where it belongs: write two signatures and
//! put both in a `signature_groups:` entry. That costs one line and keeps the
//! evaluator flat.
//!
//! # Field references
//!
//! A `field:` condition names a value the protocol decoder already extracted.
//! It is not an offset into the payload — offsets into a decoded protocol are
//! how a parser differential becomes a bypass. [`Field`] is the closed set the
//! decoders publish, and a signature naming anything else fails to load rather
//! than silently never matching.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ufw_shared::hash::derive_signature_id;
use ufw_shared::json::JsonWriter;
use ufw_shared::policy_types::L7Protocol;
use ufw_shared::protocol::Writer;

use crate::automaton::{self, Automaton, MatchTable, Pattern, NO_PATTERN};

/// How bad a match is. Carried into the log event so a SIEM can triage
/// without a lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A decoded protocol value a signature can test.
///
/// Closed by design. Adding a field means adding it to the decoder in all
/// three kernel implementations, and the discriminant is ABI: it is what the
/// kernel-side evaluator switches on, so values are never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Field {
    // DNS
    DnsMaxLabelLength = 1,
    DnsNameLength = 2,
    DnsLabelCount = 3,
    DnsQueryType = 4,
    DnsAnswerCount = 5,
    // HTTP
    HttpMethod = 20,
    HttpUriLength = 21,
    HttpHeaderCount = 22,
    HttpBodyLength = 23,
    HttpHostLength = 24,
    // TLS
    TlsVersion = 40,
    TlsSniLength = 41,
    TlsCipherCount = 42,
    TlsExtensionCount = 43,
    TlsHandshakeType = 44,
    // Encrypted-traffic classification. Everything is TLS now, and a DPI
    // engine that can say nothing about a TLS flow can say nothing about most
    // flows. These describe *how the client asked* rather than what it sent,
    // which is available without the interception this project does not do.
    TlsCipherHash = 45,
    TlsExtensionHash = 46,
    TlsAlpnHash = 47,
    TlsJa4 = 48,
    TlsGreaseCount = 49,
    TlsSupportedVersion = 50,
    TlsEncryptedClientHello = 51,
    // SSH
    SshProtocolVersion = 60,
    SshBannerLength = 61,
    // Generic, available for every protocol
    PayloadLength = 100,
    PayloadPrintableRatio = 101,
}

impl Field {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "dns.max_label_length" => Field::DnsMaxLabelLength,
            "dns.name_length" => Field::DnsNameLength,
            "dns.label_count" => Field::DnsLabelCount,
            "dns.query_type" => Field::DnsQueryType,
            "dns.answer_count" => Field::DnsAnswerCount,
            "http.method" => Field::HttpMethod,
            "http.uri_length" => Field::HttpUriLength,
            "http.header_count" => Field::HttpHeaderCount,
            "http.body_length" => Field::HttpBodyLength,
            "http.host_length" => Field::HttpHostLength,
            "tls.version" => Field::TlsVersion,
            "tls.sni_length" => Field::TlsSniLength,
            "tls.cipher_count" => Field::TlsCipherCount,
            "tls.extension_count" => Field::TlsExtensionCount,
            "tls.handshake_type" => Field::TlsHandshakeType,
            "tls.cipher_hash" => Field::TlsCipherHash,
            "tls.extension_hash" => Field::TlsExtensionHash,
            "tls.alpn_hash" => Field::TlsAlpnHash,
            "tls.ja4" => Field::TlsJa4,
            "tls.grease_count" => Field::TlsGreaseCount,
            "tls.supported_version" => Field::TlsSupportedVersion,
            "tls.ech" => Field::TlsEncryptedClientHello,
            "ssh.protocol_version" => Field::SshProtocolVersion,
            "ssh.banner_length" => Field::SshBannerLength,
            "payload.length" => Field::PayloadLength,
            "payload.printable_ratio" => Field::PayloadPrintableRatio,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Field::DnsMaxLabelLength => "dns.max_label_length",
            Field::DnsNameLength => "dns.name_length",
            Field::DnsLabelCount => "dns.label_count",
            Field::DnsQueryType => "dns.query_type",
            Field::DnsAnswerCount => "dns.answer_count",
            Field::HttpMethod => "http.method",
            Field::HttpUriLength => "http.uri_length",
            Field::HttpHeaderCount => "http.header_count",
            Field::HttpBodyLength => "http.body_length",
            Field::HttpHostLength => "http.host_length",
            Field::TlsVersion => "tls.version",
            Field::TlsSniLength => "tls.sni_length",
            Field::TlsCipherCount => "tls.cipher_count",
            Field::TlsExtensionCount => "tls.extension_count",
            Field::TlsHandshakeType => "tls.handshake_type",
            Field::TlsCipherHash => "tls.cipher_hash",
            Field::TlsExtensionHash => "tls.extension_hash",
            Field::TlsAlpnHash => "tls.alpn_hash",
            Field::TlsJa4 => "tls.ja4",
            Field::TlsGreaseCount => "tls.grease_count",
            Field::TlsSupportedVersion => "tls.supported_version",
            Field::TlsEncryptedClientHello => "tls.ech",
            Field::SshProtocolVersion => "ssh.protocol_version",
            Field::SshBannerLength => "ssh.banner_length",
            Field::PayloadLength => "payload.length",
            Field::PayloadPrintableRatio => "payload.printable_ratio",
        }
    }

    /// Every field name, for "did you mean?" suggestions.
    pub const ALL: [&'static str; 26] = [
        "dns.max_label_length",
        "dns.name_length",
        "dns.label_count",
        "dns.query_type",
        "dns.answer_count",
        "http.method",
        "http.uri_length",
        "http.header_count",
        "http.body_length",
        "http.host_length",
        "tls.version",
        "tls.sni_length",
        "tls.cipher_count",
        "tls.extension_count",
        "tls.handshake_type",
        "tls.cipher_hash",
        "tls.extension_hash",
        "tls.alpn_hash",
        "tls.ja4",
        "tls.grease_count",
        "tls.supported_version",
        "tls.ech",
        "ssh.protocol_version",
        "ssh.banner_length",
        "payload.length",
        "payload.printable_ratio",
    ];

    /// Which protocol's decoder publishes this field. A signature that tests
    /// a field from another protocol can never match, so that is a load error
    /// rather than a rule that quietly does nothing.
    pub fn protocol(self) -> Option<L7Protocol> {
        Some(match self {
            Field::DnsMaxLabelLength
            | Field::DnsNameLength
            | Field::DnsLabelCount
            | Field::DnsQueryType
            | Field::DnsAnswerCount => L7Protocol::Dns,
            Field::HttpMethod
            | Field::HttpUriLength
            | Field::HttpHeaderCount
            | Field::HttpBodyLength
            | Field::HttpHostLength => L7Protocol::Http,
            Field::TlsVersion
            | Field::TlsSniLength
            | Field::TlsCipherCount
            | Field::TlsExtensionCount
            | Field::TlsHandshakeType
            | Field::TlsCipherHash
            | Field::TlsExtensionHash
            | Field::TlsAlpnHash
            | Field::TlsJa4
            | Field::TlsGreaseCount
            | Field::TlsSupportedVersion
            | Field::TlsEncryptedClientHello => L7Protocol::Tls,
            Field::SshProtocolVersion | Field::SshBannerLength => L7Protocol::Ssh,
            // Generic fields belong to every protocol.
            Field::PayloadLength | Field::PayloadPrintableRatio => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompareOp {
    Eq = 1,
    Ne = 2,
    Lt = 3,
    Le = 4,
    Gt = 5,
    Ge = 6,
}

impl CompareOp {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "==" | "eq" => CompareOp::Eq,
            "!=" | "ne" => CompareOp::Ne,
            "<" | "lt" => CompareOp::Lt,
            "<=" | "le" => CompareOp::Le,
            ">" | "gt" => CompareOp::Gt,
            ">=" | "ge" => CompareOp::Ge,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CompareOp::Eq => "==",
            CompareOp::Ne => "!=",
            CompareOp::Lt => "<",
            CompareOp::Le => "<=",
            CompareOp::Gt => ">",
            CompareOp::Ge => ">=",
        }
    }

    pub fn apply(self, left: u64, right: u64) -> bool {
        match self {
            CompareOp::Eq => left == right,
            CompareOp::Ne => left != right,
            CompareOp::Lt => left < right,
            CompareOp::Le => left <= right,
            CompareOp::Gt => left > right,
            CompareOp::Ge => left >= right,
        }
    }
}

/// One test. All conditions in a signature must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Compare a decoded protocol field against a constant.
    Field {
        field: Field,
        op: CompareOp,
        value: u64,
    },
    /// Match a literal byte pattern inside a bounded window.
    ///
    /// `offset` and `depth` are mandatory in spirit even though `depth`
    /// defaults: an unbounded search over a reassembled stream is the one
    /// construct here that could cost time proportional to attacker-chosen
    /// input, so the default is the reassembly budget rather than "the rest".
    Content {
        pattern: Vec<u8>,
        offset: u32,
        depth: u32,
        nocase: bool,
    },
    /// Shannon entropy over a decoded field, in hundredths of a bit per byte.
    ///
    /// Stored scaled because the kernel-side evaluator has no floating point
    /// available in any of the three environments, and a threshold that is
    /// rounded differently on each platform is a divergence.
    Entropy { field: Field, min_centibits: u32 },
}

impl Condition {
    fn kind(&self) -> u8 {
        match self {
            Condition::Field { .. } => 1,
            Condition::Content { .. } => 2,
            Condition::Entropy { .. } => 3,
        }
    }
}

/// One signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Stable id derived from the name, matching what the policy compiler
    /// puts in a rule's DPI clause. This is the join between the two files.
    pub id: u32,
    pub name: String,
    pub description: String,
    pub protocol: L7Protocol,
    pub severity: Severity,
    pub conditions: Vec<Condition>,
    /// Free-form references (CVE, advisory URL). Not sent to the kernel.
    pub references: Vec<String>,
    /// The file it came from, for diagnostics.
    pub origin: PathBuf,
}

impl Signature {
    pub fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.u64_field("id", self.id as u64);
        w.str_field("name", &self.name);
        w.str_field("description", &self.description);
        w.str_field("protocol", self.protocol.as_str());
        w.str_field("severity", self.severity.as_str());
        w.str_field("origin", &self.origin.display().to_string());
        w.begin_array_field("conditions");
        for c in &self.conditions {
            w.begin_object();
            match c {
                Condition::Field { field, op, value } => {
                    w.str_field("kind", "field");
                    w.str_field("field", field.as_str());
                    w.str_field("op", op.as_str());
                    w.u64_field("value", *value);
                }
                Condition::Content {
                    pattern,
                    offset,
                    depth,
                    nocase,
                } => {
                    w.str_field("kind", "content");
                    w.str_field("pattern", &ufw_shared::hash::hex(pattern));
                    w.u64_field("offset", *offset as u64);
                    w.u64_field("depth", *depth as u64);
                    w.bool_field("nocase", *nocase);
                }
                Condition::Entropy {
                    field,
                    min_centibits,
                } => {
                    w.str_field("kind", "entropy");
                    w.str_field("field", field.as_str());
                    w.u64_field("min_centibits", *min_centibits as u64);
                }
            }
            w.end_object();
        }
        w.end_array();
        w.str_array_field("references", self.references.iter().map(String::as_str));
        w.end_object();
    }
}

/// Everything loaded from a signature directory.
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    /// Keyed by id so a policy's DPI clause resolves in one lookup, and
    /// ordered so the wire encoding is byte-identical across loads — the
    /// kernel compares a hash to decide whether a reload changed anything.
    pub signatures: BTreeMap<u32, Signature>,
}

impl SignatureSet {
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn get(&self, id: u32) -> Option<&Signature> {
        self.signatures.get(&id)
    }

    pub fn by_name(&self, name: &str) -> Option<&Signature> {
        self.signatures.values().find(|s| s.name == name)
    }

    /// Signature ids a policy references that this set does not define.
    ///
    /// A policy that denies on a signature nobody shipped is a rule that can
    /// never fire, and the operator who wrote it believes they are protected.
    /// Reporting it is the whole reason ids are derived from names rather
    /// than assigned by the signature file.
    pub fn missing(&self, referenced: &[u32]) -> Vec<u32> {
        referenced
            .iter()
            .copied()
            .filter(|id| !self.signatures.contains_key(id))
            .collect()
    }

    /// Every distinct `(bytes, nocase)` pattern named by a content condition,
    /// in a deterministic order. Index in this list is the pattern id the
    /// wire encoding carries and the kernels index their scan results by.
    ///
    /// Deduplicated because a signature set typically names the same handful
    /// of strings from many rules, and the automaton should pay for each
    /// string once.
    pub fn patterns(&self) -> Vec<Pattern> {
        let mut out: Vec<Pattern> = Vec::new();
        for sig in self.signatures.values() {
            for c in &sig.conditions {
                if let Condition::Content {
                    pattern, nocase, ..
                } = c
                {
                    let candidate = Pattern {
                        bytes: pattern.clone(),
                        nocase: *nocase,
                    };
                    if !out.contains(&candidate) {
                        out.push(candidate);
                    }
                }
            }
        }
        out
    }

    /// The multi-pattern automaton for this set, or `None` when there is
    /// nothing to search for or the set exceeds the shipped table limits.
    ///
    /// `None` is not a failure: the kernels fall back to searching per
    /// signature, which is slower and decides exactly the same conditions.
    pub fn automaton(&self) -> Option<Automaton> {
        Automaton::build(&self.patterns())
    }

    /// One pass over `data` for every content pattern in the set.
    ///
    /// This and [`content_holds`] are the reference the three kernel
    /// implementations mirror; `daemon/tests/dpi_automaton_tests.rs` compiles
    /// the two C traversals and checks them against this one.
    pub fn scan_content(&self, data: &[u8]) -> Option<MatchTable> {
        self.automaton().map(|a| a.scan(data))
    }

    /// Wire encoding for the kernel modules.
    ///
    /// Two sections: the signatures, then the automaton. A content condition
    /// carries both its pattern *and* the pattern's automaton id, because the
    /// fallback path in [`automaton::content_matches`] needs the bytes and
    /// because a set with no automaton needs them for every match.
    pub fn encode(&self) -> Vec<u8> {
        let patterns = self.patterns();
        let automaton = Automaton::build(&patterns);
        // Ids are only meaningful when an automaton shipped. Without one every
        // content condition is marked as having no entry, which is what makes
        // a kernel take the naive path without needing a second flag to
        // disagree with.
        let id_of = |bytes: &[u8], nocase: bool| -> u32 {
            if automaton.is_none() {
                return NO_PATTERN;
            }
            patterns
                .iter()
                .position(|p| p.bytes == bytes && p.nocase == nocase)
                .map(|i| i as u32)
                .unwrap_or(NO_PATTERN)
        };

        let mut w = Writer::new();
        w.u32(self.signatures.len() as u32);
        for sig in self.signatures.values() {
            w.u32(sig.id);
            w.u8(sig.protocol as u8);
            w.u8(sig.severity as u8);
            w.u16(sig.conditions.len() as u16);
            for c in &sig.conditions {
                w.u8(c.kind());
                match c {
                    Condition::Field { field, op, value } => {
                        w.u16(*field as u16);
                        w.u8(*op as u8);
                        w.u64(*value);
                    }
                    Condition::Content {
                        pattern,
                        offset,
                        depth,
                        nocase,
                    } => {
                        w.u32(*offset);
                        w.u32(*depth);
                        w.u8(u8::from(*nocase));
                        w.u32(id_of(pattern, *nocase));
                        w.bytes(pattern);
                    }
                    Condition::Entropy {
                        field,
                        min_centibits,
                    } => {
                        w.u16(*field as u16);
                        w.u32(*min_centibits);
                    }
                }
            }
        }

        match &automaton {
            Some(a) => {
                w.u8(1);
                a.encode(&mut w);
            }
            None => w.u8(0),
        }
        w.finish()
    }

    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.u64_field("count", self.signatures.len() as u64);
        w.begin_array_field("signatures");
        for sig in self.signatures.values() {
            sig.write_json(&mut w);
        }
        w.end_array();
        w.end_object();
        w.finish()
    }
}

/// Decide one content condition the way the kernels do.
///
/// `table` is the result of a single automaton pass over `data` and
/// `pattern_id` is the id the wire encoding gave this condition. Either being
/// absent means the set shipped without an automaton, in which case this is
/// the bounded naive search — the same search, decided the same way, without
/// the shared pass.
pub fn content_holds(
    condition: &Condition,
    table: Option<&MatchTable>,
    pattern_id: u32,
    data: &[u8],
) -> bool {
    let Condition::Content {
        pattern,
        offset,
        depth,
        nocase,
    } = condition
    else {
        return false;
    };
    match table {
        Some(t) if pattern_id != NO_PATTERN => {
            automaton::content_matches(pattern, *nocase, *offset, *depth, t.hit(pattern_id), data)
        }
        _ => automaton::naive_contains(pattern, *nocase, data, *offset, *depth),
    }
}

/// A problem with a signature file, located well enough to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError {
    pub file: PathBuf,
    pub line: u32,
    pub message: String,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file.display(), self.line, self.message)
    }
}

impl std::error::Error for SignatureError {}

/// Load every `.yaml` under `dir`, recursively.
///
/// Returns whatever loaded plus every error found. A single malformed file
/// does not discard the rest: the alternative is that one bad signature in a
/// threat-intel drop silently disarms the whole DPI engine.
pub fn load_dir(dir: &Path) -> (SignatureSet, Vec<SignatureError>) {
    let mut set = SignatureSet::default();
    let mut errors = Vec::new();
    let mut files = Vec::new();
    collect_files(dir, &mut files, &mut errors);
    // Sorted so a load is deterministic regardless of directory order, which
    // is what lets the kernel-side hash mean "the signatures changed".
    files.sort();
    for file in files {
        match std::fs::read_to_string(&file) {
            Ok(text) => parse_into(&mut set, &text, &file, &mut errors),
            Err(e) => errors.push(SignatureError {
                file: file.clone(),
                line: 0,
                message: format!("cannot read: {e}"),
            }),
        }
    }
    (set, errors)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, errors: &mut Vec<SignatureError>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push(SignatureError {
                file: dir.to_path_buf(),
                line: 0,
                message: format!("cannot list signature directory: {e}"),
            });
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out, errors);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            out.push(path);
        }
    }
}

/// Parse one signature file into `set`.
///
/// A hand-rolled reader for the same YAML subset the policy language uses.
/// The format is a list of flat maps with one nested list, which does not
/// justify a parser generator, and the whole project takes no dependencies.
pub fn parse_into(
    set: &mut SignatureSet,
    text: &str,
    file: &Path,
    errors: &mut Vec<SignatureError>,
) {
    let mut current: Option<Builder> = None;
    let mut in_conditions = false;
    let mut saw_version = false;

    macro_rules! fail {
        ($line:expr, $($arg:tt)*) => {
            errors.push(SignatureError {
                file: file.to_path_buf(),
                line: $line,
                message: format!($($arg)*),
            })
        };
    }

    for (idx, raw) in text.lines().enumerate() {
        let line = idx as u32 + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();

        // A new signature starts at the shallowest list level.
        if let Some(rest) = trimmed.strip_prefix("- ") {
            if in_conditions && indent >= 6 {
                let Some(builder) = current.as_mut() else {
                    fail!(line, "a condition outside any signature");
                    continue;
                };
                match parse_condition(rest, file, line) {
                    Ok(c) => builder.conditions.push(c),
                    Err(e) => errors.push(e),
                }
                continue;
            }
            // Otherwise it is a new signature entry.
            in_conditions = false;
            if let Some(b) = current.take() {
                finish(set, b, file, errors);
            }
            let mut builder = Builder::default();
            builder.line = line;
            if let Some((k, v)) = split_kv(rest) {
                apply_key(&mut builder, k, v, file, line, errors);
            } else {
                fail!(line, "a signature entry starts with `- id: <name>`");
            }
            current = Some(builder);
            continue;
        }

        let Some((key, value)) = split_kv(trimmed) else {
            fail!(line, "expected `key: value`, found `{trimmed}`");
            continue;
        };

        match key {
            "version" if current.is_none() => {
                saw_version = true;
                if value != "1" {
                    fail!(line, "unsupported signature format version `{value}`");
                }
            }
            // The file-level metadata block is documentation; its keys are
            // accepted and ignored rather than enumerated, because a
            // signature drop should not fail to load over a comment field.
            "signatures" if current.is_none() => {}
            "metadata" | "name" | "description" | "author" | "revision" | "source"
                if current.is_none() => {}
            "conditions" => {
                if current.is_none() {
                    fail!(line, "`conditions:` outside a signature");
                } else {
                    in_conditions = true;
                }
            }
            _ => {
                let Some(builder) = current.as_mut() else {
                    fail!(line, "`{key}:` outside a signature");
                    continue;
                };
                in_conditions = false;
                apply_key(builder, key, value, file, line, errors);
            }
        }
    }

    if let Some(b) = current.take() {
        finish(set, b, file, errors);
    }
    if !saw_version {
        errors.push(SignatureError {
            file: file.to_path_buf(),
            line: 1,
            message: "missing `version: 1`; a signature file without a version cannot be \
                      migrated safely"
                .into(),
        });
    }
}

#[derive(Debug, Default)]
struct Builder {
    line: u32,
    name: Option<String>,
    description: String,
    protocol: Option<L7Protocol>,
    severity: Option<Severity>,
    conditions: Vec<Condition>,
    references: Vec<String>,
}

fn apply_key(
    b: &mut Builder,
    key: &str,
    value: &str,
    file: &Path,
    line: u32,
    errors: &mut Vec<SignatureError>,
) {
    let mut fail = |message: String| {
        errors.push(SignatureError {
            file: file.to_path_buf(),
            line,
            message,
        });
    };
    match key {
        "id" => b.name = Some(unquote(value).to_string()),
        "description" => b.description = unquote(value).to_string(),
        "protocol" => match L7Protocol::parse(unquote(value)) {
            Some(p) => b.protocol = Some(p),
            None => fail(format!("`{value}` is not a known application protocol")),
        },
        "severity" => match Severity::parse(unquote(value)) {
            Some(s) => b.severity = Some(s),
            None => fail(format!(
                "`{value}` is not a severity (info, low, medium, high, critical)"
            )),
        },
        "references" => b.references = parse_list(value),
        other => fail(format!(
            "unknown signature key `{other}` (expected id, description, protocol, \
             severity, conditions, references)"
        )),
    }
}

fn finish(set: &mut SignatureSet, b: Builder, file: &Path, errors: &mut Vec<SignatureError>) {
    let mut fail = |line: u32, message: String| {
        errors.push(SignatureError {
            file: file.to_path_buf(),
            line,
            message,
        });
    };
    let Some(name) = b.name else {
        fail(b.line, "signature has no `id:`".into());
        return;
    };
    let Some(protocol) = b.protocol else {
        fail(b.line, format!("signature `{name}` has no `protocol:`"));
        return;
    };
    if b.conditions.is_empty() {
        fail(
            b.line,
            format!(
                "signature `{name}` has no conditions, so it would match every {} flow",
                protocol.as_str()
            ),
        );
        return;
    }
    // A condition testing another protocol's field can never hold, and a
    // signature that can never hold is worse than no signature: someone is
    // relying on it.
    for c in &b.conditions {
        let field = match c {
            Condition::Field { field, .. } | Condition::Entropy { field, .. } => *field,
            Condition::Content { .. } => continue,
        };
        if let Some(owner) = field.protocol() {
            if owner != protocol {
                fail(
                    b.line,
                    format!(
                        "signature `{name}` is `protocol: {}` but tests `{}`, which only the \
                         {} decoder publishes; it could never match",
                        protocol.as_str(),
                        field.as_str(),
                        owner.as_str()
                    ),
                );
                return;
            }
        }
    }

    let id = derive_signature_id(&name);
    let signature = Signature {
        id,
        name: name.clone(),
        description: b.description,
        protocol,
        severity: b.severity.unwrap_or(Severity::Medium),
        conditions: b.conditions,
        references: b.references,
        origin: file.to_path_buf(),
    };

    if let Some(existing) = set.signatures.get(&id) {
        // Same name twice, or a hash collision. Either way the policy's
        // reference is ambiguous, so refuse rather than pick.
        fail(
            b.line,
            format!(
                "signature `{name}` collides with `{}` from {} (id {id}); ids derive from \
                 names, so this is a duplicate definition",
                existing.name,
                existing.origin.display()
            ),
        );
        return;
    }
    set.signatures.insert(id, signature);
}

/// Parse one `- field: x, op: ..., value: n` style condition.
///
/// Conditions are written as an inline flow map so a condition is one line:
/// `- {field: dns.name_length, op: ">=", value: 100}` and the shorthand
/// `- field: dns.name_length >= 100` both work. The shorthand is what the
/// shipped rules use, because a signature people have to read under time
/// pressure should fit on one line.
fn parse_condition(text: &str, file: &Path, line: u32) -> Result<Condition, SignatureError> {
    let err = |message: String| SignatureError {
        file: file.to_path_buf(),
        line,
        message,
    };
    let body = text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();

    let (key, rest) = split_kv(body).ok_or_else(|| {
        err(format!(
            "expected `field:`, `content:` or `entropy:`, got `{body}`"
        ))
    })?;

    match key {
        "field" => {
            // Either `field: name >= value` or `field: name, op: ">=", value: n`.
            let (name, op, value) = if let Some((name, op, value)) = split_comparison(rest) {
                (name, op, value)
            } else {
                let mut parts = rest.split(',').map(str::trim);
                let name = parts.next().unwrap_or_default().to_string();
                let mut op = None;
                let mut value = None;
                for part in parts {
                    let Some((k, v)) = split_kv(part) else {
                        continue;
                    };
                    match k {
                        "op" => op = CompareOp::parse(unquote(v)),
                        "value" => value = parse_u64(unquote(v)),
                        _ => {}
                    }
                }
                (
                    name,
                    op.ok_or_else(|| err("a field condition needs an `op:`".into()))?,
                    value.ok_or_else(|| err("a field condition needs a `value:`".into()))?,
                )
            };
            let field = Field::parse(&name).ok_or_else(|| {
                let hint = closest(&name, &Field::ALL)
                    .map(|s| format!(" (did you mean `{s}`?)"))
                    .unwrap_or_default();
                err(format!("`{name}` is not a decoded field{hint}"))
            })?;
            Ok(Condition::Field { field, op, value })
        }
        "content" => {
            let mut parts = rest.split(',').map(str::trim);
            let pattern_text = parts.next().unwrap_or_default();
            let pattern = parse_pattern(unquote(pattern_text))
                .map_err(|e| err(format!("content pattern: {e}")))?;
            if pattern.is_empty() {
                return Err(err("an empty content pattern matches everything".into()));
            }
            let mut offset = 0u32;
            // Default the search window to the smallest reassembly budget
            // rather than "the rest of the stream": the macOS extension only
            // ever buffers that much, so a wider default would be a window
            // that silently means something different on one platform.
            let mut depth = ufw_shared::constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS as u32;
            let mut nocase = false;
            for part in parts {
                let Some((k, v)) = split_kv(part) else {
                    if part == "nocase" {
                        nocase = true;
                    }
                    continue;
                };
                match k {
                    "offset" => offset = parse_u64(unquote(v)).unwrap_or(0) as u32,
                    "depth" => depth = parse_u64(unquote(v)).unwrap_or(0) as u32,
                    "nocase" => nocase = unquote(v) == "true",
                    _ => {}
                }
            }
            if (depth as usize) < pattern.len() {
                return Err(err(format!(
                    "depth {depth} is smaller than the {}-byte pattern, so it can never match",
                    pattern.len()
                )));
            }
            Ok(Condition::Content {
                pattern,
                offset,
                depth,
                nocase,
            })
        }
        "entropy" => {
            let mut parts = rest.split(',').map(str::trim);
            let name = parts.next().unwrap_or_default().to_string();
            let field = Field::parse(&name)
                .ok_or_else(|| err(format!("`{name}` is not a decoded field")))?;
            let mut min = None;
            for part in parts {
                let Some((k, v)) = split_kv(part) else {
                    continue;
                };
                if k == "min" {
                    min = parse_centibits(unquote(v));
                }
            }
            let min_centibits =
                min.ok_or_else(|| err("an entropy condition needs `min:`".into()))?;
            if min_centibits > 800 {
                return Err(err(format!(
                    "a minimum of {}.{:02} bits per byte exceeds the 8.00 maximum, so it can \
                     never match",
                    min_centibits / 100,
                    min_centibits % 100
                )));
            }
            Ok(Condition::Entropy {
                field,
                min_centibits,
            })
        }
        other => Err(err(format!(
            "unknown condition kind `{other}` (expected field, content or entropy)"
        ))),
    }
}

/// `name >= 40` → (name, Ge, 40).
fn split_comparison(text: &str) -> Option<(String, CompareOp, u64)> {
    for token in [">=", "<=", "==", "!=", ">", "<"] {
        if let Some((left, right)) = text.split_once(token) {
            let op = CompareOp::parse(token)?;
            let value = parse_u64(unquote(right.trim()))?;
            return Some((left.trim().to_string(), op, value));
        }
    }
    None
}

/// `|16 03 01|` hex form, or a quoted ASCII literal.
fn parse_pattern(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if let Some(inner) = text.strip_prefix('|').and_then(|t| t.strip_suffix('|')) {
        let mut out = Vec::new();
        for byte in inner.split_whitespace() {
            let v =
                u8::from_str_radix(byte, 16).map_err(|_| format!("`{byte}` is not a hex byte"))?;
            out.push(v);
        }
        return Ok(out);
    }
    Ok(text.as_bytes().to_vec())
}

/// `3.5` → 350. Parsed by hand rather than through a float so the value the
/// kernel compares is exactly the value that was written.
fn parse_centibits(text: &str) -> Option<u32> {
    let text = text.trim();
    let (whole, frac) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    let whole: u32 = whole.parse().ok()?;
    let frac = match frac.len() {
        0 => 0,
        1 => frac.parse::<u32>().ok()? * 10,
        _ => frac.get(..2)?.parse::<u32>().ok()?,
    };
    Some(whole * 100 + frac)
}

fn parse_u64(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    text.parse().ok()
}

fn split_kv(text: &str) -> Option<(&str, &str)> {
    let (key, value) = text.split_once(':')?;
    Some((key.trim(), value.trim()))
}

fn unquote(text: &str) -> &str {
    let text = text.trim();
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .or_else(|| text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
        .unwrap_or(text)
}

fn parse_list(text: &str) -> Vec<String> {
    text.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|s| unquote(s).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Levenshtein-nearest candidate, for "did you mean?".
fn closest<'a>(word: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let mut best: Option<(usize, &str)> = None;
    for c in candidates {
        let d = distance(word, c);
        if d <= word.len().max(c.len()) / 3 && best.map(|(bd, _)| d < bd).unwrap_or(true) {
            best = Some((d, c));
        }
    }
    best.map(|(_, c)| c)
}

fn distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut cur = vec![0usize; b_chars.len() + 1];
    for (i, ac) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, bc) in b_chars.iter().enumerate() {
            let cost = usize::from(ac != *bc);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_chars.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (SignatureSet, Vec<SignatureError>) {
        let mut set = SignatureSet::default();
        let mut errors = Vec::new();
        parse_into(&mut set, text, Path::new("test.yaml"), &mut errors);
        (set, errors)
    }

    const DNS_TUNNEL: &str = r#"
version: 1
metadata:
  name: dns-signatures
signatures:
  - id: dns-tunnel-long-label
    description: "Encoded payload in a DNS label"
    protocol: dns
    severity: high
    conditions:
      - field: dns.max_label_length >= 40
      - field: dns.label_count >= 3
    references: [T1071.004]
"#;

    #[test]
    fn a_signature_parses_into_its_conditions() {
        let (set, errors) = parse(DNS_TUNNEL);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(set.len(), 1);
        let sig = set.by_name("dns-tunnel-long-label").expect("loaded");
        assert_eq!(sig.protocol, L7Protocol::Dns);
        assert_eq!(sig.severity, Severity::High);
        assert_eq!(sig.references, ["T1071.004"]);
        assert_eq!(
            sig.conditions,
            vec![
                Condition::Field {
                    field: Field::DnsMaxLabelLength,
                    op: CompareOp::Ge,
                    value: 40
                },
                Condition::Field {
                    field: Field::DnsLabelCount,
                    op: CompareOp::Ge,
                    value: 3
                },
            ]
        );
    }

    #[test]
    fn the_id_matches_what_the_policy_compiler_derives() {
        // This is the join between a policy and a signature file. If the two
        // ever derive ids differently, every DPI rule silently stops firing.
        let (set, _) = parse(DNS_TUNNEL);
        let sig = set.by_name("dns-tunnel-long-label").unwrap();
        assert_eq!(sig.id, derive_signature_id("dns-tunnel-long-label"));
    }

    #[test]
    fn both_condition_spellings_mean_the_same_thing() {
        let shorthand = "version: 1\nsignatures:\n  - id: a\n    protocol: dns\n    \
                         conditions:\n      - field: dns.name_length > 100\n";
        let longhand = "version: 1\nsignatures:\n  - id: b\n    protocol: dns\n    \
                        conditions:\n      - field: dns.name_length, op: \">\", value: 100\n";
        let (a, ea) = parse(shorthand);
        let (b, eb) = parse(longhand);
        assert!(ea.is_empty() && eb.is_empty(), "{ea:?} {eb:?}");
        assert_eq!(
            a.by_name("a").unwrap().conditions,
            b.by_name("b").unwrap().conditions
        );
    }

    #[test]
    fn content_patterns_parse_as_hex_or_ascii() {
        let text = "version: 1\nsignatures:\n  - id: tls-hello\n    protocol: tls\n    \
                    conditions:\n      - content: |16 03 01|, offset: 0, depth: 8\n  \
                    - id: http-post\n    protocol: http\n    conditions:\n      \
                    - content: \"POST /admin\", depth: 64, nocase: true\n";
        let (set, errors) = parse(text);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            set.by_name("tls-hello").unwrap().conditions[0],
            Condition::Content {
                pattern: vec![0x16, 0x03, 0x01],
                offset: 0,
                depth: 8,
                nocase: false
            }
        );
        match &set.by_name("http-post").unwrap().conditions[0] {
            Condition::Content {
                pattern, nocase, ..
            } => {
                assert_eq!(pattern, b"POST /admin");
                assert!(nocase);
            }
            other => panic!("expected a content condition, got {other:?}"),
        }
    }

    #[test]
    fn entropy_is_stored_scaled_rather_than_as_a_float() {
        // No kernel environment here has floating point, and a threshold
        // rounded differently per platform is a divergence.
        let text = "version: 1\nsignatures:\n  - id: e\n    protocol: dns\n    \
                    conditions:\n      - entropy: dns.name_length, min: 3.5\n";
        let (set, errors) = parse(text);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            set.by_name("e").unwrap().conditions[0],
            Condition::Entropy {
                field: Field::DnsNameLength,
                min_centibits: 350
            }
        );
    }

    #[test]
    fn a_signature_that_could_never_match_is_an_error() {
        // Every one of these loads cleanly as syntax and is useless as a
        // signature, which is the dangerous combination: someone believes
        // they are covered.
        let cases = [
            // Field from another protocol's decoder.
            (
                "version: 1\nsignatures:\n  - id: x\n    protocol: dns\n    \
                 conditions:\n      - field: http.uri_length > 10\n",
                "could never match",
            ),
            // Depth narrower than the pattern.
            (
                "version: 1\nsignatures:\n  - id: x\n    protocol: tls\n    \
                 conditions:\n      - content: |16 03 01|, depth: 2\n",
                "never match",
            ),
            // Entropy above the theoretical maximum.
            (
                "version: 1\nsignatures:\n  - id: x\n    protocol: dns\n    \
                 conditions:\n      - entropy: dns.name_length, min: 9.0\n",
                "never match",
            ),
            // No conditions at all: matches every flow of that protocol.
            (
                "version: 1\nsignatures:\n  - id: x\n    protocol: dns\n",
                "no conditions",
            ),
        ];
        for (text, expected) in cases {
            let (_, errors) = parse(text);
            assert!(
                errors.iter().any(|e| e.message.contains(expected)),
                "expected {expected:?} in {errors:?}"
            );
        }
    }

    #[test]
    fn an_unknown_field_suggests_a_real_one() {
        let text = "version: 1\nsignatures:\n  - id: x\n    protocol: dns\n    \
                    conditions:\n      - field: dns.max_label_len >= 40\n";
        let (_, errors) = parse(text);
        assert!(
            errors[0]
                .message
                .contains("did you mean `dns.max_label_length`"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn a_duplicate_definition_is_refused_rather_than_resolved() {
        let text = "version: 1\nsignatures:\n  - id: dup\n    protocol: dns\n    \
                    conditions:\n      - field: dns.label_count > 1\n  \
                    - id: dup\n    protocol: dns\n    conditions:\n      \
                    - field: dns.label_count > 2\n";
        let (set, errors) = parse(text);
        assert_eq!(set.len(), 1);
        assert!(errors
            .iter()
            .any(|e| e.message.contains("duplicate definition")));
    }

    #[test]
    fn a_missing_version_is_an_error() {
        let text = "signatures:\n  - id: x\n    protocol: dns\n    conditions:\n      \
                    - field: dns.label_count > 1\n";
        let (_, errors) = parse(text);
        assert!(errors.iter().any(|e| e.message.contains("version")));
    }

    #[test]
    fn errors_in_one_signature_do_not_discard_the_others() {
        // A bad entry in a threat-intel drop must not disarm the engine.
        let text = "version: 1\nsignatures:\n  - id: good-one\n    protocol: dns\n    \
                    conditions:\n      - field: dns.label_count > 1\n  \
                    - id: bad-one\n    protocol: dns\n    conditions:\n      \
                    - field: nonsense > 1\n  \
                    - id: good-two\n    protocol: http\n    conditions:\n      \
                    - content: \"GET /\", depth: 16\n";
        let (set, errors) = parse(text);
        assert!(!errors.is_empty());
        assert!(set.by_name("good-one").is_some());
        assert!(
            set.by_name("good-two").is_some(),
            "loading continued past the error"
        );
    }

    #[test]
    fn signatures_a_policy_names_but_nobody_ships_are_reportable() {
        let (set, _) = parse(DNS_TUNNEL);
        let referenced = [
            derive_signature_id("dns-tunnel-long-label"),
            derive_signature_id("never-written"),
        ];
        assert_eq!(
            set.missing(&referenced),
            vec![derive_signature_id("never-written")]
        );
    }

    #[test]
    fn the_wire_encoding_is_stable_across_loads() {
        // The kernel decides whether a reload changed anything by comparing a
        // hash, so two loads of the same text must encode identically.
        let (a, _) = parse(DNS_TUNNEL);
        let (b, _) = parse(DNS_TUNNEL);
        assert_eq!(a.encode(), b.encode());
        assert!(!a.encode().is_empty());
    }

    #[test]
    fn the_load_order_of_files_does_not_change_the_encoding() {
        let first = "version: 1\nsignatures:\n  - id: aaa\n    protocol: dns\n    \
                     conditions:\n      - field: dns.label_count > 1\n";
        let second = "version: 1\nsignatures:\n  - id: zzz\n    protocol: http\n    \
                      conditions:\n      - content: \"GET\", depth: 8\n";

        let mut forward = SignatureSet::default();
        let mut e = Vec::new();
        parse_into(&mut forward, first, Path::new("a.yaml"), &mut e);
        parse_into(&mut forward, second, Path::new("b.yaml"), &mut e);

        let mut backward = SignatureSet::default();
        parse_into(&mut backward, second, Path::new("b.yaml"), &mut e);
        parse_into(&mut backward, first, Path::new("a.yaml"), &mut e);

        assert!(e.is_empty(), "{e:?}");
        assert_eq!(forward.encode(), backward.encode());
    }

    #[test]
    fn json_output_round_trips_through_the_parser() {
        let (set, _) = parse(DNS_TUNNEL);
        let json = set.to_json();
        let parsed = ufw_shared::json::parse(&json).expect("valid JSON");
        assert_eq!(parsed.get("count").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn comparison_operators_do_what_they_say() {
        assert!(CompareOp::Ge.apply(40, 40));
        assert!(!CompareOp::Gt.apply(40, 40));
        assert!(CompareOp::Ne.apply(1, 2));
        assert!(CompareOp::Lt.apply(1, 2));
    }

    #[test]
    fn the_shipped_rules_load_cleanly() {
        // If the signatures this project ships do not load, the DPI examples
        // in the policies are decoration.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("sig-rules");
        if !root.exists() {
            return;
        }
        let (set, errors) = load_dir(&root);
        assert!(errors.is_empty(), "{errors:#?}");
        assert!(set.len() >= 8, "only {} signatures loaded", set.len());

        // And every signature the shipped policies name must be among them.
        for name in [
            "dns-tunnel-long-label",
            "dns-tunnel-high-entropy",
            "http-exploit-post",
            "tls-downgrade-attempt",
        ] {
            assert!(
                set.by_name(name).is_some(),
                "`{name}` is referenced but not defined"
            );
        }
    }
}
