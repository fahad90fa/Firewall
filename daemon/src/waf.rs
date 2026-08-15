//! A userspace WAF engine over the shipped signature set.
//!
//! The DPI layer inspects HTTP on the wire, which means plaintext — an HTTPS
//! payload is opaque to it. This engine closes that gap by running the *same
//! signatures* against a request that has already been decrypted, so the
//! TLS-terminating reverse proxy in [`bin/ufw-waf`](../bin/ufw-waf/main.rs) can
//! inspect HTTPS the DPI layer never could.
//!
//! It is deliberately built on [`SignatureSet`](crate::signatures::SignatureSet)
//! rather than a second rule format: the OWASP set in
//! `sig-rules/exploits/web_owasp.yaml` is authored once and enforced both by the
//! kernel DPI path (on plaintext) and here (on decrypted requests). A signature
//! matches when *every* one of its conditions holds against the request — the
//! same conjunction the kernel evaluates — and the engine reports the
//! highest-severity match so a caller can decide by severity.
//!
//! What it is not: a full WAF. There is no request normalization, no OWASP Core
//! Rule Set, no virtual patching or bot management. It is signature detection on
//! decrypted traffic — the piece a host firewall can genuinely provide — meant
//! to sit *beside* a dedicated edge WAF, not replace it.

use std::sync::Arc;

use crate::automaton;
use crate::signatures::{CompareOp, Condition, Field, Severity, SignatureSet};
use ufw_shared::policy_types::L7Protocol;

/// Facts extracted from an HTTP request, mirroring the fields the decoder
/// publishes to the kernel signature evaluator.
#[derive(Debug, Default, Clone)]
pub struct HttpFacts {
    pub method: u64,
    pub uri_length: u64,
    pub header_count: u64,
    pub body_length: u64,
    pub host_length: u64,
    pub payload_length: u64,
    pub printable_ratio: u64,
}

fn method_code(m: &[u8]) -> u64 {
    match m {
        b"GET" => 1,
        b"POST" => 2,
        b"PUT" => 3,
        b"DELETE" => 4,
        b"HEAD" => 5,
        b"OPTIONS" => 6,
        b"PATCH" => 7,
        b"CONNECT" => 8,
        b"TRACE" => 9,
        _ => 0,
    }
}

/// Parse the request head and body far enough to evaluate the signature fields.
/// Tolerant by design: a malformed request still yields usable facts (and the
/// content conditions run over the raw bytes regardless).
pub fn parse_facts(request: &[u8]) -> HttpFacts {
    let mut facts = HttpFacts {
        payload_length: request.len() as u64,
        ..Default::default()
    };

    let head_end = find_subslice(request, b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(request.len());
    let head = &request[..head_end];
    let body = &request[head_end..];
    facts.body_length = body.len() as u64;

    let printable = request.iter().filter(|b| b.is_ascii_graphic() || **b == b' ').count();
    facts.printable_ratio = if request.is_empty() {
        100
    } else {
        (printable as u64 * 100) / request.len() as u64
    };

    let mut lines = head.split(|&b| b == b'\n');
    if let Some(first) = lines.next() {
        let first = trim_cr(first);
        let mut parts = first.split(|&b| b == b' ');
        if let Some(m) = parts.next() {
            facts.method = method_code(m);
        }
        if let Some(uri) = parts.next() {
            facts.uri_length = uri.len() as u64;
        }
    }
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            continue;
        }
        facts.header_count += 1;
        if let Some(rest) = strip_prefix_ci(line, b"host:") {
            facts.host_length = trim_ascii(rest).len() as u64;
        }
    }
    facts
}

/// A signature that fired on a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafHit {
    pub signature: String,
    pub severity: Severity,
    pub description: String,
}

/// Runs the shipped signatures against decrypted HTTP requests.
#[derive(Debug, Clone)]
pub struct WafEngine {
    set: Arc<SignatureSet>,
    /// Severity at or above which `inspect` returns a block. Signatures below
    /// it still match but are advisory (a caller can log them).
    block_at: Severity,
}

impl WafEngine {
    pub fn new(set: Arc<SignatureSet>) -> Self {
        WafEngine {
            set,
            block_at: Severity::Medium,
        }
    }

    pub fn with_block_threshold(mut self, severity: Severity) -> Self {
        self.block_at = severity;
        self
    }

    /// The highest-severity HTTP signature whose every condition holds against
    /// the request, if any. Only `http` signatures are considered — this is a
    /// web inspector.
    pub fn inspect(&self, request: &[u8]) -> Option<WafHit> {
        let facts = parse_facts(request);
        // Normalize once: an attacker percent-encodes `' or 1=1` to evade a
        // raw-byte match, so content conditions are checked against the decoded
        // form as well as the original (a signature that deliberately targets an
        // encoded sequence still matches the original).
        let normalized = percent_decode(request);
        let mut best: Option<WafHit> = None;
        for sig in self.set.signatures.values() {
            if sig.protocol != L7Protocol::Http {
                continue;
            }
            if !sig
                .conditions
                .iter()
                .all(|c| condition_holds(c, request, &normalized, &facts))
            {
                continue;
            }
            let better = best
                .as_ref()
                .map(|b| sig.severity > b.severity)
                .unwrap_or(true);
            if better {
                best = Some(WafHit {
                    signature: sig.name.clone(),
                    severity: sig.severity,
                    description: sig.description.clone(),
                });
            }
        }
        best
    }

    /// Whether a request should be blocked (a match at or above the threshold).
    pub fn is_blocked(&self, request: &[u8]) -> Option<WafHit> {
        self.inspect(request).filter(|h| h.severity >= self.block_at)
    }
}

fn condition_holds(c: &Condition, request: &[u8], normalized: &[u8], facts: &HttpFacts) -> bool {
    match c {
        Condition::Content {
            pattern,
            offset,
            depth,
            nocase,
        } => {
            automaton::naive_contains(pattern, *nocase, request, *offset, *depth)
                || automaton::naive_contains(pattern, *nocase, normalized, *offset, *depth)
        }
        Condition::Field { field, op, value } => match fact_for(*field, facts) {
            Some(actual) => compare(actual, *op, *value),
            // A field this minimal parser does not extract cannot be asserted;
            // treat it as unmet rather than risk a false block.
            None => false,
        },
        // Entropy conditions do not appear in the web signature set; a WAF that
        // guessed at them would only add false positives.
        Condition::Entropy { .. } => false,
    }
}

fn fact_for(field: Field, f: &HttpFacts) -> Option<u64> {
    Some(match field {
        Field::HttpMethod => f.method,
        Field::HttpUriLength => f.uri_length,
        Field::HttpHeaderCount => f.header_count,
        Field::HttpBodyLength => f.body_length,
        Field::HttpHostLength => f.host_length,
        Field::PayloadLength => f.payload_length,
        Field::PayloadPrintableRatio => f.printable_ratio,
        _ => return None,
    })
}

fn compare(actual: u64, op: CompareOp, value: u64) -> bool {
    match op {
        CompareOp::Eq => actual == value,
        CompareOp::Ne => actual != value,
        CompareOp::Lt => actual < value,
        CompareOp::Le => actual <= value,
        CompareOp::Gt => actual > value,
        CompareOp::Ge => actual >= value,
    }
}

/// Percent-decode a request so an encoded payload matches the same signature
/// its plaintext form would. `+` becomes a space (query-string convention). A
/// malformed `%` escape is left literal rather than dropped, so nothing an
/// attacker sends can shrink the buffer past what a decoder downstream sees.
fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                match (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// --- small byte helpers, no allocation --------------------------------------

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

fn strip_prefix_ci<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if line.len() < prefix.len() {
        return None;
    }
    if line[..prefix.len()]
        .iter()
        .zip(prefix)
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn engine() -> WafEngine {
        // The real shipped signatures — the same set the kernel DPI path uses.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("sig-rules");
        let (set, errors) = crate::signatures::load_dir(&root);
        assert!(errors.is_empty(), "{errors:#?}");
        WafEngine::new(Arc::new(set))
    }

    #[test]
    fn a_clean_request_is_not_flagged() {
        let e = engine();
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n";
        assert!(e.inspect(req).is_none(), "a normal GET must not match");
    }

    #[test]
    fn a_sql_injection_is_caught() {
        let e = engine();
        let req = b"GET /items?id=1' or 1=1-- HTTP/1.1\r\nHost: shop.example\r\n\r\n";
        let hit = e.inspect(req).expect("SQLi tautology should fire");
        assert_eq!(hit.signature, "owasp-sqli-tautology");
    }

    #[test]
    fn a_reflected_xss_is_caught() {
        let e = engine();
        let req = b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n";
        let hit = e.inspect(req).expect("XSS script tag should fire");
        assert_eq!(hit.signature, "owasp-xss-script-tag");
    }

    #[test]
    fn an_ssrf_metadata_grab_is_critical() {
        let e = engine();
        let req = b"GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n";
        let hit = e.is_blocked(req).expect("SSRF metadata is a block");
        assert_eq!(hit.signature, "owasp-ssrf-cloud-metadata");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn a_two_condition_signature_needs_both_parts() {
        let e = engine();
        // XXE needs both `<!ENTITY` and `SYSTEM`; one alone must not fire.
        let entity_only = b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n<!ENTITY foo 'bar'>";
        assert!(
            e.inspect(entity_only)
                .map(|h| h.signature != "owasp-xxe-external-entity")
                .unwrap_or(true),
            "a benign entity without SYSTEM must not trip the XXE rule"
        );
        let full = b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n<!ENTITY xxe SYSTEM 'file:///etc/passwd'>";
        let hit = e.inspect(full).expect("a real XXE payload should fire");
        assert_eq!(hit.signature, "owasp-xxe-external-entity");
    }

    #[test]
    fn the_highest_severity_match_wins() {
        let e = engine();
        // Contains both an SSRF metadata grab (critical) and a script tag (high).
        let req =
            b"GET /?u=http://169.254.169.254/&q=<script> HTTP/1.1\r\nHost: x\r\n\r\n";
        let hit = e.inspect(req).unwrap();
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn a_percent_encoded_sql_injection_is_normalized_and_caught() {
        // The exact evasion an end-to-end run surfaced: `1' or 1=1--`
        // url-encoded to `1%27%20or%201%3D1--` slips a raw-byte match, so the
        // engine must decode before matching.
        let e = engine();
        let req = b"GET /items?id=1%27%20or%201%3D1-- HTTP/1.1\r\nHost: shop\r\n\r\n";
        let hit = e.inspect(req).expect("an encoded SQLi must still be caught");
        assert_eq!(hit.signature, "owasp-sqli-tautology");
    }

    #[test]
    fn percent_decoding_is_tolerant_of_malformed_escapes() {
        assert_eq!(percent_decode(b"a%20b"), b"a b");
        assert_eq!(percent_decode(b"a+b"), b"a b");
        // A stray `%` with no valid hex must survive, not vanish.
        assert_eq!(percent_decode(b"100%"), b"100%");
        assert_eq!(percent_decode(b"a%zzb"), b"a%zzb");
    }

    #[test]
    fn parse_facts_reads_method_and_headers() {
        let f = parse_facts(b"POST /a HTTP/1.1\r\nHost: h.example\r\nX: 1\r\n\r\nbody");
        assert_eq!(f.method, 2); // POST
        assert_eq!(f.header_count, 2);
        assert_eq!(f.host_length, "h.example".len() as u64);
        assert_eq!(f.body_length, 4);
    }
}
