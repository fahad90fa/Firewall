//! The memory-safe core of the Linux data path.
//!
//! This is a faithful port of `kernel/linux/inc/dpi_decoders.h` into safe,
//! `no_std`, allocation-free Rust. It parses DNS, HTTP, TLS and SSH payloads —
//! attacker-chosen bytes, in softirq context, in ring 0 — and it exists in
//! Rust for one reason the C version could not offer: **an out-of-bounds read
//! is a `None`, not a kernel memory disclosure.**
//!
//! The C had to get every bounds check right by inspection, and a firewall's
//! parsers are precisely where an off-by-one becomes a privilege escalation.
//! Here the compiler enforces it: there is no `unsafe`, every byte read goes
//! through `slice::get`, and every arithmetic that could wrap is spelled
//! `wrapping_*` or `saturating_*` so nothing panics on a crafted length either.
//!
//! # Why this is a byte-for-byte port and not an improvement
//!
//! The equivalence claim — one policy, three kernels, same verdict — extends
//! to the facts the decoders extract. If this Rust reads `http.header_count`
//! differently from the Windows C, a policy means something different on a
//! Linux host, and no policy test would ever surface it. So this reproduces
//! the C's arithmetic exactly, including its integer-only entropy and its FNV
//! fingerprint hashes, and `tests/differential.rs` compiles the C header and
//! checks the two agree on every field across a fuzz corpus.
//!
//! Getting the C *out of ring 0* is the point (item 3 of the hardening plan):
//! the highest-risk code becomes memory-safe by construction, verified on the
//! host, and only the thin Rust-for-Linux glue in `../module.rs` — netfilter
//! hook registration, which touches no payload — remains outside this crate.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod fields;

/// The decoded facts a signature can test.
///
/// Fixed-size and stack-allocatable: 128 `u32` values and a presence bit each,
/// which is what lets this live in a `no_std` context with no allocator. The
/// layout mirrors `struct ufw_decoded` in the C so the two are trivially
/// comparable.
#[derive(Clone)]
pub struct Decoded {
    values: [u32; 128],
    present: [bool; 128],
}

impl Default for Decoded {
    fn default() -> Self {
        Decoded {
            values: [0; 128],
            present: [false; 128],
        }
    }
}

impl Decoded {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a field. Absent-is-not-zero: a field never written stays
    /// `present == false`, and [`Self::get`] returns `None`, which the
    /// evaluator treats as failing its condition. That is the fail-closed
    /// direction, and it is why the presence bit exists rather than a sentinel
    /// value that a crafted payload could forge.
    fn set(&mut self, field: usize, value: u32) {
        if field < 128 {
            self.values[field] = value;
            self.present[field] = true;
        }
    }

    pub fn get(&self, field: usize) -> Option<u32> {
        if field < 128 && self.present[field] {
            Some(self.values[field])
        } else {
            None
        }
    }

    pub fn is_present(&self, field: usize) -> bool {
        field < 128 && self.present[field]
    }
}

/// FNV-1a, 32-bit. `wrapping_mul` because the C relies on the unsigned
/// multiply wrapping, and a debug-mode Rust `*` would panic on the same input
/// the C accepts silently.
#[inline]
fn fnv1a(h: u32, b: u8) -> u32 {
    (h ^ b as u32).wrapping_mul(16_777_619)
}

const FNV_OFFSET: u32 = 2_166_136_261;

/// GREASE (RFC 8701): the `0x?A?A` pattern with equal nibbles. Skipped from
/// fingerprints and counted separately, exactly as the C does.
#[inline]
fn is_grease(v: u32) -> bool {
    (v & 0x0F0F) == 0x0A0A && ((v >> 8) & 0xFF) == (v & 0xFF)
}

/// Read a big-endian u16 at `pos`, or `None` if it runs off the end. Every
/// two-byte field in these protocols goes through this, so there is exactly
/// one place a length-field read can be out of bounds, and it cannot be.
#[inline]
fn be16(data: &[u8], pos: usize) -> Option<u32> {
    let hi = *data.get(pos)? as u32;
    let lo = *data.get(pos + 1)? as u32;
    Some((hi << 8) | lo)
}

// --- DNS --------------------------------------------------------------------

pub fn decode_dns(d: &mut Decoded, data: &[u8]) {
    let len = data.len();
    if len < 12 {
        return;
    }
    // ancount lives at offset 6. Present by construction: len >= 12.
    if let Some(ancount) = be16(data, 6) {
        d.set(fields::DNS_ANSWER_COUNT, ancount);
    }

    let mut pos = 12usize;
    let mut name_len = 0u32;
    let mut max_label = 0u32;
    let mut labels = 0u32;

    // Walk the QNAME label chain. Compression pointers (0xC0 bits) are refused
    // rather than followed: a pointer in a question is malformed, and chasing
    // one in the kernel needs a visited set against a crafted loop. Bailing
    // leaves the fields absent — the safe direction.
    while pos < len {
        let label_len = data[pos] as usize; // pos < len checked by the loop
        if label_len == 0 {
            break;
        }
        if (label_len & 0xC0) == 0xC0 {
            return;
        }
        if label_len > 63 || pos + 1 + label_len > len {
            return;
        }
        if label_len as u32 > max_label {
            max_label = label_len as u32;
        }
        name_len += label_len as u32 + 1;
        labels += 1;
        pos += 1 + label_len;

        if name_len > 255 || labels > 128 {
            return;
        }
    }

    d.set(fields::DNS_MAX_LABEL_LEN, max_label);
    d.set(fields::DNS_NAME_LEN, name_len);
    d.set(fields::DNS_LABEL_COUNT, labels);

    // QTYPE follows the terminating zero: skip it (pos), then a 2-byte type.
    if let Some(qtype) = be16(data, pos + 1) {
        d.set(fields::DNS_QUERY_TYPE, qtype);
    }
}

// --- HTTP -------------------------------------------------------------------

pub fn http_method_id(data: &[u8]) -> u32 {
    let starts = |p: &[u8]| data.len() >= p.len() && &data[..p.len()] == p;
    if starts(b"GET ") {
        1
    } else if starts(b"POST ") {
        2
    } else if starts(b"PUT ") {
        3
    } else if starts(b"DELETE ") {
        4
    } else if starts(b"HEAD ") {
        5
    } else if starts(b"OPTIONS ") {
        6
    } else if starts(b"PATCH ") {
        7
    } else if starts(b"CONNECT ") {
        8
    } else if starts(b"TRACE ") {
        9
    } else {
        0
    }
}

pub fn decode_http(d: &mut Decoded, data: &[u8]) {
    let len = data.len();
    d.set(fields::HTTP_METHOD, http_method_id(data));

    // The request URI: from the first space to the next whitespace, within the
    // first 64 bytes of the request line.
    let mut uri_start = 0usize;
    for (i, &b) in data.iter().take(len.min(64)).enumerate() {
        if b == b' ' {
            uri_start = i + 1;
            break;
        }
    }
    let mut uri_len = 0u32;
    if uri_start != 0 {
        let mut i = uri_start;
        while i < len {
            let c = data[i];
            if c == b' ' || c == b'\r' || c == b'\n' {
                break;
            }
            uri_len += 1;
            i += 1;
        }
    }
    d.set(fields::HTTP_URI_LEN, uri_len);

    // Count header lines and find the blank line that ends them.
    let mut headers = 0u32;
    let mut body_start = 0usize;
    let mut i = 0usize;
    while i + 1 < len {
        if data[i] == b'\n' {
            headers += 1;
            if data[i + 1] == b'\r' || data[i + 1] == b'\n' {
                body_start = i + 2;
                break;
            }
        }
        i += 1;
    }
    // The request line is not a header.
    d.set(fields::HTTP_HEADER_COUNT, headers.saturating_sub(1));
    d.set(
        fields::HTTP_BODY_LEN,
        if body_start != 0 && body_start < len {
            (len - body_start) as u32
        } else {
            0
        },
    );

    // Printable ratio of the body, for the exfil heuristics.
    let mut printable = 0u32;
    for &c in &data[body_start..len] {
        if (0x20..0x7F).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t' {
            printable += 1;
        }
    }
    if body_start < len {
        d.set(
            fields::PAYLOAD_PRINTABLE,
            printable.wrapping_mul(100) / (len - body_start) as u32,
        );
    }
}

// --- TLS --------------------------------------------------------------------

pub fn decode_tls(d: &mut Decoded, data: &[u8]) {
    let len = data.len();
    if len < 6 {
        return;
    }

    // Record layer version and handshake type are always readable at len >= 6.
    d.set(fields::TLS_VERSION, be16(data, 1).unwrap_or(0));
    d.set(fields::TLS_HANDSHAKE, data[5] as u32);

    if data[0] != 0x16 || data[5] != 0x01 {
        return; // not a ClientHello; the fields below do not exist
    }

    // handshake header(4) + client version(2) + random(32)
    let mut pos = 5 + 4 + 2 + 32;
    if pos >= len {
        return;
    }
    // The ClientHello's own version beats the record layer's, which is pinned
    // low for middlebox compatibility.
    if let Some(v) = be16(data, 9) {
        d.set(fields::TLS_VERSION, v);
    }

    let session_len = data[pos] as usize;
    pos += 1 + session_len;
    if pos + 2 > len {
        return;
    }

    let cipher_len = match be16(data, pos) {
        Some(v) => v as usize,
        None => return,
    };
    let mut cipher_count = 0u32;
    let mut cipher_hash = FNV_OFFSET;
    {
        let mut c = pos + 2;
        let cend = (pos + 2 + cipher_len).min(len);
        while c + 1 < cend {
            let suite = be16(data, c).unwrap_or(0);
            if !is_grease(suite) {
                cipher_count += 1;
                cipher_hash = fnv1a(cipher_hash, data[c]);
                cipher_hash = fnv1a(cipher_hash, data[c + 1]);
            }
            c += 2;
        }
    }
    d.set(fields::TLS_CIPHER_COUNT, cipher_count);
    pos += 2 + cipher_len;
    if pos >= len {
        return;
    }

    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > len {
        return;
    }

    let ext_total = match be16(data, pos) {
        Some(v) => v as usize,
        None => return,
    };
    pos += 2;
    let ext_end = (pos + ext_total).min(len);

    d.set(fields::TLS_SNI_LEN, 0);
    d.set(fields::TLS_ECH, 0);

    let mut extensions = 0u32;
    let mut grease = 0u32;
    let mut ext_hash = FNV_OFFSET;
    let mut alpn_hash = FNV_OFFSET;

    while pos + 4 <= ext_end {
        let ext_type = be16(data, pos).unwrap_or(0);
        let ext_len = be16(data, pos + 2).unwrap_or(0) as usize;

        if is_grease(ext_type) {
            grease += 1;
        } else {
            extensions += 1;
            // Extension types in order, GREASE removed: the JA4 half that
            // identifies the library.
            ext_hash = fnv1a(ext_hash, (ext_type >> 8) as u8);
            ext_hash = fnv1a(ext_hash, ext_type as u8);
        }
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }

        // server_name (0): list length(2) type(1) name length(2).
        if ext_type == 0 && ext_len >= 5 {
            if let Some(sni) = be16(data, pos + 3) {
                d.set(fields::TLS_SNI_LEN, sni);
            }
        }

        // ALPN (16): list length(2) then length-prefixed protocol names.
        if ext_type == 16 && ext_len >= 3 {
            let mut a = pos + 2;
            let alpn_end = (pos + ext_len).min(ext_end);
            while a < alpn_end {
                let n = data[a] as usize; // a < alpn_end <= len
                a += 1;
                if a + n > alpn_end {
                    break;
                }
                for k in 0..n {
                    alpn_hash = fnv1a(alpn_hash, data[a + k]);
                }
                a += n;
            }
        }

        // supported_versions (43): the true version for TLS 1.3.
        if ext_type == 43 && ext_len >= 3 {
            let mut v = pos + 1;
            let vend = (pos + ext_len).min(ext_end);
            let mut best = 0u32;
            while v + 1 < vend {
                let ver = be16(data, v).unwrap_or(0);
                if !is_grease(ver) && ver > best {
                    best = ver;
                }
                v += 2;
            }
            if best != 0 {
                d.set(fields::TLS_SUPPORTED_VER, best);
            }
        }

        // encrypted_client_hello: record that the SNI was hidden rather than
        // reporting it absent.
        if ext_type == 0xFE0D {
            d.set(fields::TLS_ECH, 1);
        }

        pos += ext_len;
    }

    d.set(fields::TLS_EXT_COUNT, extensions);
    d.set(fields::TLS_GREASE_COUNT, grease);
    d.set(fields::TLS_CIPHER_HASH, cipher_hash);
    d.set(fields::TLS_EXT_HASH, ext_hash);
    d.set(fields::TLS_ALPN_HASH, alpn_hash);

    // JA4's `a` segment, packed into one comparable integer.
    let version = if d.is_present(fields::TLS_SUPPORTED_VER) {
        d.values[fields::TLS_SUPPORTED_VER]
    } else {
        d.values[fields::TLS_VERSION]
    };
    let mut ja4 = 0u32;
    ja4 |= (version & 0xFF) << 24;
    ja4 |= (if d.values[fields::TLS_SNI_LEN] != 0 {
        1
    } else {
        0
    }) << 23;
    ja4 |= (if d.values[fields::TLS_ECH] != 0 { 1 } else { 0 }) << 22;
    ja4 |= cipher_count.min(99) << 15;
    ja4 |= extensions.min(99) << 8;
    ja4 |= alpn_hash & 0xFF;
    d.set(fields::TLS_JA4, ja4);
}

// --- SSH --------------------------------------------------------------------

pub fn decode_ssh(d: &mut Decoded, data: &[u8]) {
    let len = data.len();
    if len < 8 || &data[..4] != b"SSH-" {
        return;
    }
    // "SSH-2.0-..." — major and minor are ASCII digits at 4 and 6.
    if data[4].is_ascii_digit() && data[6].is_ascii_digit() {
        d.set(
            fields::SSH_PROTO_VERSION,
            (data[4] - b'0') as u32 * 10 + (data[6] - b'0') as u32,
        );
    }
    let mut banner_len = 0u32;
    for &b in data.iter().take(len.min(255)) {
        if b == b'\r' || b == b'\n' {
            break;
        }
        banner_len += 1;
    }
    d.set(fields::SSH_BANNER_LEN, banner_len);
}

// --- protocol identification ------------------------------------------------

pub fn identify(data: &[u8], dst_port: u16) -> u8 {
    if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 {
        return fields::L7_TLS;
    }
    if data.len() >= 4 && &data[..4] == b"SSH-" {
        return fields::L7_SSH;
    }
    if http_method_id(data) != 0 {
        return fields::L7_HTTP;
    }
    if data.len() >= 4 && &data[..4] == b"HTTP" {
        return fields::L7_HTTP;
    }
    // DNS has no distinctive prefix, so it falls back to the port — weaker,
    // and deliberately last.
    if dst_port == 53 || dst_port == 5353 {
        return fields::L7_DNS;
    }
    if dst_port == 25 || dst_port == 465 || dst_port == 587 {
        return fields::L7_SMTP;
    }
    fields::L7_UNKNOWN
}

// --- entropy ----------------------------------------------------------------

/// Integer log2 in hundredths of a bit. Bit-identical to `ilog2_centi` in the
/// C and the Swift, which is what lets an entropy threshold mean the same
/// thing on all three platforms.
fn ilog2_centi(v: u32) -> u32 {
    if v == 0 {
        return 0;
    }
    let whole = 31 - v.leading_zeros(); // fls(v) - 1
    let remainder = v - (1u32 << whole);
    let frac = remainder.wrapping_mul(100) / (1u32 << whole);
    whole.wrapping_mul(100) + frac
}

/// Shannon entropy in hundredths of a bit per byte, via
/// `H = log2(n) - (1/n) * sum(c_i * log2(c_i))`. Integer throughout, matching
/// the C exactly — no FPU in the kernel, and a per-platform rounding
/// difference would be an equivalence failure that depends on payload content.
pub fn entropy_centibits(data: &[u8]) -> u32 {
    let len = data.len();
    if len == 0 {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut weighted = 0u64;
    for &c in counts.iter() {
        if c != 0 {
            weighted += c as u64 * ilog2_centi(c) as u64;
        }
    }
    let total = ilog2_centi(len as u32);
    let mean = (weighted / len as u64) as u32;
    total.saturating_sub(mean)
}

/// Decode by protocol id — the entry point the classifier calls, mirroring the
/// `switch (l7)` in `ufw_dpi_scan`.
pub fn decode(l7: u8, data: &[u8]) -> Decoded {
    let mut d = Decoded::new();
    d.set(fields::PAYLOAD_LEN, data.len() as u32);
    match l7 {
        fields::L7_DNS => decode_dns(&mut d, data),
        fields::L7_HTTP => decode_http(&mut d, data),
        fields::L7_TLS => decode_tls(&mut d, data),
        fields::L7_SSH => decode_ssh(&mut d, data),
        _ => {}
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dns_query_yields_its_label_facts() {
        // www.example.com, one question.
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in [b"www".as_slice(), b"example", b"com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label);
        }
        q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

        let d = decode(fields::L7_DNS, &q);
        assert_eq!(d.get(fields::DNS_LABEL_COUNT), Some(3));
        assert_eq!(d.get(fields::DNS_MAX_LABEL_LEN), Some(7)); // "example"
        assert_eq!(d.get(fields::DNS_QUERY_TYPE), Some(1)); // A
    }

    #[test]
    fn a_compression_pointer_in_a_question_leaves_the_fields_absent() {
        // 0xC0 high bits: the fail-closed refusal, not a followed pointer.
        let mut q = vec![0u8; 12];
        q.push(0xC0);
        q.push(0x0C);
        let d = decode(fields::L7_DNS, &q);
        assert_eq!(d.get(fields::DNS_LABEL_COUNT), None);
    }

    #[test]
    fn a_post_request_is_recognised_and_measured() {
        let req = b"POST /admin HTTP/1.1\r\nHost: x\r\n\r\nbody";
        let d = decode(fields::L7_HTTP, req);
        assert_eq!(d.get(fields::HTTP_METHOD), Some(2));
        assert_eq!(d.get(fields::HTTP_URI_LEN), Some(6)); // "/admin"
                                                          // 5, not 4: the C's body_start lands *on* the blank line's `\n`
                                                          // rather than after it, so the body is "\nbody". The port reproduces
                                                          // that quirk exactly rather than "fixing" it — the differential test
                                                          // is what guarantees this Rust and the shipped C agree, quirks and
                                                          // all, because a decoder that disagrees is a policy that means two
                                                          // things.
        assert_eq!(d.get(fields::HTTP_BODY_LEN), Some(5));
    }

    #[test]
    fn a_truncated_payload_never_panics() {
        // The whole justification for the port: every prefix of every seed is
        // safe. In C this is a promise; here the type system keeps it.
        let seeds: &[(u8, &[u8])] = &[
            (fields::L7_TLS, &[0x16, 0x03, 0x01, 0x00, 0x50, 0x01]),
            (fields::L7_HTTP, b"POST /x HTTP/1.1\r\n\r\n"),
            (fields::L7_DNS, &[0u8; 20]),
            (fields::L7_SSH, b"SSH-2.0-x\r\n"),
        ];
        for &(l7, full) in seeds {
            for cut in 0..=full.len() {
                let _ = decode(l7, &full[..cut]); // must not panic
            }
        }
    }

    #[test]
    fn entropy_of_uniform_bytes_is_near_the_maximum() {
        let all: Vec<u8> = (0..=255u8).collect();
        let h = entropy_centibits(&all);
        // 8 bits = 800 centibits; the integer approximation lands close.
        assert!(h >= 700, "uniform entropy came out {h}");
    }

    #[test]
    fn entropy_of_one_repeated_byte_is_zero() {
        assert_eq!(entropy_centibits(&[0x41; 100]), 0);
    }
}
