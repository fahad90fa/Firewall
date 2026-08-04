//! SHA-256, implemented in-tree.
//!
//! Used for three things: hashing ELF/PE/Mach-O binaries during application
//! identity resolution, deriving the `ruleset_hash` that lets the daemon and
//! the kernel module agree on which policy is installed, and deriving stable
//! rule identifiers from rule names so that a rule keeps its id across
//! recompiles (which is what makes incremental hot-reload diffs meaningful).
//!
//! This is a straight transcription of FIPS 180-4. It is not constant-time and
//! is not intended for secret-dependent inputs; nothing in this project hashes
//! a secret.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Streaming SHA-256 state.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { state: INIT, buf: [0u8; 64], buf_len: 0, total_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }

        let rest = chunks.remainder();
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buf_len = rest.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Pad: 0x80, then zeros, then the 64-bit big-endian bit length.
        self.update_raw(&[0x80]);
        while self.buf_len != 56 {
            self.update_raw(&[0x00]);
        }
        let len_be = bit_len.to_be_bytes();
        self.buf[56..64].copy_from_slice(&len_be);
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Buffer bytes without disturbing the message-length accumulator, which
    /// has already been fixed by the time padding is appended.
    fn update_raw(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buf_len] = b;
            self.buf_len += 1;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        let add = [a, b, c, d, e, f, g, h];
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(add[i]);
        }
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Lowercase hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse a hex string of any even length into bytes. Rejects odd lengths and
/// non-hex characters. Accepts an optional `sha256:` prefix, which is how
/// hashes are written in policy files.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("sha256:").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in b.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
}

/// Parse exactly 32 bytes of hex into a digest.
pub fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    let v = unhex(s)?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

/// Derive a stable 32-bit rule id from a policy name and a rule name.
///
/// Rule ids must survive recompilation: the hot-reload diff in the daemon
/// compares old and new rule sets by id, so an id derived from the rule's
/// ordinal position would make every rule after an insertion look modified.
/// Deriving it from the name instead means only genuinely-changed rules appear
/// in the diff.
///
/// Ids collide with probability ~n²/2³³; the compiler detects a collision and
/// reports it as a source-level error rather than silently merging rules.
pub fn derive_rule_id(policy_name: &str, rule_name: &str) -> u32 {
    let mut h = Sha256::new();
    h.update(policy_name.as_bytes());
    h.update(b"\x1f");
    h.update(rule_name.as_bytes());
    let d = h.finalize();
    let raw = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    // Keep out of the reserved low range and away from the synthetic ids.
    let span = crate::constants::RULE_ID_EMERGENCY_ALLOW - crate::constants::RULE_ID_BASE;
    crate::constants::RULE_ID_BASE + (raw % span)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn multi_block_and_streaming_agree() {
        let data = vec![0xa5u8; 1000];
        let one_shot = sha256(&data);
        let mut h = Sha256::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(one_shot, h.finalize());
    }

    #[test]
    fn exactly_one_million_a() {
        let mut h = Sha256::new();
        let block = vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&block);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = sha256(b"policy");
        assert_eq!(parse_sha256(&hex(&d)), Some(d));
        assert_eq!(parse_sha256(&format!("sha256:{}", hex(&d))), Some(d));
        assert_eq!(parse_sha256("abcd"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn rule_ids_are_stable_and_in_range() {
        let a = derive_rule_id("base", "allow-dns");
        let b = derive_rule_id("base", "allow-dns");
        let c = derive_rule_id("base", "allow-ntp");
        assert_eq!(a, b);
        assert_ne!(a, c);
        for id in [a, c] {
            assert!(id >= crate::constants::RULE_ID_BASE);
            assert!(id < crate::constants::RULE_ID_EMERGENCY_ALLOW);
        }
    }
}
