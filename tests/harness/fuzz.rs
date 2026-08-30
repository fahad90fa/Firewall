//! A small, dependency-free, deterministic fuzz driver.
//!
//! The C ring-0 decoders are fuzzed by libFuzzer in `fuzz/` and CI; the Rust
//! parsers — the wire protocol, the policy compiler, the console's HTTP head —
//! were not fuzzed at all, and they are the surface that faces the network and
//! the fleet distribution channel. This module closes that gap without adding a
//! `cargo-fuzz`/libFuzzer dependency to the workspace: a fixed-seed PRNG drives
//! a bounded number of random and mutation-derived inputs through a parser and
//! asserts the one property every parser owes a hostile caller — *it returns,
//! it does not crash the process.* A panic (an unwrap, an arithmetic overflow,
//! an out-of-bounds slice) is caught and re-raised with the exact input that
//! triggered it, in hex, so the failure is reproducible from the seed alone.
//!
//! It is deterministic on purpose. A fuzzer that finds a different bug on every
//! run trains people to re-run until green; this one finds the same inputs
//! every time, so a regression is a stable red and a fix is a stable green. The
//! scheduled libFuzzer campaign is where open-ended, coverage-guided search
//! lives — this is the always-on tripwire that rides in `cargo test`.

use std::panic::{self, AssertUnwindSafe};

/// SplitMix64 — a tiny, well-distributed PRNG. Same generator the detector
/// tests use, so there is one obvious source of determinism in the suite.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// A fresh buffer of uniform random bytes, length in `[0, max_len]`. Reaches the
/// early rejection paths (bad magic, short frames) the most.
pub fn random_bytes(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    let len = rng.below(max_len + 1);
    (0..len).map(|_| rng.byte()).collect()
}

/// A mutation of `seed`. Mutating a *valid* input is what reaches the deep code
/// paths a parser only runs once the header and framing check out — where the
/// interesting overflows live. Applies a few edits: single-byte flips, byte
/// substitutions, insertions, deletions and truncations.
pub fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    let edits = 1 + rng.below(6);
    for _ in 0..edits {
        if v.is_empty() {
            v.push(rng.byte());
            continue;
        }
        match rng.below(5) {
            0 => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len());
                v[i] = rng.byte();
            }
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.byte());
            }
            3 => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            _ => {
                let keep = rng.below(v.len());
                v.truncate(keep);
            }
        }
    }
    v
}

/// Run `f` over `iters` random inputs and `iters` mutations of each seed in
/// `seeds`, asserting none makes `f` panic. On a panic, fails with the label and
/// the offending input in hex so it can be replayed.
///
/// `f` takes bytes and does whatever the parser-under-test needs; its return
/// value is ignored — the property is only that it returns at all.
pub fn no_panic_over_bytes<F>(label: &str, seeds: &[&[u8]], iters: usize, max_len: usize, mut f: F)
where
    F: FnMut(&[u8]),
{
    // Silence the default panic printer for the duration; a caught panic is
    // reported by us, with the reproducing input, rather than as a bare
    // backtrace buried in thousands of lines of fuzz output.
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut rng = Rng::new(0x5EED_0000_0000_0001 ^ label_seed(label));
        for _ in 0..iters {
            let input = random_bytes(&mut rng, max_len);
            drive(&mut f, &input, label);
        }
        for seed in seeds {
            let mut rng = Rng::new(0x00A1_1CE5 ^ label_seed(label) ^ fnv(seed));
            for _ in 0..iters {
                let input = mutate(&mut rng, seed);
                drive(&mut f, &input, label);
            }
        }
    }));
    panic::set_hook(prev);
    if let Err(e) = result {
        // `drive` already formatted a precise message and re-panicked with it;
        // surface that string.
        let msg = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown panic".into());
        panic!("{msg}");
    }
}

fn drive<F: FnMut(&[u8])>(f: &mut F, input: &[u8], label: &str) {
    let r = panic::catch_unwind(AssertUnwindSafe(|| f(input)));
    if r.is_err() {
        panic!(
            "fuzz target `{label}` panicked on input ({} bytes): {}",
            input.len(),
            hex(input)
        );
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn label_seed(label: &str) -> u64 {
    fnv(label.as_bytes())
}
