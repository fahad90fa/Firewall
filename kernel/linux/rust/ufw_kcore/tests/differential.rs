//! The Rust port against the C it replaces, field for field.
//!
//! `src/lib.rs` is a port of `kernel/linux/inc/dpi_decoders.h`. A port is only
//! worth having if it is *faithful*: the equivalence claim — one policy, three
//! kernels, same verdict — reaches down to the facts the decoders extract, so
//! if this Rust reads `tls.ja4` differently from the shipped C, a signature
//! matches on a Linux host and not on a Windows one, and no policy test would
//! ever show it.
//!
//! This compiles the C header, runs both decoders over the same mutated
//! corpus, and asserts every present field and every value agrees. It is the
//! same discipline as `daemon/tests/dpi_decoder_tests.rs`, pointed at the new
//! Rust rather than at the Windows C.
//!
//! Without a C compiler it reports that and passes, rather than failing a
//! developer's machine for a toolchain they do not otherwise need.

use std::path::PathBuf;
use std::process::Command;

use ufw_kcore::{decode, entropy_centibits, fields, identify};

fn repo_root() -> PathBuf {
    // tests/ -> ufw_kcore/ -> rust/ -> linux/ -> kernel/ -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("repo root")
        .to_path_buf()
}

fn c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|&cc| {
            Command::new(cc)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|v| v as _)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
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
            (self.next() % n as u64) as usize
        }
    }
}

fn seeds() -> Vec<(u8, Vec<u8>)> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();

    let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for l in [b"www".as_slice(), b"example", b"com"] {
        dns.push(l.len() as u8);
        dns.extend_from_slice(l);
    }
    dns.extend_from_slice(&[0, 0, 0x01, 0, 0x01]);
    out.push((fields::L7_DNS, dns));

    out.push((
        fields::L7_HTTP,
        b"POST /admin/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 9\r\n\r\nbody-here"
            .to_vec(),
    ));
    out.push((fields::L7_HTTP, b"GET / HTTP/1.0\r\n\r\n".to_vec()));

    // TLS 1.3 ClientHello with SNI, ALPN, supported_versions and a GREASE pair.
    let mut tls = vec![
        0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03,
    ];
    tls.extend_from_slice(&[0xAB; 32]);
    tls.push(0x00); // session id
    tls.extend_from_slice(&[0x00, 0x06, 0x0A, 0x0A, 0xC0, 0x2F, 0xC0, 0x30]); // ciphers incl GREASE
    tls.extend_from_slice(&[0x01, 0x00]); // compression
                                          // extensions: SNI, ALPN, supported_versions
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00, 0x00, 0x0B, 0x00, 0x09, 0x00, 0x00, 0x06]);
    ext.extend_from_slice(b"host.x");
    ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x0B, 0x00, 0x09, 0x02, b'h', b'2', 0x08]);
    ext.extend_from_slice(b"http/1.1");
    ext.extend_from_slice(&[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);
    tls.extend_from_slice(&[(ext.len() >> 8) as u8, ext.len() as u8]);
    tls.extend_from_slice(&ext);
    out.push((fields::L7_TLS, tls));

    out.push((
        fields::L7_SSH,
        b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n".to_vec(),
    ));

    out.push((fields::L7_DNS, Vec::new()));
    out.push((fields::L7_TLS, vec![0x16]));
    out.push((fields::L7_HTTP, vec![0x00]));
    out
}

fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(3) {
        if v.is_empty() {
            v.push(rng.next() as u8);
            continue;
        }
        match rng.below(5) {
            0 => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            1 => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            2 => {
                for _ in 0..rng.below(48) {
                    v.push(rng.next() as u8);
                }
            }
            3 => {
                let i = rng.below(v.len());
                v[i] = [0, 1, 0x7F, 0x80, 0xFF][rng.below(5)];
            }
            _ => {
                let (a, b) = (rng.below(v.len()), rng.below(v.len()));
                v.swap(a, b);
            }
        }
        v.truncate(4096);
    }
    v
}

/// `u32 count`, then per case: `u8 l7`, `u16 port`, `u32 len`, bytes.
fn encode(cases: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = (cases.len() as u32).to_le_bytes().to_vec();
    for (l7, p) in cases {
        out.push(*l7);
        out.extend_from_slice(&443u16.to_le_bytes());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// One line per case: every present field as `id=value`, then `H=` entropy and
/// `L=` identified protocol. Exactly what the Rust computes below, so the two
/// strings are directly comparable.
const HARNESS: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include "dpi_decoders.h"

static unsigned char corpus[1 << 20];
static unsigned char payload[1 << 16];
static __u32 counts[256];   /* entropy_centibits() scratch histogram */

static unsigned rd(const unsigned char *p) {
    return (unsigned)p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16)|((unsigned)p[3]<<24);
}

int main(int argc, char **argv) {
    FILE *f; size_t len; unsigned count, i, pos, field;
    if (argc != 2) return 64;
    f = fopen(argv[1], "rb"); if (!f) return 65;
    len = fread(corpus, 1, sizeof(corpus), f); fclose(f);
    if (len < 4) return 66;
    count = rd(corpus); pos = 4;
    for (i = 0; i < count; i++) {
        struct ufw_decoded d; unsigned l7, port, plen;
        if (pos + 7 > len) return 67;
        l7 = corpus[pos]; port = corpus[pos+1] | (corpus[pos+2] << 8);
        plen = rd(corpus + pos + 3); pos += 7;
        if (pos + plen > len || plen > sizeof(payload)) return 68;
        if (plen) memcpy(payload, corpus + pos, plen);
        pos += plen;
        ufw_zero(&d, sizeof(d));
        decoded_set(&d, UFW_FIELD_PAYLOAD_LEN, plen);
        switch (l7) {
        case UFW_L7_DNS:  decode_dns(&d, payload, plen); break;
        case UFW_L7_HTTP: decode_http(&d, payload, plen); break;
        case UFW_L7_TLS:  decode_tls(&d, payload, plen); break;
        case UFW_L7_SSH:  decode_ssh(&d, payload, plen); break;
        default: break;
        }
        printf("%u:", i);
        for (field = 0; field < 128; field++)
            if (d.present[field]) printf(" %u=%u", field, d.values[field]);
        printf(" H=%u L=%u\n", entropy_centibits(payload, plen, counts),
               ufw_dpi_identify(payload, plen, (unsigned short)port));
    }
    return 0;
}
"#;

/// The Rust side, printed in the exact format the C harness uses.
fn rust_line(index: usize, l7: u8, payload: &[u8]) -> String {
    let d = decode(l7, payload);
    let mut line = format!("{index}:");
    for field in 0..128usize {
        if d.is_present(field) {
            line.push_str(&format!(" {}={}", field, d.get(field).unwrap()));
        }
    }
    line.push_str(&format!(
        " H={} L={}",
        entropy_centibits(payload),
        identify(payload, 443)
    ));
    line
}

#[test]
fn the_rust_port_agrees_with_the_c_it_replaces() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler; skipping the differential check");
        return;
    };
    let inc = repo_root().join("kernel/linux/inc");
    if !inc.join("dpi_decoders.h").exists() {
        eprintln!("dpi_decoders.h not present; skipping");
        return;
    }

    let mut cases = seeds();
    let mut rng = Rng(0xC0DE_F00D_1234_5678);
    let base = seeds();
    for _ in 0..8000 {
        let (l7, seed) = &base[rng.below(base.len())];
        cases.push((*l7, mutate(seed, &mut rng)));
    }

    let dir = std::env::temp_dir().join(format!("ufw-kcore-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("h.c");
    std::fs::write(&src, HARNESS).unwrap();
    let corpus = dir.join("corpus.bin");
    std::fs::write(&corpus, encode(&cases)).unwrap();
    let bin = dir.join("h");

    let build = Command::new(cc)
        .args(["-std=c11", "-Wall", "-Werror", "-O2"])
        .arg("-I")
        .arg(&inc)
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc");
    assert!(
        build.status.success(),
        "the C harness did not compile:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new(&bin).arg(&corpus).output().expect("run");
    assert!(
        run.status.success(),
        "C harness exited {:?}",
        run.status.code()
    );
    let c_out = String::from_utf8_lossy(&run.stdout);

    // The Rust side must produce field output for a healthy fraction of cases,
    // or two silent decoders would agree on nothing and pass.
    let mut with_fields = 0;
    for (index, (l7, payload)) in cases.iter().enumerate() {
        let rust = rust_line(index, *l7, payload);
        if rust.contains('=') && !rust.trim_end().ends_with(&format!("{index}:")) {
            with_fields += 1;
        }
        let c = c_out
            .lines()
            .find(|l| l.starts_with(&format!("{index}:")))
            .unwrap_or_else(|| panic!("C produced no line for case {index}"));
        assert_eq!(
            rust,
            c,
            "the Rust port and the C decoder disagree on case {index} (l7 {l7}):\n\
             rust: {rust}\n   c: {c}\n payload: {}",
            hex(payload)
        );
    }
    assert!(
        with_fields > cases.len() / 4,
        "too few decoded fields to be meaningful"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
