//! Real-traffic **pcap** efficacy harness for the WAF.
//!
//! `waf_efficacy.rs` measures the WAF against requests authored in-memory. This
//! harness closes the last gap named in `docs/design/detection-efficacy.md`: it
//! ingests actual **captured `.pcap` files**, reassembles the TCP payloads,
//! extracts the HTTP requests, runs them through the real `WafEngine`, and prints
//! a confusion matrix. Point it at an independent labeled corpus and it produces
//! the honest "catch X% at Y% false-positive" number that self-authored requests
//! cannot.
//!
//! ## Usage
//!
//! - **In CI (self-test):** the `pcap_reader_roundtrips_real_capture_bytes` test
//!   writes a handful of *real pcap-format* captures to a temp dir (a SQLi POST,
//!   a clean GET, …), parses them back through the same reader a live capture
//!   would use, and asserts the WAF scores them correctly. This proves the
//!   pcap → Ethernet → IPv4 → TCP → HTTP → WAF pipeline actually works on wire
//!   bytes, not just that a parser compiles.
//! - **Against a real dataset:** set `UFW_PCAP_DIR=/path/to/pcaps` and run with
//!   `--nocapture`. Files are labeled by name prefix: `mal_*`.pcap = malicious,
//!   `ben_*`.pcap = benign (anything else is scored but not counted). The harness
//!   prints catch-rate + false-positive rate over whatever real captures you drop
//!   in — e.g. the web-attack pcaps from CIC-IDS2017 or malware-traffic-analysis.net.
//!
//! Scope is deliberately the HTTP/WAF path (where a measured number already
//! exists to compare against); the same flow extractor could feed the DNS-exfil
//! and behavioral detectors, which is left as a documented extension.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ufw_daemon::signatures;
use ufw_daemon::waf::WafEngine;

// ---------------------------------------------------------------------------
// Minimal classic-pcap reader: file -> per-flow reassembled TCP payloads.
// ---------------------------------------------------------------------------

/// A reassembled TCP flow: the concatenated payload bytes in capture order.
#[derive(Default)]
struct Flow {
    payload: Vec<u8>,
}

/// (src_ip, src_port, dst_ip, dst_port) — the flow's identity.
type FlowKey = (u32, u16, u32, u16);

fn u16be(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}
fn u32be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}
fn u32le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
}

/// Parse a classic `.pcap` byte buffer and return each TCP flow's reassembled
/// payload, keyed by (src, sport, dst, dport). Best-effort and bounds-checked:
/// anything malformed is skipped, never panics — the same discipline the live
/// parsers use. Supports Ethernet (LINKTYPE 1) and raw IPv4 (101); IPv4 only.
fn flows_from_pcap(bytes: &[u8]) -> BTreeMap<FlowKey, Flow> {
    let mut flows: BTreeMap<FlowKey, Flow> = BTreeMap::new();
    if bytes.len() < 24 {
        return flows;
    }
    // Global header: magic tells endianness; byte-swapped magic = big-endian.
    let magic = u32le(&bytes[0..4]);
    let (le, _nano) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xd4c3_b2a1 => (false, false),
        0xa1b2_3c4d => (true, true),
        0x4d3c_b2a1 => (false, true),
        _ => return flows,
    };
    let rd32 = |b: &[u8]| if le { u32le(b) } else { u32be(b) };
    let linktype = rd32(&bytes[20..24]);
    let mut pos = 24usize;
    while pos + 16 <= bytes.len() {
        let incl_len = rd32(&bytes[pos + 8..pos + 12]) as usize;
        pos += 16;
        if pos + incl_len > bytes.len() {
            break;
        }
        let frame = &bytes[pos..pos + incl_len];
        pos += incl_len;
        if let Some((key, payload)) = tcp_from_frame(linktype, frame) {
            flows
                .entry(key)
                .or_default()
                .payload
                .extend_from_slice(payload);
        }
    }
    flows
}

/// Pull the (flow-key, tcp-payload) out of one link-layer frame, or None.
fn tcp_from_frame(linktype: u32, frame: &[u8]) -> Option<(FlowKey, &[u8])> {
    // Locate the IPv4 header.
    let ip = match linktype {
        1 => {
            // Ethernet II: dst6 src6 ethertype2, with optional 802.1Q VLAN tags.
            if frame.len() < 14 {
                return None;
            }
            let mut off = 12;
            let mut ethertype = u16be(&frame[off..off + 2]);
            off += 2;
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if frame.len() < off + 4 {
                    return None;
                }
                ethertype = u16be(&frame[off + 2..off + 4]);
                off += 4;
            }
            if ethertype != 0x0800 {
                return None; // not IPv4
            }
            &frame[off..]
        }
        101 => frame, // raw IPv4
        _ => return None,
    };
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != 6 {
        return None; // not TCP
    }
    let src = u32be(&ip[12..16]);
    let dst = u32be(&ip[16..20]);
    let total_len = u16be(&ip[2..4]) as usize;
    let ip_end = total_len.min(ip.len());
    let tcp = ip.get(ihl..ip_end)?;
    if tcp.len() < 20 {
        return None;
    }
    let sport = u16be(&tcp[0..2]);
    let dport = u16be(&tcp[2..4]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if data_off < 20 || tcp.len() < data_off {
        return None;
    }
    let payload = &tcp[data_off..];
    if payload.is_empty() {
        return None;
    }
    Some(((src, sport, dst, dport), payload))
}

/// Does this reassembled payload begin with an HTTP request line?
fn looks_like_http_request(p: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    METHODS.iter().any(|m| p.starts_with(m))
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Confusion {
    tp: u32,
    fn_: u32,
    fp: u32,
    tn: u32,
}

impl Confusion {
    fn record(&mut self, malicious: bool, flagged: bool) {
        match (malicious, flagged) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }
}

fn engine() -> WafEngine {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("sig-rules");
    let (set, errors) = signatures::load_dir(&root);
    assert!(errors.is_empty(), "sig-rules failed to load: {errors:#?}");
    WafEngine::new(Arc::new(set))
}

/// Run every HTTP request in a pcap through the WAF. Returns (flagged_any,
/// http_requests_seen): a capture is "flagged" if any HTTP request in it fires.
fn score_pcap(engine: &WafEngine, bytes: &[u8]) -> (bool, usize) {
    let mut flagged = false;
    let mut seen = 0usize;
    for (_key, flow) in flows_from_pcap(bytes) {
        // A flow may carry pipelined requests; inspect the reassembled buffer,
        // which is what the WAF's content + normalized scan already handles.
        if looks_like_http_request(&flow.payload) {
            seen += 1;
            if engine.inspect(&flow.payload).is_some() {
                flagged = true;
            }
        }
    }
    (flagged, seen)
}

/// Build a minimal but *valid* classic-pcap capturing one HTTP request over
/// Ethernet/IPv4/TCP — real wire bytes the reader above must accept.
fn synth_pcap(http: &[u8]) -> Vec<u8> {
    // TCP header (20 bytes), ports 12345 -> 80, data offset 5 (<<4 = 0x50).
    let mut tcp = vec![
        0x30, 0x39, 0x00, 0x50, // sport 12345, dport 80
        0, 0, 0, 1, // seq
        0, 0, 0, 0, // ack
        0x50, 0x18, 0xff, 0xff, // data offset 5, flags PSH|ACK, window
        0, 0, 0, 0, // checksum (0), urgent
    ];
    tcp.extend_from_slice(http);

    // IPv4 header (20 bytes), protocol 6 (TCP).
    let total_len = (20 + tcp.len()) as u16;
    let mut ip = vec![
        0x45,
        0x00, // version/IHL, DSCP
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0, // id, flags, ttl, proto=6, checksum=0
        10,
        0,
        0,
        1, // src 10.0.0.1
        10,
        0,
        0,
        2, // dst 10.0.0.2
    ];
    ip.extend_from_slice(&tcp);

    // Ethernet II header (14 bytes), ethertype 0x0800.
    let mut frame = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00];
    frame.extend_from_slice(&ip);

    // pcap global header (LE, LINKTYPE_ETHERNET=1) + one record.
    let mut out = vec![
        0xd4, 0xc3, 0xb2, 0xa1, // magic (LE)
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // thiszone, sigfigs
        0xff, 0xff, 0, 0, // snaplen 65535
        0x01, 0x00, 0x00, 0x00, // network = 1 (ethernet)
    ];
    let l = frame.len() as u32;
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // ts_sec, ts_usec
    out.extend_from_slice(&l.to_le_bytes()); // incl_len
    out.extend_from_slice(&l.to_le_bytes()); // orig_len
    out.extend_from_slice(&frame);
    out
}

#[test]
fn pcap_reader_roundtrips_real_capture_bytes() {
    let e = engine();

    // Malicious HTTP requests, as real pcap captures.
    let sqli = synth_pcap(b"GET /items?id=1' or 1=1-- HTTP/1.1\r\nHost: shop\r\n\r\n");
    let xss = synth_pcap(b"GET /q?x=<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n");
    let (f1, n1) = score_pcap(&e, &sqli);
    let (f2, _) = score_pcap(&e, &xss);
    assert!(
        n1 >= 1,
        "the reader must recover the HTTP request from pcap bytes"
    );
    assert!(f1, "a SQLi request captured in a pcap must be flagged");
    assert!(f2, "an XSS request captured in a pcap must be flagged");

    // Benign request must not flag.
    let clean = synth_pcap(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let (f3, n3) = score_pcap(&e, &clean);
    assert_eq!(n3, 1);
    assert!(!f3, "a clean GET captured in a pcap must not be flagged");

    // A capture with no HTTP (bare TCP payload) yields no requests.
    let non_http = synth_pcap(b"\x16\x03\x01\x00\x2f binary tls-ish bytes");
    let (_f4, n4) = score_pcap(&e, &non_http);
    assert_eq!(n4, 0, "non-HTTP payloads are not counted as requests");
}

/// Real-dataset run: `UFW_PCAP_DIR=/path cargo test -p ufw-daemon --test
/// pcap_efficacy -- --nocapture`. Labeled by filename prefix mal_/ben_.
#[test]
fn measure_against_real_pcap_corpus() {
    let Ok(dir) = std::env::var("UFW_PCAP_DIR") else {
        eprintln!(
            "UFW_PCAP_DIR not set — skipping the real-corpus run. Point it at labeled \
             pcaps (mal_*.pcap / ben_*.pcap), e.g. CIC-IDS2017 web-attack captures."
        );
        return;
    };
    let e = engine();
    let mut c = Confusion::default();
    let mut files = 0u32;
    let mut requests = 0usize;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("cannot read UFW_PCAP_DIR={dir}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|x| x == "pcap" || x == "pcapng")
                .unwrap_or(false)
        })
        .collect();
    entries.sort();

    for path in &entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let malicious = if name.starts_with("mal_") {
            true
        } else if name.starts_with("ben_") {
            false
        } else {
            continue; // unlabeled: score-neutral
        };
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let (flagged, seen) = score_pcap(&e, &bytes);
        files += 1;
        requests += seen;
        c.record(malicious, flagged);
    }

    let catch = if c.tp + c.fn_ > 0 {
        c.tp as f64 / (c.tp + c.fn_) as f64
    } else {
        f64::NAN
    };
    let fp = if c.fp + c.tn > 0 {
        c.fp as f64 / (c.fp + c.tn) as f64
    } else {
        f64::NAN
    };
    println!("\nWAF efficacy over real pcap corpus ({dir}):");
    println!("  {files} labeled captures, {requests} HTTP requests inspected");
    println!("  TP={} FN={} FP={} TN={}", c.tp, c.fn_, c.fp, c.tn);
    println!(
        "  catch-rate={:.1}%  false-positive-rate={:.1}%",
        catch * 100.0,
        fp * 100.0
    );
    println!(
        "  (this is the honest independent-corpus number; the in-repo waf_efficacy.rs \
         reports 89.7%/0% on an authored corpus.)"
    );
    assert!(files > 0, "no mal_/ben_ prefixed pcaps found under {dir}");
}
