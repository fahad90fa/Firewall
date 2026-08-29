//! DNS tunnelling / exfiltration detector.
//!
//! DNS is the channel that is almost never blocked, which is exactly why it is a
//! favourite for data exfiltration and command-and-control: encode the payload
//! into the labels of a query for a domain you control, and every resolver on
//! the path forwards it for you. This detector scores DNS query names for the
//! two shapes that betray a tunnel:
//!
//!  1. **A single encoded blob** — one query whose payload labels are long and
//!     high-entropy, i.e. base32/base64/hex-encoded data rather than a hostname.
//!  2. **Chunked streaming** — many *distinct*, high-entropy sub-domains under a
//!     single parent domain from one source inside a window: the fan-out of a
//!     file being carried out one query at a time.
//!
//! It is deliberately conservative about false positives. A long but readable
//! hostname, a CDN's short sharded sub-domains (`img12.cdn.example`), and a
//! handful of normal look-ups all score low — the alert wants **length AND
//! entropy AND (for the chunked case) volume** together, because any one alone
//! is ordinary.
//!
//! State is bounded (a tracked-endpoint cap with a sliding window), so a flood
//! of parent domains cannot grow it without limit. It is fed decoded query names
//! (`dns.qname`, which the protocol decoder already extracts); it does not parse
//! packets itself.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::Decision;

/// Tuning for the DNS exfiltration detector. Thresholds are in the units the
/// detector measures: entropy in centibits/byte (100 = 1 bit/byte; random
/// base32 ≈ 500, English text ≈ 350–420), lengths in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExfilConfig {
    /// Sliding window over which chunks under one parent are counted.
    pub window_secs: u64,
    /// A payload label sequence at/above this length AND entropy is a
    /// single-query encoded blob on its own.
    pub single_blob_len: usize,
    pub single_blob_entropy: u32,
    /// A payload counts as a tunnelling *chunk* at/above this length and entropy.
    pub chunk_len: usize,
    pub chunk_entropy: u32,
    /// Distinct chunks under one parent, within the window, that mean tunnelling.
    pub chunk_threshold: usize,
    /// Parent domains tracked per source. Beyond the product with sources, LRU
    /// evicts.
    pub max_endpoints: usize,
    /// Minimum gap between alerts for the same (source, parent).
    pub realert_interval_secs: u64,
}

impl Default for DnsExfilConfig {
    fn default() -> Self {
        DnsExfilConfig {
            window_secs: 60,
            single_blob_len: 40,
            single_blob_entropy: 430,
            chunk_len: 16,
            chunk_entropy: 400,
            chunk_threshold: 30,
            max_endpoints: 8192,
            realert_interval_secs: 120,
        }
    }
}

/// Why the detector fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfilReason {
    /// One query carried an encoded blob.
    EncodedBlob,
    /// Many encoded chunks streamed under one parent domain.
    ChunkedTunnel,
}

/// A detected DNS exfiltration/tunnelling event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsExfilAlert {
    pub src: IpAddr,
    pub parent: String,
    pub reason: ExfilReason,
    /// The blob length (EncodedBlob) or the chunk count (ChunkedTunnel).
    pub metric: usize,
    pub entropy_centibits: u32,
    ts_us: u64,
}

impl DnsExfilAlert {
    pub fn to_event(&self, host_id: &str, sequence: u64) -> LogEvent {
        let mut event = LogEvent::new(
            self.ts_us,
            host_id,
            Decision::Allow,
            ufw_shared::constants::RULE_ID_DEFAULT,
            Default::default(),
        );
        event.sequence = sequence;
        event.kind = EventKind::Alert;
        event.severity = Severity::Warning;
        event.message = Some(match self.reason {
            ExfilReason::EncodedBlob => format!(
                "DNS exfiltration: {} queried a {}-byte high-entropy ({} cb/byte) label under `{}` \
                 — an encoded payload, not a hostname",
                self.src, self.metric, self.entropy_centibits, self.parent,
            ),
            ExfilReason::ChunkedTunnel => format!(
                "DNS tunnelling: {} sent {} distinct high-entropy sub-domains under `{}` in one \
                 window — the shape of chunked data exfiltration",
                self.src, self.metric, self.parent,
            ),
        });
        event.tags = vec!["exfil".into(), "dns-tunnel".into()];
        event
    }
}

/// Shannon entropy of `data`, in centibits per byte (0..=800). Empty is 0.
pub fn entropy_centibits(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut bits = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        bits -= p * p.log2();
    }
    (bits * 100.0).round() as u32
}

/// Split a query name into `(parent, payload)`: the parent is the last two
/// labels (the registrable endpoint, heuristically — not a full public-suffix
/// list), and the payload is everything to their left, concatenated. A name with
/// two or fewer labels has no payload.
fn split_qname(qname: &str) -> (String, Vec<u8>) {
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = q.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return (q, Vec::new());
    }
    let split = labels.len() - 2;
    let parent = labels[split..].join(".");
    let payload = labels[..split].concat().into_bytes();
    (parent, payload)
}

#[derive(Debug, Default)]
struct EndpointState {
    /// Distinct qualifying chunk hashes seen in the window, insertion-ordered.
    chunks: VecDeque<(u64, u64)>, // (ts_us, chunk_hash)
    seen: HashSet<u64>,
    last_seen_us: u64,
    last_alert_us: u64,
}

/// Per-(source, parent-domain) DNS exfiltration detector.
#[derive(Debug)]
pub struct DnsExfilDetector {
    config: DnsExfilConfig,
    endpoints: HashMap<(IpAddr, String), EndpointState>,
    alerts_raised: u64,
}

fn hash_bytes(b: &[u8]) -> u64 {
    // FNV-1a — stable, allocation-free, good enough for de-duplication.
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

impl DnsExfilDetector {
    pub fn new(config: DnsExfilConfig) -> Self {
        DnsExfilDetector {
            config,
            endpoints: HashMap::new(),
            alerts_raised: 0,
        }
    }

    pub fn tracked_endpoints(&self) -> usize {
        self.endpoints.len()
    }

    pub fn alerts_raised(&self) -> u64 {
        self.alerts_raised
    }

    /// Feed a decoded DNS query. Returns an alert on an encoded blob or once the
    /// chunk count under a parent crosses the tunnelling threshold.
    pub fn observe_query(
        &mut self,
        src: IpAddr,
        qname: &str,
        now_us: u64,
    ) -> Option<DnsExfilAlert> {
        let (parent, payload) = split_qname(qname);
        if payload.is_empty() {
            return None;
        }
        let entropy = entropy_centibits(&payload);
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        let realert_us = self.config.realert_interval_secs.saturating_mul(1_000_000);

        // A single query that is itself an encoded blob — decided before any
        // state, so it fires on the first packet.
        if payload.len() >= self.config.single_blob_len
            && entropy >= self.config.single_blob_entropy
        {
            let key = (src, parent.clone());
            let allow = self
                .endpoints
                .get(&key)
                .map(|s| {
                    s.last_alert_us == 0 || now_us.saturating_sub(s.last_alert_us) >= realert_us
                })
                .unwrap_or(true);
            self.evict_if_needed(now_us);
            let state = self.endpoints.entry(key).or_default();
            state.last_seen_us = now_us;
            if allow {
                state.last_alert_us = now_us;
                self.alerts_raised += 1;
                return Some(DnsExfilAlert {
                    src,
                    parent,
                    reason: ExfilReason::EncodedBlob,
                    metric: payload.len(),
                    entropy_centibits: entropy,
                    ts_us: now_us,
                });
            }
            return None;
        }

        // Otherwise, is this a tunnelling *chunk* worth accumulating?
        let is_chunk =
            payload.len() >= self.config.chunk_len && entropy >= self.config.chunk_entropy;

        self.evict_if_needed(now_us);
        let chunk_threshold = self.config.chunk_threshold;
        // Hard ceiling on distinct chunks retained per (source, parent) so a
        // tunnel streaming endless distinct labels cannot grow the window
        // without bound. Well above the alert threshold.
        let chunk_cap = chunk_threshold.saturating_mul(4).max(64);
        let key = (src, parent.clone());
        let state = self.endpoints.entry(key).or_default();
        state.last_seen_us = now_us;

        // Age out old chunks.
        while let Some(&(ts, h)) = state.chunks.front() {
            if now_us.saturating_sub(ts) > window_us {
                state.chunks.pop_front();
                state.seen.remove(&h);
            } else {
                break;
            }
        }

        if !is_chunk {
            return None;
        }
        let h = hash_bytes(&payload);
        if state.seen.insert(h) {
            state.chunks.push_back((now_us, h));
            while state.chunks.len() > chunk_cap {
                if let Some((_, old)) = state.chunks.pop_front() {
                    state.seen.remove(&old);
                } else {
                    break;
                }
            }
        } else {
            return None; // a repeated chunk adds no new fan-out
        }

        if state.chunks.len() >= chunk_threshold
            && (state.last_alert_us == 0
                || now_us.saturating_sub(state.last_alert_us) >= realert_us)
        {
            state.last_alert_us = now_us;
            let count = state.chunks.len();
            self.alerts_raised += 1;
            return Some(DnsExfilAlert {
                src,
                parent,
                reason: ExfilReason::ChunkedTunnel,
                metric: count,
                entropy_centibits: entropy,
                ts_us: now_us,
            });
        }
        None
    }

    pub fn expire(&mut self, now_us: u64) {
        let window_us = self.config.window_secs.saturating_mul(1_000_000);
        self.endpoints
            .retain(|_, s| now_us.saturating_sub(s.last_seen_us) <= window_us);
    }

    fn evict_if_needed(&mut self, now_us: u64) {
        if self.endpoints.len() < self.config.max_endpoints {
            return;
        }
        self.expire(now_us);
        while self.endpoints.len() >= self.config.max_endpoints {
            if let Some(victim) = self
                .endpoints
                .iter()
                .min_by_key(|(_, s)| s.last_seen_us)
                .map(|(k, _)| k.clone())
            {
                self.endpoints.remove(&victim);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000;

    fn src() -> IpAddr {
        "10.0.0.5".parse().unwrap()
    }

    // A base32-ish encoded chunk of `n` bytes — high entropy, tunnel-shaped.
    fn encoded(seed: u64, n: usize) -> String {
        const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut s = String::new();
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        for _ in 0..n {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            s.push(A[(x % 32) as usize] as char);
        }
        s
    }

    #[test]
    fn chunked_tunnel_fires() {
        let mut d = DnsExfilDetector::new(DnsExfilConfig::default());
        let mut fired = None;
        for i in 0..30u64 {
            let q = format!(
                "{}.{}.tunnel.evil.com",
                encoded(i, 24),
                encoded(i + 1000, 8)
            );
            fired = d.observe_query(src(), &q, 10 * SEC);
        }
        let a = fired.expect("30 distinct high-entropy sub-domains is a tunnel");
        assert_eq!(a.reason, ExfilReason::ChunkedTunnel);
        assert_eq!(a.parent, "evil.com");
        assert!(a.metric >= 30);
    }

    #[test]
    fn single_encoded_blob_fires_immediately() {
        let mut d = DnsExfilDetector::new(DnsExfilConfig::default());
        let q = format!("{}.exfil.evil.com", encoded(7, 50));
        let a = d
            .observe_query(src(), &q, 10 * SEC)
            .expect("a 50-byte high-entropy label is an encoded blob");
        assert_eq!(a.reason, ExfilReason::EncodedBlob);
        assert!(a.metric >= 50);
    }

    #[test]
    fn ordinary_lookups_do_not_fire() {
        let mut d = DnsExfilDetector::new(DnsExfilConfig::default());
        for q in [
            "www.google.com",
            "api.github.com",
            "mail.example.org",
            "cdn.jsdelivr.net",
            "login.microsoftonline.com",
            "s3.amazonaws.com",
        ] {
            assert!(
                d.observe_query(src(), q, 10 * SEC).is_none(),
                "{q} must be clean"
            );
        }
        assert_eq!(d.alerts_raised(), 0);
    }

    #[test]
    fn cdn_shards_and_long_readable_names_do_not_fire() {
        let mut d = DnsExfilDetector::new(DnsExfilConfig::default());
        // Many short, low-entropy shards under one parent — a CDN, not a tunnel.
        for i in 0..60 {
            let q = format!("img{i}.static.cdn-example.com");
            assert!(d.observe_query(src(), &q, 10 * SEC).is_none());
        }
        // A long but readable hostname.
        let q = "this-is-a-very-long-but-perfectly-readable-hostname.example.com";
        assert!(d.observe_query(src(), q, 10 * SEC).is_none());
        assert_eq!(d.alerts_raised(), 0);
    }

    #[test]
    fn a_slow_trickle_below_threshold_does_not_fire() {
        let mut d = DnsExfilDetector::new(DnsExfilConfig::default());
        // Only 10 chunks — below the 30 threshold — even if high entropy.
        let mut any = None;
        for i in 0..10u64 {
            let q = format!("{}.t.evil.com", encoded(i, 24));
            any = d.observe_query(src(), &q, 10 * SEC);
        }
        assert!(any.is_none());
    }

    #[test]
    fn entropy_separates_encoded_from_english() {
        // Random base32 is high-entropy; a readable word is not.
        assert!(entropy_centibits(encoded(1, 40).as_bytes()) >= 430);
        assert!(entropy_centibits(b"marketingnewsletter") < 430);
    }
}
