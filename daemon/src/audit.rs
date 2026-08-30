//! A tamper-evident audit log for the decisions that change what the firewall
//! does.
//!
//! The event log (`logging/`) answers "what traffic did we see"; it is high
//! volume and best-effort. This is a different, smaller log answering a
//! question an incident responder asks after the fact: *who changed the
//! enforcement, and was the record of it changed too?* Policy installs, mode
//! switches, contain actions, the fail-closed barrier, a license lapse — the
//! events that, if quietly deleted or edited by whoever got in, would erase the
//! evidence of how they got in.
//!
//! # The property, and its honest limit
//!
//! Each record carries the hash of the one before it, so the log is a chain: to
//! change record *n* you must recompute *n* and every record after it, or the
//! links stop matching. That makes any edit, reorder, insertion or
//! middle-deletion **detectable** to anyone holding the chain — [`verify_chain`]
//! finds the first break and names it.
//!
//! Hash-chaining alone does not stop an attacker who can rewrite the *whole*
//! tail from a point they control, because they can recompute the rest. Two
//! defences, both supported here and both stated plainly rather than implied:
//!
//!   * **A key.** With an HMAC key the chain is a MAC chain: an attacker without
//!     the key cannot produce a record whose MAC verifies, so they cannot
//!     rewrite the tail at all — *as long as the key is not also on the box they
//!     rooted.* On a single host it usually is, so the key raises the bar
//!     (an attacker must now also find the key) without being a wall.
//!
//!   * **An external anchor.** Truncating the tail — dropping the last N records
//!     — leaves a chain that is internally perfect. It is only detectable
//!     against a head captured elsewhere: shipped to a SIEM, printed to a
//!     console, mirrored to an append-only store. [`verify_against_head`] is
//!     that check; the daemon emits the head as an event so a remote sink holds
//!     it.
//!
//! So the guarantee is precise: **tamper-evidence, not tamper-proofing.** You
//! cannot keep a root attacker from deleting the file; you can keep them from
//! silently editing it and having the result look consistent to someone who
//! kept a copy of the head. That is the honest and useful property, and it is
//! the one this module delivers and tests.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use ufw_shared::hash::{self, constant_time_eq, hmac_sha256, sha256};
use ufw_shared::json::{self, Json, JsonWriter};

/// The genesis link: what record 0 chains back to. A fixed, domain-separated
/// constant so an empty log has a well-defined head and record 0's `prev` is
/// not attacker-chosen.
fn genesis() -> [u8; 32] {
    sha256(b"unified-firewall/audit/genesis/v1")
}

/// The kinds of change worth an audit record. The byte tag is part of the
/// hashed content, so it is stable on the wire — never renumber a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCategory {
    /// A policy was installed, reloaded, or rolled back.
    PolicyChange,
    /// Enforcement mode changed (enforce/monitor).
    ModeChange,
    /// A source was contained, or a containment expired/was lifted.
    Contain,
    /// The fail-closed barrier was installed or removed.
    FailSafe,
    /// A configuration change was applied.
    ConfigChange,
    /// A licensing state transition (activated, lapsed, reverted).
    License,
    /// A fleet bundle was accepted, rejected, or rolled back.
    Fleet,
}

impl AuditCategory {
    fn tag(self) -> u8 {
        match self {
            AuditCategory::PolicyChange => 1,
            AuditCategory::ModeChange => 2,
            AuditCategory::Contain => 3,
            AuditCategory::FailSafe => 4,
            AuditCategory::ConfigChange => 5,
            AuditCategory::License => 6,
            AuditCategory::Fleet => 7,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AuditCategory::PolicyChange => "policy-change",
            AuditCategory::ModeChange => "mode-change",
            AuditCategory::Contain => "contain",
            AuditCategory::FailSafe => "fail-safe",
            AuditCategory::ConfigChange => "config-change",
            AuditCategory::License => "license",
            AuditCategory::Fleet => "fleet",
        }
    }

    fn from_str(s: &str) -> Option<AuditCategory> {
        Some(match s {
            "policy-change" => AuditCategory::PolicyChange,
            "mode-change" => AuditCategory::ModeChange,
            "contain" => AuditCategory::Contain,
            "fail-safe" => AuditCategory::FailSafe,
            "config-change" => AuditCategory::ConfigChange,
            "license" => AuditCategory::License,
            "fleet" => AuditCategory::Fleet,
            _ => return None,
        })
    }
}

/// One link in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp_us: u64,
    pub category: AuditCategory,
    /// Who or what made the change (a role, a host id, "system").
    pub actor: String,
    /// What changed, in one line.
    pub detail: String,
    /// The hash of the previous record (genesis for record 0).
    pub prev: [u8; 32],
    /// This record's own hash over all the fields above.
    pub hash: [u8; 32],
}

/// Length-prefixed field append, so `("ab","c")` and `("a","bc")` never hash the
/// same — the ambiguity that would otherwise let two different records collide.
fn put_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// The hash (or MAC, when keyed) binding a record's content to its predecessor.
fn digest(
    key: Option<&[u8]>,
    seq: u64,
    timestamp_us: u64,
    category: AuditCategory,
    actor: &str,
    detail: &str,
    prev: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64 + actor.len() + detail.len());
    buf.extend_from_slice(b"UFWAUDIT1"); // domain + version separation
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&timestamp_us.to_be_bytes());
    buf.push(category.tag());
    put_lp(&mut buf, actor.as_bytes());
    put_lp(&mut buf, detail.as_bytes());
    buf.extend_from_slice(prev);
    match key {
        Some(k) => hmac_sha256(k, &buf),
        None => sha256(&buf),
    }
}

impl AuditRecord {
    /// Recompute this record's hash from its fields and the given key, and
    /// return whether it matches what the record claims. The comparison is
    /// constant-time so verification does not leak where a forged record first
    /// diverges.
    pub fn is_authentic(&self, key: Option<&[u8]>) -> bool {
        let expected = digest(
            key,
            self.seq,
            self.timestamp_us,
            self.category,
            &self.actor,
            &self.detail,
            &self.prev,
        );
        constant_time_eq(&expected, &self.hash)
    }

    /// Serialize to one canonical JSON line for the append-only file.
    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.begin_object();
        w.u64_field("seq", self.seq);
        w.u64_field("ts", self.timestamp_us);
        w.str_field("category", self.category.as_str());
        w.str_field("actor", &self.actor);
        w.str_field("detail", &self.detail);
        w.str_field("prev", &hash::hex(&self.prev));
        w.str_field("hash", &hash::hex(&self.hash));
        w.end_object();
        w.finish()
    }

    /// Parse one JSON line back into a record. Returns None on any missing or
    /// malformed field — a corrupt line is a chain break, surfaced by the
    /// verifier, not a panic.
    pub fn from_json(line: &str) -> Option<AuditRecord> {
        let v = json::parse(line).ok()?;
        let s = |k: &str| v.get(k).and_then(Json::as_str);
        let prev = to_32(&hash::unhex(s("prev")?)?)?;
        let hashv = to_32(&hash::unhex(s("hash")?)?)?;
        Some(AuditRecord {
            seq: v.get("seq").and_then(Json::as_u64)?,
            timestamp_us: v.get("ts").and_then(Json::as_u64)?,
            category: AuditCategory::from_str(s("category")?)?,
            actor: s("actor")?.to_string(),
            detail: s("detail")?.to_string(),
            prev,
            hash: hashv,
        })
    }
}

fn to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Some(a)
    } else {
        None
    }
}

/// The append-only, hash-chained audit log, backed by a file.
pub struct AuditLog {
    path: PathBuf,
    file: File,
    head: [u8; 32],
    next_seq: u64,
    key: Option<Vec<u8>>,
}

impl AuditLog {
    /// Open (or create) the log at `path`. An existing file is read and its
    /// chain verified; a break on load is returned as an error rather than
    /// silently continued, because appending onto a tampered chain would launder
    /// the tampering under fresh, valid links.
    pub fn open(path: impl AsRef<Path>, key: Option<Vec<u8>>) -> Result<AuditLog, String> {
        let path = path.as_ref().to_path_buf();
        let (head, next_seq) = if path.exists() {
            let records = read_records(&path)?;
            verify_chain(&records, key.as_deref()).map_err(|b| {
                format!(
                    "refusing to append to a tampered audit log: {}",
                    b.describe()
                )
            })?;
            match records.last() {
                Some(r) => (r.hash, r.seq + 1),
                None => (genesis(), 0),
            }
        } else {
            (genesis(), 0)
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("opening audit log {}: {e}", path.display()))?;
        Ok(AuditLog {
            path,
            file,
            head,
            next_seq,
            key,
        })
    }

    /// The current head hash — the value to export to a remote anchor so tail
    /// truncation becomes detectable.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn head_hex(&self) -> String {
        hash::hex(&self.head)
    }

    /// Append a record and persist it. Returns the record (with its hash), whose
    /// hash is the new head. Flushed before returning so a crash cannot lose an
    /// acknowledged audit entry.
    pub fn append(
        &mut self,
        category: AuditCategory,
        actor: impl Into<String>,
        detail: impl Into<String>,
        timestamp_us: u64,
    ) -> Result<AuditRecord, String> {
        let actor = actor.into();
        let detail = detail.into();
        let hash = digest(
            self.key.as_deref(),
            self.next_seq,
            timestamp_us,
            category,
            &actor,
            &detail,
            &self.head,
        );
        let record = AuditRecord {
            seq: self.next_seq,
            timestamp_us,
            category,
            actor,
            detail,
            prev: self.head,
            hash,
        };
        let mut line = record.to_json();
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.flush())
            .map_err(|e| format!("writing audit record to {}: {e}", self.path.display()))?;
        self.head = record.hash;
        self.next_seq += 1;
        Ok(record)
    }
}

/// Read and parse every record in a log file, in order.
pub fn read_records(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, String> {
    let f = File::open(path.as_ref())
        .map_err(|e| format!("opening {}: {e}", path.as_ref().display()))?;
    let mut records = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| format!("reading line {}: {e}", i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        match AuditRecord::from_json(&line) {
            Some(r) => records.push(r),
            None => return Err(format!("line {} is not a valid audit record", i + 1)),
        }
    }
    Ok(records)
}

/// The first inconsistency a verifier found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditBreak {
    /// Record `seq`'s hash does not match its content — it was edited (or the
    /// wrong key was supplied).
    ContentAltered { seq: u64 },
    /// Record `seq`'s `prev` does not point at the previous record's hash — a
    /// record was inserted, removed, or reordered here.
    ChainBroken { seq: u64 },
    /// The sequence numbers are not 0,1,2,… — a record is missing or duplicated.
    SequenceGap { expected: u64, found: u64 },
    /// The chain is internally consistent but its head is not the one a trusted
    /// anchor recorded — the tail was truncated (or extended and re-truncated).
    HeadMismatch,
    /// The log is empty where a record was expected.
    Empty,
}

impl AuditBreak {
    pub fn describe(&self) -> String {
        match self {
            AuditBreak::ContentAltered { seq } => {
                format!("record {seq} was altered (hash does not match its content)")
            }
            AuditBreak::ChainBroken { seq } => {
                format!("the chain is broken at record {seq} (prev link does not match)")
            }
            AuditBreak::SequenceGap { expected, found } => {
                format!(
                    "a record is missing or duplicated (expected seq {expected}, found {found})"
                )
            }
            AuditBreak::HeadMismatch => {
                "the log head does not match the trusted anchor — the tail was truncated".into()
            }
            AuditBreak::Empty => "the audit log is empty".into(),
        }
    }
}

/// Verify a chain's internal consistency: every record authentic, every link
/// intact, sequence numbers contiguous from zero. Detects edits, reordering,
/// insertions and middle-deletions; does *not* detect tail truncation (nothing
/// internal can) — use [`verify_against_head`] for that.
pub fn verify_chain(records: &[AuditRecord], key: Option<&[u8]>) -> Result<(), AuditBreak> {
    let mut expected_prev = genesis();
    for (i, r) in records.iter().enumerate() {
        let expected_seq = i as u64;
        if r.seq != expected_seq {
            return Err(AuditBreak::SequenceGap {
                expected: expected_seq,
                found: r.seq,
            });
        }
        if r.prev != expected_prev {
            return Err(AuditBreak::ChainBroken { seq: r.seq });
        }
        if !r.is_authentic(key) {
            return Err(AuditBreak::ContentAltered { seq: r.seq });
        }
        expected_prev = r.hash;
    }
    Ok(())
}

/// Verify the chain *and* that its final hash equals `expected_head` — the value
/// a trusted external anchor recorded. This is what turns "internally
/// consistent" into "nothing was dropped off the end".
pub fn verify_against_head(
    records: &[AuditRecord],
    key: Option<&[u8]>,
    expected_head: &[u8; 32],
) -> Result<(), AuditBreak> {
    verify_chain(records, key)?;
    let head = records.last().map(|r| r.hash).unwrap_or_else(genesis);
    if constant_time_eq(&head, expected_head) {
        Ok(())
    } else {
        Err(AuditBreak::HeadMismatch)
    }
}

/// A short human-readable summary of a log's state, for `ufwctl audit verify`.
pub fn summarize(records: &[AuditRecord]) -> String {
    let mut s = String::new();
    let _ = write!(s, "{} record(s)", records.len());
    if let Some(last) = records.last() {
        let _ = write!(
            s,
            ", head sha256:{}…, latest: [{}] {}",
            &hash::hex(&last.hash)[..16],
            last.category.as_str(),
            last.detail
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(key: Option<&[u8]>, entries: &[(AuditCategory, &str, &str)]) -> Vec<AuditRecord> {
        let mut head = genesis();
        let mut out = Vec::new();
        for (i, (cat, actor, detail)) in entries.iter().enumerate() {
            let seq = i as u64;
            let ts = 1_000 + seq;
            let hash = digest(key, seq, ts, *cat, actor, detail, &head);
            out.push(AuditRecord {
                seq,
                timestamp_us: ts,
                category: *cat,
                actor: (*actor).into(),
                detail: (*detail).into(),
                prev: head,
                hash,
            });
            head = hash;
        }
        out
    }

    fn sample() -> Vec<AuditRecord> {
        build(
            None,
            &[
                (AuditCategory::PolicyChange, "system", "installed base.yaml"),
                (AuditCategory::ModeChange, "admin", "monitor -> enforce"),
                (AuditCategory::Contain, "operator", "contained 203.0.113.9"),
            ],
        )
    }

    #[test]
    fn a_well_formed_chain_verifies() {
        assert_eq!(verify_chain(&sample(), None), Ok(()));
    }

    #[test]
    fn editing_a_record_is_detected() {
        let mut r = sample();
        r[1].detail = "monitor -> monitor".into(); // rewrite history, leave the hash
        assert_eq!(
            verify_chain(&r, None),
            Err(AuditBreak::ContentAltered { seq: 1 })
        );
    }

    #[test]
    fn deleting_a_middle_record_is_detected() {
        let mut r = sample();
        r.remove(1);
        // Reindexing seq to stay 0,1 would still break the prev link.
        r[1].seq = 1;
        assert!(matches!(
            verify_chain(&r, None),
            Err(AuditBreak::ChainBroken { .. }) | Err(AuditBreak::ContentAltered { .. })
        ));
    }

    #[test]
    fn reordering_is_detected() {
        let mut r = sample();
        r.swap(0, 1);
        assert!(verify_chain(&r, None).is_err());
    }

    #[test]
    fn tail_truncation_is_detected_only_against_a_head() {
        let full = sample();
        let anchor = full.last().unwrap().hash;
        let mut truncated = full.clone();
        truncated.pop();
        // Internally the truncated chain is still perfect...
        assert_eq!(verify_chain(&truncated, None), Ok(()));
        // ...and only the external head catches it.
        assert_eq!(
            verify_against_head(&truncated, None, &anchor),
            Err(AuditBreak::HeadMismatch)
        );
        assert_eq!(verify_against_head(&full, None, &anchor), Ok(()));
    }

    #[test]
    fn a_key_stops_forgery_without_it() {
        let key = b"audit-key".to_vec();
        let keyed = build(
            Some(&key),
            &[(AuditCategory::PolicyChange, "system", "installed")],
        );
        // With the key it verifies; without it, the MACs do not match.
        assert_eq!(verify_chain(&keyed, Some(&key)), Ok(()));
        assert_eq!(
            verify_chain(&keyed, None),
            Err(AuditBreak::ContentAltered { seq: 0 })
        );
        // An attacker who edits a record and recomputes the hash *without* the
        // key produces a record that fails keyed verification.
        let mut forged = keyed.clone();
        forged[0].detail = "installed evil.yaml".into();
        forged[0].hash = digest(
            None, // attacker lacks the key
            forged[0].seq,
            forged[0].timestamp_us,
            forged[0].category,
            &forged[0].actor,
            &forged[0].detail,
            &forged[0].prev,
        );
        assert_eq!(
            verify_chain(&forged, Some(&key)),
            Err(AuditBreak::ContentAltered { seq: 0 })
        );
    }

    #[test]
    fn records_round_trip_through_json() {
        for r in sample() {
            let line = r.to_json();
            assert_eq!(AuditRecord::from_json(&line), Some(r));
        }
    }

    #[test]
    fn a_file_backed_log_appends_and_reopens_without_a_break() {
        let dir = std::env::temp_dir().join(format!("ufw-audit-{}", ufw_shared::now_us()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        let mut log = AuditLog::open(&path, None).expect("open new");
        log.append(AuditCategory::PolicyChange, "system", "install base", 10)
            .unwrap();
        log.append(AuditCategory::ModeChange, "admin", "enforce", 20)
            .unwrap();
        let head_before = log.head();
        drop(log);

        // Reopen: the existing chain must verify, and the head must carry over.
        let log2 = AuditLog::open(&path, None).expect("reopen verifies");
        assert_eq!(log2.head(), head_before);

        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(verify_chain(&records, None), Ok(()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_a_tampered_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("ufw-audit-t-{}", ufw_shared::now_us()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        {
            let mut log = AuditLog::open(&path, None).unwrap();
            log.append(AuditCategory::PolicyChange, "system", "a", 1)
                .unwrap();
            log.append(AuditCategory::PolicyChange, "system", "b", 2)
                .unwrap();
        }
        // Corrupt the first line's detail without fixing the hash.
        let content = std::fs::read_to_string(&path).unwrap();
        let corrupted = content.replacen("\"a\"", "\"evil\"", 1);
        std::fs::write(&path, corrupted).unwrap();

        assert!(
            AuditLog::open(&path, None).is_err(),
            "appending onto a tampered log must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
