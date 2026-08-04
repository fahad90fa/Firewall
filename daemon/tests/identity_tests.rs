//! Identity resolution and trust classification, end to end.
//!
//! The platform resolvers are unit-tested against fixture trees; these cover
//! the service around them — caching, TTL, trust-database changes — and the
//! trust *decisions*, which are the part a policy actually depends on.

use std::sync::Arc;

use ufw_daemon::identity::{IdentityResolver, IdentityService, ResolverOptions, TrustDatabase};
use ufw_shared::identity_types::TrustMask;
use ufw_shared::identity_types::{AppIdentity, IdentityQuery, SignatureType, TrustLevel};
use ufw_shared::policy_types::{AppFingerprint, AppMatch, PathPattern};

/// A resolver that reports whatever the test set up for a pid, and counts how
/// often it was asked.
#[derive(Debug, Default)]
struct ScriptedResolver {
    calls: std::sync::atomic::AtomicU32,
    answers: std::sync::Mutex<std::collections::HashMap<u32, AppIdentity>>,
}

impl ScriptedResolver {
    fn set(&self, pid: u32, identity: AppIdentity) {
        self.answers.lock().unwrap().insert(pid, identity);
    }

    fn calls(&self) -> u32 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl IdentityResolver for ScriptedResolver {
    fn resolve(&self, query: &IdentityQuery, trust: &TrustDatabase) -> AppIdentity {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut identity = self
            .answers
            .lock()
            .unwrap()
            .get(&query.pid)
            .cloned()
            .unwrap_or_else(|| AppIdentity::unresolved(query.pid, ufw_shared::now_us()));
        identity.start_time_us = query.start_time_us;
        identity.trust = trust.classify(
            identity.signature_type,
            identity.signature_valid,
            identity.sha256.as_ref(),
            identity.team_id.as_deref(),
            identity.signer.as_deref(),
            TrustLevel::Known,
        );
        identity
    }

    fn name(&self) -> &'static str {
        "scripted"
    }
}

fn signed(pid: u32, path: &str, signer: &str) -> AppIdentity {
    let mut id = AppIdentity::unresolved(pid, ufw_shared::now_us());
    id.path = path.into();
    id.signature_type = SignatureType::Authenticode;
    id.signature_valid = true;
    id.signer = Some(signer.into());
    id.sha256 = Some(ufw_shared::hash::sha256(path.as_bytes()));
    id
}

fn query(pid: u32, start: u64) -> IdentityQuery {
    IdentityQuery {
        pid,
        start_time_us: start,
        hint_path: None,
        platform_token: Vec::new(),
    }
}

fn service(resolver: Arc<ScriptedResolver>, anchors: &[(String, TrustLevel)]) -> IdentityService {
    struct Shared(Arc<ScriptedResolver>);
    impl IdentityResolver for Shared {
        fn resolve(&self, q: &IdentityQuery, t: &TrustDatabase) -> AppIdentity {
            self.0.resolve(q, t)
        }
        fn name(&self) -> &'static str {
            "scripted"
        }
    }
    IdentityService::new(
        Box::new(Shared(resolver)),
        TrustDatabase::from_entries(anchors),
        ResolverOptions {
            ttl_secs: 60,
            ..Default::default()
        },
        64,
    )
}

#[test]
fn a_repeat_query_for_a_live_process_is_served_from_the_cache() {
    let resolver = Arc::new(ScriptedResolver::default());
    resolver.set(100, signed(100, "/usr/bin/app", "Contoso Ltd"));
    let s = service(Arc::clone(&resolver), &[]);

    let first = s.answer(&query(100, 5_000));
    let second = s.answer(&query(100, 5_000));
    assert_eq!(first, second);
    assert_eq!(resolver.calls(), 1, "the second query must not re-resolve");
    assert_eq!(s.cache_stats().hits, 1);
}

#[test]
fn a_recycled_pid_gets_its_own_identity() {
    let resolver = Arc::new(ScriptedResolver::default());
    resolver.set(100, signed(100, "/usr/bin/first", "Contoso Ltd"));
    let s = service(Arc::clone(&resolver), &[]);

    let first = s.answer(&query(100, 5_000));
    assert_eq!(first.path, "/usr/bin/first");

    // Same pid, later start time: a different process entirely.
    resolver.set(100, signed(100, "/tmp/second", "Nobody"));
    let second = s.answer(&query(100, 9_000));
    assert_eq!(second.path, "/tmp/second");
    assert_eq!(resolver.calls(), 2);
}

#[test]
fn changing_the_trust_database_re_resolves_affected_identities() {
    let resolver = Arc::new(ScriptedResolver::default());
    resolver.set(100, signed(100, "/usr/bin/app", "Contoso Ltd"));
    let s = service(Arc::clone(&resolver), &[]);

    // No anchor: a valid signature from an unlisted publisher is `known`.
    assert_eq!(s.answer(&query(100, 1)).trust, TrustLevel::Known);

    let mut db = TrustDatabase::new();
    db.insert("Contoso Ltd", TrustLevel::Trusted);
    s.set_trust(db);

    // The cached answer must not survive a trust change that would alter it.
    assert_eq!(s.answer(&query(100, 1)).trust, TrustLevel::Trusted);
    assert_eq!(resolver.calls(), 2);
}

#[test]
fn trust_classification_covers_the_cases_a_policy_relies_on() {
    let resolver = Arc::new(ScriptedResolver::default());
    let anchors = vec![
        ("Contoso Ltd".to_string(), TrustLevel::Trusted),
        ("Microsoft Corporation".to_string(), TrustLevel::System),
    ];
    let s = service(Arc::clone(&resolver), &anchors);

    // A validly signed, anchored publisher.
    resolver.set(1, signed(1, "/usr/bin/a", "Contoso Ltd"));
    assert_eq!(s.answer(&query(1, 1)).trust, TrustLevel::Trusted);

    // A validly signed publisher with no anchor.
    resolver.set(2, signed(2, "/usr/bin/b", "Someone Else"));
    assert_eq!(s.answer(&query(2, 1)).trust, TrustLevel::Known);

    // A signature that exists and fails: worse than unsigned, because it is
    // evidence of tampering.
    let mut tampered = signed(3, "/usr/bin/c", "Contoso Ltd");
    tampered.signature_valid = false;
    resolver.set(3, tampered);
    assert_eq!(s.answer(&query(3, 1)).trust, TrustLevel::Untrusted);

    // Unsigned.
    let mut unsigned = AppIdentity::unresolved(4, ufw_shared::now_us());
    unsigned.path = "/tmp/dropper".into();
    unsigned.signature_type = SignatureType::None;
    resolver.set(4, unsigned);
    assert_eq!(s.answer(&query(4, 1)).trust, TrustLevel::Unknown);

    // Nothing known at all.
    assert_eq!(s.answer(&query(9999, 1)).trust, TrustLevel::Unknown);
}

#[test]
fn an_unresolvable_process_is_untrusted_not_merely_unknown() {
    // The resolver's own fallback, without the scripted classification, is
    // what a real resolver returns when it cannot inspect a process.
    let id = AppIdentity::unresolved(1234, ufw_shared::now_us());
    assert_eq!(id.trust, TrustLevel::Untrusted);
    assert_eq!(id.signature_type, SignatureType::Indeterminate);
}

#[test]
fn a_resolved_identity_drives_the_policy_predicate_it_was_written_for() {
    // The point of all of this: the identity a resolver produces has to
    // satisfy the predicate a policy compiled from an `applications:` block.
    let resolver = Arc::new(ScriptedResolver::default());
    let s = service(
        Arc::clone(&resolver),
        &[("Contoso Ltd".to_string(), TrustLevel::Trusted)],
    );
    resolver.set(7, signed(7, "/usr/lib/contoso/browser", "Contoso Ltd"));
    let identity = s.answer(&query(7, 1));

    let predicate = AppMatch {
        fingerprints: vec![
            AppFingerprint {
                paths: vec![PathPattern::new(r"C:\Contoso\browser.exe", true)],
                signers: vec!["Contoso Ltd".into()],
                ..Default::default()
            },
            AppFingerprint {
                paths: vec![PathPattern::new("/usr/lib/contoso/*", false)],
                ..Default::default()
            },
        ],
        trust: TrustMask::at_least(TrustLevel::Trusted),
        require_valid_signature: true,
        negate: false,
    };
    assert!(
        predicate.matches(Some(&identity)),
        "the Linux fingerprint should match without the Windows signer requirement"
    );

    // Downgrade the trust anchor and the same identity stops matching.
    s.set_trust(TrustDatabase::new());
    let downgraded = s.answer(&query(7, 1));
    assert_eq!(downgraded.trust, TrustLevel::Known);
    assert!(!predicate.matches(Some(&downgraded)));
}

#[test]
fn the_cache_stays_within_its_capacity_under_churn() {
    let resolver = Arc::new(ScriptedResolver::default());
    let s = service(Arc::clone(&resolver), &[]);
    for pid in 0..1000u32 {
        resolver.set(pid, signed(pid, "/usr/bin/x", "Contoso Ltd"));
        s.answer(&query(pid, pid as u64 + 1));
    }
    let stats = s.cache_stats();
    assert!(stats.entries <= stats.capacity, "{stats:?}");
    assert!(stats.evictions > 0);
}

#[test]
fn concurrent_queries_are_safe_and_share_the_cache() {
    let resolver = Arc::new(ScriptedResolver::default());
    for pid in 0..16u32 {
        resolver.set(pid, signed(pid, "/usr/bin/x", "Contoso Ltd"));
    }
    let s = Arc::new(service(Arc::clone(&resolver), &[]));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = Arc::clone(&s);
        handles.push(std::thread::spawn(move || {
            for pid in 0..16u32 {
                let id = s.answer(&query(pid, pid as u64 + 1));
                assert_eq!(id.pid, pid);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker");
    }

    // 8 threads x 16 pids = 128 lookups. The cache does not suppress
    // duplicate concurrent resolutions of the same key -- two threads that
    // miss at the same moment both resolve, and the second simply overwrites
    // the first with an identical answer. Single-flight would mean holding a
    // lock across a resolution that reads and hashes a file, which is exactly
    // the thing that must not block the connection path. So the invariant is
    // "far fewer resolutions than lookups", not "at most one per key".
    let stats = s.cache_stats();
    assert!(
        resolver.calls() < 128,
        "the cache did nothing: {} resolutions for 128 lookups",
        resolver.calls()
    );
    assert!(stats.hits > 0, "no lookup was served from the cache");
    assert!(stats.entries <= 16);
}
