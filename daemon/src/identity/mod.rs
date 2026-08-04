//! Application identity resolution and caching.
//!
//! The kernel modules can see *that* a process opened a socket. They cannot
//! afford to verify a certificate chain in a packet path, and on two of the
//! three platforms they could not do it at all. So identity resolution lives
//! here: the module asks, the daemon answers, and both sides cache the answer.
//!
//! # The cache key is not the pid
//!
//! Process ids are recycled. A cache keyed on pid alone will, eventually, hand
//! a freshly-spawned process the identity of a dead one — and on a busy host
//! "eventually" is not long. Entries are therefore keyed on
//! `(pid, start_time_us)`: the pair is unique for the lifetime of the system,
//! so pid reuse produces a miss rather than a wrong answer.
//!
//! # Failing closed
//!
//! Resolution can fail: the process exited between the query and the answer,
//! the binary is unreadable, the signature blob is malformed. Every one of
//! those returns [`AppIdentity::unresolved`], which is `Untrusted` — strictly
//! worse than `Unknown`, which is what an *unsigned but readable* binary gets.
//! An attacker who can make resolution fail therefore gains nothing.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use ufw_shared::identity_types::{AppIdentity, IdentityQuery, SignatureType, TrustLevel};
use ufw_shared::{hash, now_us};

pub mod linux;
pub mod macos;
pub mod windows;

/// Platform-specific identity resolution.
pub trait IdentityResolver: Send + Sync {
    /// Resolve a process to an identity. Implementations return
    /// [`AppIdentity::unresolved`] rather than an error when the process
    /// cannot be inspected.
    fn resolve(&self, query: &IdentityQuery, trust: &TrustDatabase) -> AppIdentity;

    /// Name of the resolver, for diagnostics.
    fn name(&self) -> &'static str;
}

/// Build the resolver for the host platform.
pub fn platform_resolver(options: ResolverOptions) -> Box<dyn IdentityResolver> {
    #[cfg(target_os = "windows")]
    {
        return Box::new(windows::WindowsResolver::new(options));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return Box::new(linux::LinuxResolver::new(options));
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return Box::new(macos::MacOsResolver::new(options));
    }
    #[allow(unreachable_code)]
    {
        Box::new(NullResolver::new(options))
    }
}

/// Options every platform resolver honours.
#[derive(Debug, Clone)]
pub struct ResolverOptions {
    /// Executables larger than this are not hashed. Hashing a 2 GiB binary in
    /// the path of a connection attempt is not a trade anyone wants; the
    /// identity simply carries no `sha256` and hash-constrained rules cannot
    /// match it.
    pub max_hash_bytes: u64,
    /// Trust assigned to a validly-signed binary whose signer is not in the
    /// trust database.
    pub default_signed_trust: TrustLevel,
    /// Time-to-live stamped on resolved identities.
    pub ttl_secs: u64,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        ResolverOptions {
            max_hash_bytes: 256 * 1024 * 1024,
            default_signed_trust: TrustLevel::Known,
            ttl_secs: ufw_shared::constants::IDENTITY_CACHE_TTL_SECS,
        }
    }
}

/// A resolver for hosts with no platform backend. Everything is untrusted,
/// which is the only safe answer when nothing can be verified.
#[derive(Debug)]
pub struct NullResolver {
    options: ResolverOptions,
}

impl NullResolver {
    pub fn new(options: ResolverOptions) -> Self {
        NullResolver { options }
    }

    pub fn options(&self) -> &ResolverOptions {
        &self.options
    }
}

impl IdentityResolver for NullResolver {
    fn resolve(&self, query: &IdentityQuery, _trust: &TrustDatabase) -> AppIdentity {
        AppIdentity::unresolved(query.pid, now_us())
    }

    fn name(&self) -> &'static str {
        "null"
    }
}

// ===========================================================================
// Trust database
// ===========================================================================

/// Maps signers, Team IDs and specific binaries to trust levels.
///
/// Lookup order is most specific first: an exact binary hash beats a Team ID,
/// which beats a signer name. That ordering is what lets an operator pin one
/// build of an application without loosening the rule for everything else the
/// same publisher signs.
#[derive(Debug, Default)]
pub struct TrustDatabase {
    by_hash: HashMap<[u8; 32], TrustLevel>,
    by_team_id: HashMap<String, TrustLevel>,
    /// Signer names, lowercased for case-insensitive comparison.
    by_signer: HashMap<String, TrustLevel>,
}

impl TrustDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from configuration entries of the form `subject = level`.
    ///
    /// A subject that parses as a 64-character hex digest (optionally
    /// `sha256:`-prefixed) is a binary hash; one that looks like an Apple Team
    /// ID is a Team ID; anything else is a signer name.
    pub fn from_entries(entries: &[(String, TrustLevel)]) -> Self {
        let mut db = TrustDatabase::new();
        for (subject, level) in entries {
            db.insert(subject, *level);
        }
        db
    }

    pub fn insert(&mut self, subject: &str, level: TrustLevel) {
        if let Some(digest) = hash::parse_sha256(subject) {
            self.by_hash.insert(digest, level);
        } else if is_team_id(subject) {
            self.by_team_id.insert(subject.to_string(), level);
        } else {
            self.by_signer.insert(subject.to_ascii_lowercase(), level);
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len() + self.by_team_id.len() + self.by_signer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Trust level for an identity, or `None` when nothing matches.
    pub fn lookup(
        &self,
        sha256: Option<&[u8; 32]>,
        team_id: Option<&str>,
        signer: Option<&str>,
    ) -> Option<TrustLevel> {
        if let Some(h) = sha256 {
            if let Some(l) = self.by_hash.get(h) {
                return Some(*l);
            }
        }
        if let Some(t) = team_id {
            if let Some(l) = self.by_team_id.get(t) {
                return Some(*l);
            }
        }
        if let Some(s) = signer {
            if let Some(l) = self.by_signer.get(&s.to_ascii_lowercase()) {
                return Some(*l);
            }
        }
        None
    }

    /// Decide the trust level of a resolved identity.
    ///
    /// The database can only ever be consulted for a *validly signed* binary.
    /// Trusting an unverified signer string would let anyone claim to be
    /// Microsoft by writing the name into their own unsigned binary.
    pub fn classify(
        &self,
        signature_type: SignatureType,
        signature_valid: bool,
        sha256: Option<&[u8; 32]>,
        team_id: Option<&str>,
        signer: Option<&str>,
        default_signed: TrustLevel,
    ) -> TrustLevel {
        // A hash pin is the one anchor that does not depend on a signature: it
        // identifies the exact bytes, which is a stronger statement than any
        // certificate.
        if let Some(h) = sha256 {
            if let Some(level) = self.by_hash.get(h) {
                return *level;
            }
        }
        match signature_type {
            SignatureType::None => TrustLevel::Unknown,
            SignatureType::Indeterminate => TrustLevel::Unknown,
            _ if !signature_valid => TrustLevel::Untrusted,
            _ => self
                .lookup(None, team_id, signer)
                .unwrap_or(default_signed),
        }
    }
}

fn is_team_id(s: &str) -> bool {
    s.len() == 10 && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

// ===========================================================================
// Cache
// ===========================================================================

/// Key that survives pid reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityKey {
    pub pid: u32,
    pub start_time_us: u64,
}

/// TTL cache with a bounded size.
///
/// Eviction is by oldest resolution time rather than least-recently-used: the
/// working set here is "processes with open sockets", which turns over on
/// process lifetime, and tracking access order would cost a write on every
/// cache *hit* in the connection path.
#[derive(Debug)]
pub struct IdentityCache {
    entries: Mutex<HashMap<IdentityKey, AppIdentity>>,
    capacity: usize,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

impl IdentityCache {
    pub fn new(capacity: usize) -> Self {
        IdentityCache {
            entries: Mutex::new(HashMap::with_capacity(capacity.min(4096))),
            capacity: capacity.max(1),
            hits: Default::default(),
            misses: Default::default(),
            evictions: Default::default(),
        }
    }

    pub fn get(&self, key: IdentityKey, now_us: u64) -> Option<AppIdentity> {
        use std::sync::atomic::Ordering;
        let mut entries = self.entries.lock().unwrap();
        match entries.get(&key) {
            Some(id) if !id.is_expired(now_us) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(id.clone())
            }
            Some(_) => {
                entries.remove(&key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn insert(&self, key: IdentityKey, identity: AppIdentity) {
        use std::sync::atomic::Ordering;
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            // Drop expired entries first; only fall back to evicting a live
            // one if that was not enough.
            let now = now_us();
            entries.retain(|_, v| !v.is_expired(now));
            if entries.len() >= self.capacity {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, v)| v.resolved_at_us)
                    .map(|(k, _)| *k)
                {
                    entries.remove(&oldest);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        entries.insert(key, identity);
    }

    /// Forget everything, e.g. after a trust-database change that could alter
    /// previously computed trust levels.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> CacheStats {
        use std::sync::atomic::Ordering;
        CacheStats {
            entries: self.len(),
            capacity: self.capacity,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

// ===========================================================================
// Service
// ===========================================================================

/// The identity resolution service the daemon exposes to the kernel module.
pub struct IdentityService {
    resolver: Box<dyn IdentityResolver>,
    cache: IdentityCache,
    trust: Mutex<TrustDatabase>,
    options: ResolverOptions,
}

impl std::fmt::Debug for IdentityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityService")
            .field("resolver", &self.resolver.name())
            .field("cache", &self.cache.stats())
            .finish()
    }
}

impl IdentityService {
    pub fn new(
        resolver: Box<dyn IdentityResolver>,
        trust: TrustDatabase,
        options: ResolverOptions,
        capacity: usize,
    ) -> Self {
        IdentityService {
            resolver,
            cache: IdentityCache::new(capacity),
            trust: Mutex::new(trust),
            options,
        }
    }

    pub fn resolver_name(&self) -> &'static str {
        self.resolver.name()
    }

    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Answer a query from the kernel module.
    pub fn answer(&self, query: &IdentityQuery) -> AppIdentity {
        let now = now_us();
        let key = IdentityKey { pid: query.pid, start_time_us: query.start_time_us };

        // Only consult the cache when the module supplied a start time. Without
        // one the key is a bare pid, which is exactly the aliasing this cache
        // is designed to avoid.
        if query.start_time_us != 0 {
            if let Some(cached) = self.cache.get(key, now) {
                return cached;
            }
        }

        let trust = self.trust.lock().unwrap();
        let mut identity = self.resolver.resolve(query, &trust);
        drop(trust);

        identity.ttl_secs = self.options.ttl_secs;
        identity.resolved_at_us = now;

        if identity.start_time_us != 0 {
            self.cache.insert(
                IdentityKey {
                    pid: identity.pid,
                    start_time_us: identity.start_time_us,
                },
                identity.clone(),
            );
        }
        identity
    }

    /// Replace the trust database and invalidate the cache, because a trust
    /// change can alter the level of an already-resolved identity.
    pub fn set_trust(&self, trust: TrustDatabase) {
        *self.trust.lock().unwrap() = trust;
        self.cache.clear();
    }

    pub fn trust_len(&self) -> usize {
        self.trust.lock().unwrap().len()
    }
}

// ===========================================================================
// Shared helpers for the platform resolvers
// ===========================================================================

/// Hash a file, unless it is larger than `max_bytes`.
pub fn hash_file(path: &Path, max_bytes: u64) -> Option<[u8; 32]> {
    use std::io::Read;

    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = hash::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hasher.finalize())
}

/// Normalize a path for policy matching: forward slashes everywhere, and
/// symlinks resolved where the platform allows it.
///
/// Two binaries reached by different paths are the same binary, and a policy
/// author should not have to enumerate every path to one.
pub fn normalize_path(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pid: u32, start: u64) -> IdentityQuery {
        IdentityQuery {
            pid,
            start_time_us: start,
            hint_path: None,
            platform_token: Vec::new(),
        }
    }

    fn identity(pid: u32, start: u64, now: u64) -> AppIdentity {
        let mut id = AppIdentity::unresolved(pid, now);
        id.start_time_us = start;
        id.ttl_secs = 60;
        id
    }

    // --- trust database ---------------------------------------------------

    #[test]
    fn trust_entries_are_classified_by_shape() {
        let mut db = TrustDatabase::new();
        db.insert(&hash::hex(&[0xab; 32]), TrustLevel::System);
        db.insert("ABCDE12345", TrustLevel::Trusted);
        db.insert("Contoso Ltd", TrustLevel::Known);
        assert_eq!(db.len(), 3);

        assert_eq!(db.lookup(Some(&[0xab; 32]), None, None), Some(TrustLevel::System));
        assert_eq!(db.lookup(None, Some("ABCDE12345"), None), Some(TrustLevel::Trusted));
        assert_eq!(db.lookup(None, None, Some("Contoso Ltd")), Some(TrustLevel::Known));
        assert_eq!(db.lookup(None, None, Some("Nobody")), None);
    }

    #[test]
    fn signer_lookup_is_case_insensitive() {
        let mut db = TrustDatabase::new();
        db.insert("Contoso Ltd", TrustLevel::Trusted);
        assert_eq!(
            db.lookup(None, None, Some("CONTOSO LTD")),
            Some(TrustLevel::Trusted)
        );
    }

    #[test]
    fn a_hash_pin_beats_a_signer_entry() {
        let mut db = TrustDatabase::new();
        db.insert("Contoso Ltd", TrustLevel::Untrusted);
        db.insert(&hash::hex(&[1u8; 32]), TrustLevel::System);
        assert_eq!(
            db.lookup(Some(&[1u8; 32]), None, Some("Contoso Ltd")),
            Some(TrustLevel::System)
        );
    }

    #[test]
    fn an_invalid_signature_is_untrusted_not_unknown() {
        let db = TrustDatabase::new();
        // A signature that exists and fails is worse than none at all: it is
        // evidence of tampering, not of an unsigned build.
        assert_eq!(
            db.classify(
                SignatureType::Authenticode,
                false,
                None,
                None,
                Some("Contoso Ltd"),
                TrustLevel::Known
            ),
            TrustLevel::Untrusted
        );
        assert_eq!(
            db.classify(SignatureType::None, false, None, None, None, TrustLevel::Known),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn an_unverified_signer_name_never_grants_trust() {
        let mut db = TrustDatabase::new();
        db.insert("Microsoft Corporation", TrustLevel::System);
        // An unsigned binary claiming to be Microsoft gets nothing.
        assert_eq!(
            db.classify(
                SignatureType::None,
                false,
                None,
                None,
                Some("Microsoft Corporation"),
                TrustLevel::Known
            ),
            TrustLevel::Unknown
        );
        // A validly signed one does.
        assert_eq!(
            db.classify(
                SignatureType::Authenticode,
                true,
                None,
                None,
                Some("Microsoft Corporation"),
                TrustLevel::Known
            ),
            TrustLevel::System
        );
    }

    #[test]
    fn a_hash_pin_applies_even_without_a_signature() {
        let mut db = TrustDatabase::new();
        db.insert(&hash::hex(&[7u8; 32]), TrustLevel::Trusted);
        assert_eq!(
            db.classify(
                SignatureType::None,
                false,
                Some(&[7u8; 32]),
                None,
                None,
                TrustLevel::Known
            ),
            TrustLevel::Trusted
        );
    }

    // --- cache ------------------------------------------------------------

    #[test]
    fn cache_hits_and_misses_are_counted() {
        let cache = IdentityCache::new(10);
        let key = IdentityKey { pid: 1, start_time_us: 100 };
        assert!(cache.get(key, 0).is_none());
        cache.insert(key, identity(1, 100, 0));
        assert!(cache.get(key, 0).is_some());
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn pid_reuse_misses_rather_than_returning_the_wrong_identity() {
        let cache = IdentityCache::new(10);
        let old = IdentityKey { pid: 42, start_time_us: 1_000 };
        cache.insert(old, identity(42, 1_000, 0));

        // Same pid, different start time: a different process.
        let new = IdentityKey { pid: 42, start_time_us: 2_000 };
        assert!(
            cache.get(new, 0).is_none(),
            "a recycled pid must not inherit the old process's identity"
        );
    }

    #[test]
    fn expired_entries_are_dropped_on_read() {
        let cache = IdentityCache::new(10);
        let key = IdentityKey { pid: 1, start_time_us: 1 };
        cache.insert(key, identity(1, 1, 0));
        assert!(cache.get(key, 61_000_000).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn the_cache_is_bounded() {
        // Entries are stamped with the live clock so none of them are expired;
        // this exercises the eviction path rather than the sweep path.
        let now = now_us();
        let cache = IdentityCache::new(4);
        for i in 0..20u32 {
            cache.insert(
                IdentityKey { pid: i, start_time_us: i as u64 + 1 },
                identity(i, i as u64 + 1, now + i as u64),
            );
        }
        assert!(cache.len() <= 4, "cache grew to {}", cache.len());
        assert!(cache.stats().evictions > 0);
    }

    #[test]
    fn eviction_prefers_the_oldest_entry() {
        let now = now_us();
        let cache = IdentityCache::new(2);
        cache.insert(IdentityKey { pid: 1, start_time_us: 1 }, identity(1, 1, now));
        cache.insert(IdentityKey { pid: 2, start_time_us: 2 }, identity(2, 2, now + 1_000));
        cache.insert(IdentityKey { pid: 3, start_time_us: 3 }, identity(3, 3, now + 2_000));
        // pid 1 was resolved first, so it is the one that went.
        assert!(cache.get(IdentityKey { pid: 1, start_time_us: 1 }, now).is_none());
        assert!(cache.get(IdentityKey { pid: 3, start_time_us: 3 }, now).is_some());
    }

    // --- service ----------------------------------------------------------

    struct CountingResolver {
        calls: std::sync::atomic::AtomicU32,
    }

    impl IdentityResolver for CountingResolver {
        fn resolve(&self, query: &IdentityQuery, _trust: &TrustDatabase) -> AppIdentity {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut id = AppIdentity::unresolved(query.pid, now_us());
            id.start_time_us = query.start_time_us;
            id.path = format!("/proc/{}/exe", query.pid);
            id.trust = TrustLevel::Known;
            id
        }

        fn name(&self) -> &'static str {
            "counting"
        }
    }

    fn service() -> IdentityService {
        IdentityService::new(
            Box::new(CountingResolver { calls: Default::default() }),
            TrustDatabase::new(),
            ResolverOptions::default(),
            16,
        )
    }

    #[test]
    fn a_repeat_query_is_served_from_the_cache() {
        let s = service();
        let q = query(7, 12_345);
        let first = s.answer(&q);
        let second = s.answer(&q);
        assert_eq!(first, second);
        assert_eq!(s.cache_stats().hits, 1);
    }

    #[test]
    fn a_query_without_a_start_time_is_never_cached() {
        // A bare pid is exactly the aliasing the cache exists to avoid, so
        // those queries always take the slow path.
        let s = service();
        s.answer(&query(7, 0));
        s.answer(&query(7, 0));
        assert_eq!(s.cache_stats().hits, 0);
        assert_eq!(s.cache_stats().entries, 0);
    }

    #[test]
    fn changing_the_trust_database_invalidates_the_cache() {
        let s = service();
        s.answer(&query(7, 1));
        assert_eq!(s.cache_stats().entries, 1);

        let mut db = TrustDatabase::new();
        db.insert("Contoso Ltd", TrustLevel::System);
        s.set_trust(db);
        assert_eq!(s.cache_stats().entries, 0);
        assert_eq!(s.trust_len(), 1);
    }

    // --- helpers ----------------------------------------------------------

    #[test]
    fn hashing_respects_the_size_limit() {
        let dir = std::env::temp_dir().join(format!("ufw-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bin");
        std::fs::write(&path, b"hello").unwrap();

        assert_eq!(hash_file(&path, 1024), Some(hash::sha256(b"hello")));
        assert_eq!(hash_file(&path, 2), None, "oversized files are not hashed");
        assert_eq!(hash_file(&dir.join("missing"), 1024), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_normalization_uses_forward_slashes() {
        let normalized = normalize_path(Path::new(r"C:\Program Files\App\app.exe"));
        assert!(!normalized.contains('\\'), "{normalized}");
    }
}
