//! Linux identity resolution: procfs, ELF hashing and LSM labels.
//!
//! Linux has no universal binary signing scheme, so identity here rests on two
//! things the kernel can vouch for: the executable the process is running
//! (`/proc/<pid>/exe`, a kernel-maintained symlink that cannot be forged from
//! userspace) and the content hash of that file. A path alone is worthless —
//! anything can be copied to `/usr/bin/curl` — which is why a policy that
//! cares pins a hash.
//!
//! Where an LSM is active, its label is carried through as platform metadata.
//! It is not folded into the trust level: SELinux and AppArmor answer a
//! different question ("what is this process allowed to do?") than the trust
//! model does ("who published this binary?"), and conflating them would make
//! both harder to reason about.
//!
//! # Reading procfs safely
//!
//! Everything here can fail benignly, and usually for the same reason: the
//! process exited between the kernel's query and this lookup. Every read is
//! therefore fallible and every failure lands on [`AppIdentity::unresolved`],
//! which is `Untrusted`.

use std::path::{Path, PathBuf};

use ufw_shared::identity_types::{AppIdentity, IdentityQuery, SignatureType, TrustLevel};
use ufw_shared::now_us;

use super::{hash_file, normalize_path, IdentityResolver, ResolverOptions, TrustDatabase};

#[derive(Debug)]
pub struct LinuxResolver {
    options: ResolverOptions,
    /// Root of the proc filesystem. Overridable so the tests can point it at a
    /// fixture tree instead of the live kernel.
    proc_root: PathBuf,
}

impl LinuxResolver {
    pub fn new(options: ResolverOptions) -> Self {
        LinuxResolver { options, proc_root: PathBuf::from("/proc") }
    }

    pub fn with_proc_root(options: ResolverOptions, proc_root: impl Into<PathBuf>) -> Self {
        LinuxResolver { options, proc_root: proc_root.into() }
    }

    fn pid_dir(&self, pid: u32) -> PathBuf {
        self.proc_root.join(pid.to_string())
    }

    /// Resolve `/proc/<pid>/exe`.
    ///
    /// A deleted executable comes back as `"/path/to/bin (deleted)"`. That is
    /// worth surfacing rather than silently trimming: a running process whose
    /// on-disk image has been unlinked is a common shape for both a package
    /// upgrade and a dropper that removed itself.
    fn exe_path(&self, pid: u32) -> Option<(String, bool)> {
        let link = self.pid_dir(pid).join("exe");
        let target = std::fs::read_link(&link).ok()?;
        let text = target.to_string_lossy().to_string();
        match text.strip_suffix(" (deleted)") {
            Some(stripped) => Some((stripped.to_string(), true)),
            None => Some((normalize_path(&target), false)),
        }
    }

    /// Process start time, in microseconds since the epoch.
    ///
    /// `/proc/<pid>/stat` field 22 is the start time in clock ticks since
    /// boot. Combining it with the boot time from `/proc/stat` gives an
    /// absolute value, which is what makes the cache key stable across a
    /// daemon restart.
    fn start_time_us(&self, pid: u32) -> Option<u64> {
        let stat = std::fs::read_to_string(self.pid_dir(pid).join("stat")).ok()?;
        // The second field is the comm, which may contain spaces and
        // parentheses; everything after the last ')' is safe to split.
        let rest = &stat[stat.rfind(')')? + 1..];
        let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;

        let boot_time_s = self.boot_time_secs()?;
        // USER_HZ is 100 on every Linux configuration this runs on; it is not
        // exposed without libc, and getting it wrong shifts every start time
        // by a constant factor, which the cache would notice immediately.
        const USER_HZ: u64 = 100;
        Some((boot_time_s + ticks / USER_HZ) * 1_000_000 + (ticks % USER_HZ) * 10_000)
    }

    fn boot_time_secs(&self) -> Option<u64> {
        let stat = std::fs::read_to_string(self.proc_root.join("stat")).ok()?;
        stat.lines()
            .find_map(|l| l.strip_prefix("btime "))
            .and_then(|v| v.trim().parse().ok())
    }

    fn uid_gid(&self, pid: u32) -> Option<String> {
        let status = std::fs::read_to_string(self.pid_dir(pid).join("status")).ok()?;
        let mut uid = None;
        let mut gid = None;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Uid:") {
                uid = v.split_whitespace().next().map(str::to_string);
            } else if let Some(v) = line.strip_prefix("Gid:") {
                gid = v.split_whitespace().next().map(str::to_string);
            }
        }
        Some(format!("{}:{}", uid?, gid?))
    }

    /// SELinux or AppArmor label, if one is active.
    fn lsm_label(&self, pid: u32) -> Option<(&'static str, String)> {
        let current = std::fs::read_to_string(self.pid_dir(pid).join("attr/current")).ok()?;
        let label = current.trim_end_matches('\0').trim();
        if label.is_empty() || label == "unconfined" {
            return None;
        }
        // An SELinux context has the shape user:role:type:level; AppArmor
        // writes a profile name and an optional mode in parentheses.
        let kind = if label.matches(':').count() >= 3 {
            "selinux_context"
        } else {
            "apparmor_profile"
        };
        Some((kind, label.to_string()))
    }

    /// Whether the binary came from the distribution's package manager.
    ///
    /// This is the closest thing Linux has to a publisher signature: a file
    /// under a package-manager-owned prefix that the package manager still
    /// claims. It is deliberately conservative — it establishes provenance for
    /// the *path*, not the bytes, so it never reaches beyond `Known` on its
    /// own.
    fn packaged_prefix(path: &str) -> bool {
        const PREFIXES: [&str; 6] = [
            "/usr/bin/",
            "/usr/sbin/",
            "/usr/lib/",
            "/usr/libexec/",
            "/bin/",
            "/sbin/",
        ];
        PREFIXES.iter().any(|p| path.starts_with(p))
    }
}

impl IdentityResolver for LinuxResolver {
    fn name(&self) -> &'static str {
        "linux-procfs"
    }

    fn resolve(&self, query: &IdentityQuery, trust: &TrustDatabase) -> AppIdentity {
        let now = now_us();
        let mut identity = AppIdentity::unresolved(query.pid, now);

        // The kernel-maintained symlink is authoritative; the module's hint is
        // only a fallback for the window where the process has already exited.
        let (path, deleted, from_procfs) = match self.exe_path(query.pid) {
            Some((p, d)) => (p, d, true),
            None => match &query.hint_path {
                Some(hint) => (hint.clone(), false, false),
                None => return identity,
            },
        };

        identity.path = path.clone();
        identity.start_time_us = self
            .start_time_us(query.pid)
            .unwrap_or(query.start_time_us);
        identity.user = self.uid_gid(query.pid);

        if deleted {
            // The bytes are gone, so there is nothing to hash and nothing to
            // vouch for. Say so explicitly rather than reporting an
            // unqualified path.
            identity
                .platform_meta
                .insert("image_deleted".into(), "true".into());
            identity.signature_type = SignatureType::Indeterminate;
            identity.trust = TrustLevel::Untrusted;
            return identity;
        }

        identity.sha256 = hash_file(Path::new(&path), self.options.max_hash_bytes);
        identity.signature_type = SignatureType::ElfContentHash;
        // "Valid" here means the content was successfully measured, which is
        // the only assertion this platform can make without a signing scheme.
        identity.signature_valid = identity.sha256.is_some();

        if let Some((kind, label)) = self.lsm_label(query.pid) {
            identity.platform_meta.insert(kind.into(), label);
        }
        if Self::packaged_prefix(&path) {
            identity
                .platform_meta
                .insert("packaged_prefix".into(), "true".into());
        }

        identity.trust = trust
            .lookup(identity.sha256.as_ref(), None, None)
            .unwrap_or_else(|| {
                if !from_procfs {
                    // The path came from the module's hint, not from the
                    // kernel's own symlink, which means nothing confirms this
                    // process was ever running these bytes. Hash it for the
                    // log, but grant nothing for it.
                    identity
                        .platform_meta
                        .insert("path_unconfirmed".into(), "true".into());
                    TrustLevel::Unknown
                } else if identity.sha256.is_none() {
                    // Unhashable (too large, unreadable): no worse than
                    // unsigned, but no better either.
                    TrustLevel::Unknown
                } else if Self::packaged_prefix(&path) {
                    self.options.default_signed_trust.min(TrustLevel::Known)
                } else {
                    TrustLevel::Unknown
                }
            });

        identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fake procfs tree so these tests exercise the parsing rather
    /// than whatever happens to be running on the build machine.
    struct FakeProc {
        root: PathBuf,
    }

    impl FakeProc {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ufw-proc-{}-{}-{name}",
                std::process::id(),
                now_us()
            ));
            fs::create_dir_all(&root).unwrap();
            fs::write(&root.join("stat"), "cpu 1 2 3\nbtime 1700000000\n").unwrap();
            FakeProc { root }
        }

        fn add_process(&self, pid: u32, exe: &Path, start_ticks: u64) {
            self.add_process_raw(pid, &exe.to_string_lossy(), start_ticks);
        }

        /// The exe link target is written verbatim, so a test can reproduce
        /// procfs's `" (deleted)"` suffix, which a real symlink cannot carry.
        fn add_process_raw(&self, pid: u32, exe_target: &str, start_ticks: u64) {
            let dir = self.root.join(pid.to_string());
            fs::create_dir_all(dir.join("attr")).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(exe_target, dir.join("exe")).unwrap();
            // Real /proc/<pid>/stat: field 22 is the start time, and the
            // tokens after the closing paren begin at field 3 (state), so the
            // start time is the 20th token. `fields` here stands in for
            // fields 4 onward.
            let mut fields = vec!["0".to_string(); 50];
            fields[18] = start_ticks.to_string();
            fs::write(
                dir.join("stat"),
                format!("{pid} (probe app) S {}", fields.join(" ")),
            )
            .unwrap();
            fs::write(dir.join("status"), "Name:\tprobe\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n").unwrap();
        }

        fn set_label(&self, pid: u32, label: &str) {
            fs::write(self.root.join(pid.to_string()).join("attr/current"), label).unwrap();
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn write_binary(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn query(pid: u32) -> IdentityQuery {
        IdentityQuery {
            pid,
            start_time_us: 0,
            hint_path: None,
            platform_token: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolves_path_hash_user_and_start_time() {
        let proc = FakeProc::new("basic");
        let bin = write_binary(&proc.root.join("bin"), "app", b"\x7fELF-payload");
        proc.add_process(1234, &bin, 500);

        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(1234), &TrustDatabase::new());

        assert!(id.path.ends_with("/app"), "{}", id.path);
        assert_eq!(id.sha256, Some(ufw_shared::hash::sha256(b"\x7fELF-payload")));
        assert_eq!(id.signature_type, SignatureType::ElfContentHash);
        assert!(id.signature_valid);
        assert_eq!(id.user.as_deref(), Some("1000:100"));
        // btime 1700000000 + 500 ticks at 100Hz = 5 seconds.
        assert_eq!(id.start_time_us, 1_700_000_005_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn a_deleted_image_is_untrusted_and_says_why() {
        let proc = FakeProc::new("deleted");
        // procfs marks an unlinked image by appending " (deleted)" to the
        // symlink target.
        proc.add_process_raw(99, "/tmp/dropper (deleted)", 1);

        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(99), &TrustDatabase::new());

        // A running process whose on-disk image is gone cannot be measured.
        assert_eq!(id.trust, TrustLevel::Untrusted);
        assert!(id.sha256.is_none());
        assert_eq!(id.path, "/tmp/dropper");
        assert_eq!(
            id.platform_meta.get("image_deleted").map(String::as_str),
            Some("true")
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_selinux_context_is_carried_as_metadata_not_folded_into_trust() {
        let proc = FakeProc::new("selinux");
        let bin = write_binary(&proc.root.join("bin"), "app", b"x");
        proc.add_process(7, &bin, 1);
        proc.set_label(7, "system_u:system_r:httpd_t:s0");

        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(7), &TrustDatabase::new());
        assert_eq!(
            id.platform_meta.get("selinux_context").map(String::as_str),
            Some("system_u:system_r:httpd_t:s0")
        );
        // The label answers a different question than trust does.
        assert_eq!(id.trust, TrustLevel::Unknown);
    }

    #[cfg(unix)]
    #[test]
    fn an_apparmor_profile_is_distinguished_from_an_selinux_context() {
        let proc = FakeProc::new("apparmor");
        let bin = write_binary(&proc.root.join("bin"), "app", b"x");
        proc.add_process(8, &bin, 1);
        proc.set_label(8, "/usr/sbin/nginx (enforce)");

        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(8), &TrustDatabase::new());
        assert!(id.platform_meta.contains_key("apparmor_profile"));
        assert!(!id.platform_meta.contains_key("selinux_context"));
    }

    #[cfg(unix)]
    #[test]
    fn a_pinned_hash_overrides_everything_else() {
        let proc = FakeProc::new("pinned");
        let bin = write_binary(&proc.root.join("opt"), "custom", b"trusted-bytes");
        proc.add_process(11, &bin, 1);

        let mut db = TrustDatabase::new();
        db.insert(
            &ufw_shared::hash::hex(&ufw_shared::hash::sha256(b"trusted-bytes")),
            TrustLevel::System,
        );

        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(11), &db);
        assert_eq!(id.trust, TrustLevel::System);
    }

    #[test]
    fn an_unknown_pid_resolves_to_untrusted() {
        let proc = FakeProc::new("missing");
        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let id = resolver.resolve(&query(4_000_000), &TrustDatabase::new());
        assert_eq!(id.trust, TrustLevel::Untrusted);
        assert!(id.path.is_empty());
    }

    #[test]
    fn the_hint_path_is_only_a_fallback() {
        let proc = FakeProc::new("hint");
        let resolver = LinuxResolver::with_proc_root(ResolverOptions::default(), &proc.root);
        let mut q = query(4_000_001);
        q.hint_path = Some("/usr/bin/curl".into());
        let id = resolver.resolve(&q, &TrustDatabase::new());
        assert_eq!(id.path, "/usr/bin/curl");
        // A hint the kernel could not confirm buys no trust, even when the
        // path sits under a package-manager prefix.
        assert_eq!(id.trust, TrustLevel::Unknown);
        assert!(id.platform_meta.contains_key("path_unconfirmed"));
    }

    #[test]
    fn packaged_prefixes_are_recognized_conservatively() {
        assert!(LinuxResolver::packaged_prefix("/usr/bin/curl"));
        assert!(LinuxResolver::packaged_prefix("/sbin/ip"));
        assert!(!LinuxResolver::packaged_prefix("/tmp/dropper"));
        assert!(!LinuxResolver::packaged_prefix("/home/user/.local/bin/x"));
    }

    #[cfg(unix)]
    #[test]
    fn an_oversized_binary_is_not_hashed_and_is_not_trusted_for_it() {
        let proc = FakeProc::new("oversized");
        let bin = write_binary(&proc.root.join("bin"), "big", &vec![0u8; 4096]);
        proc.add_process(21, &bin, 1);

        let options = ResolverOptions { max_hash_bytes: 16, ..Default::default() };
        let resolver = LinuxResolver::with_proc_root(options, &proc.root);
        let id = resolver.resolve(&query(21), &TrustDatabase::new());
        assert!(id.sha256.is_none());
        assert!(!id.signature_valid);
        assert_eq!(id.trust, TrustLevel::Unknown);
    }
}
