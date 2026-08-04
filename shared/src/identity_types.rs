//! The unified application identity model.
//!
//! Windows, Linux and macOS each answer "what program is this?" with a
//! different set of facts. Windows has an Authenticode chain and a package
//! identity; Linux has an inode, an ELF hash and possibly an SELinux label;
//! macOS has a code directory hash, a designated requirement and a Team ID.
//!
//! Policy is written against [`AppIdentity`], which is the intersection of
//! what all three can produce plus a per-platform escape hatch
//! ([`AppIdentity::platform_meta`]) for facts that only exist on one of them.
//! Normalization happens in the daemon (`daemon/src/identity/`); everything
//! downstream of that — rule matching, logging, the management API — sees only
//! this type.

use std::collections::BTreeMap;
use std::fmt;

use crate::hash;
use crate::protocol::{ProtoError, Reader, Writer};

/// How the binary behind a process was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureType {
    /// No signature was found, or the platform has no signature concept for
    /// this binary format.
    None = 0,
    /// Windows Authenticode, embedded or catalog-backed.
    Authenticode = 1,
    /// Apple code signing (Mach-O `LC_CODE_SIGNATURE`).
    MachOCodeSign = 2,
    /// Linux has no universal binary signing scheme; identity falls back to a
    /// content hash of the ELF image plus, where present, an LSM label.
    ElfContentHash = 3,
    /// A signature exists but could not be evaluated (missing root, offline
    /// revocation check, malformed blob). Deliberately distinct from `None`:
    /// "unverifiable" and "unsigned" are different security postures.
    Indeterminate = 4,
}

impl SignatureType {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureType::None => "none",
            SignatureType::Authenticode => "authenticode",
            SignatureType::MachOCodeSign => "macho-codesign",
            SignatureType::ElfContentHash => "elf-hash",
            SignatureType::Indeterminate => "indeterminate",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => SignatureType::None,
            1 => SignatureType::Authenticode,
            2 => SignatureType::MachOCodeSign,
            3 => SignatureType::ElfContentHash,
            4 => SignatureType::Indeterminate,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" | "unsigned" => SignatureType::None,
            "authenticode" => SignatureType::Authenticode,
            "macho-codesign" | "codesign" => SignatureType::MachOCodeSign,
            "elf-hash" | "elf" => SignatureType::ElfContentHash,
            "indeterminate" => SignatureType::Indeterminate,
            _ => return None,
        })
    }
}

/// Ordered trust classification. Policy compares with `>=`, so the numeric
/// order is load-bearing: raising a threshold must never accidentally admit a
/// lower class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TrustLevel {
    /// Signature present and *invalid*, or the signer is on a local deny list.
    /// Strictly worse than having no signature at all.
    Untrusted = 0,
    /// No signature, or a signature that could not be evaluated.
    Unknown = 1,
    /// Validly signed by a publisher that is not in the trust database.
    Known = 2,
    /// Validly signed by a publisher listed as trusted in the trust database.
    Trusted = 3,
    /// Validly signed by the platform vendor (Microsoft, Apple) or shipped by
    /// the distribution's package manager with a verified signature.
    System = 4,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Untrusted => "untrusted",
            TrustLevel::Unknown => "unknown",
            TrustLevel::Known => "known",
            TrustLevel::Trusted => "trusted",
            TrustLevel::System => "system",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => TrustLevel::Untrusted,
            1 => TrustLevel::Unknown,
            2 => TrustLevel::Known,
            3 => TrustLevel::Trusted,
            4 => TrustLevel::System,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "untrusted" => TrustLevel::Untrusted,
            "unknown" => TrustLevel::Unknown,
            "known" => TrustLevel::Known,
            "trusted" => TrustLevel::Trusted,
            "system" => TrustLevel::System,
            _ => return None,
        })
    }

    pub const ALL: [TrustLevel; 5] = [
        TrustLevel::Untrusted,
        TrustLevel::Unknown,
        TrustLevel::Known,
        TrustLevel::Trusted,
        TrustLevel::System,
    ];

    /// Bit position of this level in a [`TrustMask`].
    pub fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of trust levels, packed into one byte so it can be compared in a
/// single instruction inside a kernel hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TrustMask(pub u8);

impl TrustMask {
    pub const EMPTY: TrustMask = TrustMask(0);
    pub const ANY: TrustMask = TrustMask(0b0001_1111);

    pub fn from_levels<I: IntoIterator<Item = TrustLevel>>(levels: I) -> Self {
        let mut m = 0u8;
        for l in levels {
            m |= l.bit();
        }
        TrustMask(m)
    }

    pub fn contains(self, level: TrustLevel) -> bool {
        self.0 & level.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// A mask that matches everything is equivalent to no constraint; the
    /// optimizer uses this to drop redundant trust predicates.
    pub fn is_any(self) -> bool {
        self.0 & Self::ANY.0 == Self::ANY.0
    }

    pub fn levels(self) -> impl Iterator<Item = TrustLevel> {
        TrustLevel::ALL.into_iter().filter(move |l| self.contains(*l))
    }

    /// Mask of every level at or above `min`, which is how `trust: ">= known"`
    /// in a policy file is lowered.
    pub fn at_least(min: TrustLevel) -> Self {
        Self::from_levels(TrustLevel::ALL.into_iter().filter(|l| *l >= min))
    }
}

/// Normalized identity of the process behind a flow.
///
/// Every field except `pid` is optional in the sense that a platform may not
/// be able to fill it; matching treats an absent field as "does not match a
/// rule that constrains it", never as a wildcard. That asymmetry is what makes
/// an unresolvable process fall to the unsigned/unknown policy path instead of
/// silently satisfying an identity rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    /// OS process id at the time of resolution. Not an identity on its own —
    /// pids are reused — but needed to correlate with the kernel's cache.
    pub pid: u32,
    /// Process start time in microseconds since the UNIX epoch, used together
    /// with `pid` as the cache key so pid reuse invalidates rather than
    /// aliases.
    pub start_time_us: u64,
    /// Absolute path of the main executable image, normalized to forward
    /// slashes on Windows and to a canonical (symlink-resolved) form on
    /// UNIX.
    pub path: String,
    /// SHA-256 of the executable image, if it was hashed. Hashing is skipped
    /// for images above a configurable size, in which case this is `None` and
    /// hash-constrained rules cannot match.
    pub sha256: Option<[u8; 32]>,
    /// How the image was authenticated.
    pub signature_type: SignatureType,
    /// Whether the certificate chain (or code directory) validated, including
    /// revocation checking where the platform supports it.
    pub signature_valid: bool,
    /// Human-readable signer, e.g. an Authenticode subject CN or a macOS
    /// authority string.
    pub signer: Option<String>,
    /// Apple Developer Team ID (macOS only).
    pub team_id: Option<String>,
    /// Bundle identifier (macOS) or package family name (Windows Store apps).
    pub bundle_id: Option<String>,
    /// Resolved trust classification.
    pub trust: TrustLevel,
    /// User the process runs as: SID on Windows, `uid:gid` on UNIX.
    pub user: Option<String>,
    /// Platform-specific facts that have no cross-platform equivalent, e.g.
    /// `selinux_context`, `apparmor_profile`, `designated_requirement`,
    /// `package_sid`. Sorted so that serialization is deterministic.
    pub platform_meta: BTreeMap<String, String>,
    /// When this identity was resolved (microseconds since epoch).
    pub resolved_at_us: u64,
    /// Seconds after `resolved_at_us` at which this entry must be discarded.
    pub ttl_secs: u64,
}

impl AppIdentity {
    /// The identity used when resolution failed. Deliberately `Untrusted`
    /// rather than `Unknown`: a process we could not inspect at all is the
    /// worst case, not a middling one.
    pub fn unresolved(pid: u32, now_us: u64) -> Self {
        AppIdentity {
            pid,
            start_time_us: 0,
            path: String::new(),
            sha256: None,
            signature_type: SignatureType::Indeterminate,
            signature_valid: false,
            signer: None,
            team_id: None,
            bundle_id: None,
            trust: TrustLevel::Untrusted,
            user: None,
            platform_meta: BTreeMap::new(),
            resolved_at_us: now_us,
            ttl_secs: 5,
            }
    }

    pub fn is_expired(&self, now_us: u64) -> bool {
        now_us.saturating_sub(self.resolved_at_us) >= self.ttl_secs.saturating_mul(1_000_000)
    }

    /// Last path component, for compact log rendering.
    pub fn image_name(&self) -> &str {
        self.path
            .rsplit(['/', '\\'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("<unknown>")
    }

    pub fn sha256_hex(&self) -> Option<String> {
        self.sha256.as_ref().map(|d| hash::hex(d))
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.pid);
        w.u64(self.start_time_us);
        w.string(&self.path);
        match &self.sha256 {
            Some(d) => {
                w.u8(1);
                w.raw(d);
            }
            None => w.u8(0),
        }
        w.u8(self.signature_type as u8);
        w.bool(self.signature_valid);
        w.opt_string(self.signer.as_deref());
        w.opt_string(self.team_id.as_deref());
        w.opt_string(self.bundle_id.as_deref());
        w.u8(self.trust as u8);
        w.opt_string(self.user.as_deref());
        w.u16(self.platform_meta.len() as u16);
        for (k, v) in &self.platform_meta {
            w.string(k);
            w.string(v);
        }
        w.u64(self.resolved_at_us);
        w.u64(self.ttl_secs);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let pid = r.u32()?;
        let start_time_us = r.u64()?;
        let path = r.string()?;
        let sha256 = if r.u8()? != 0 {
            let mut d = [0u8; 32];
            d.copy_from_slice(r.raw(32)?);
            Some(d)
        } else {
            None
        };
        let signature_type = SignatureType::from_u8(r.u8()?)
            .ok_or(ProtoError::Malformed("unknown signature type"))?;
        let signature_valid = r.bool()?;
        let signer = r.opt_string()?;
        let team_id = r.opt_string()?;
        let bundle_id = r.opt_string()?;
        let trust =
            TrustLevel::from_u8(r.u8()?).ok_or(ProtoError::Malformed("unknown trust level"))?;
        let user = r.opt_string()?;
        let meta_len = r.u16()? as usize;
        let mut platform_meta = BTreeMap::new();
        for _ in 0..meta_len {
            let k = r.string()?;
            let v = r.string()?;
            platform_meta.insert(k, v);
        }
        let resolved_at_us = r.u64()?;
        let ttl_secs = r.u64()?;
        Ok(AppIdentity {
            pid,
            start_time_us,
            path,
            sha256,
            signature_type,
            signature_valid,
            signer,
            team_id,
            bundle_id,
            trust,
            user,
            platform_meta,
            resolved_at_us,
            ttl_secs,
        })
    }

    /// Render as a JSON object body (without surrounding braces handled by the
    /// caller's writer) for embedding in log events and API responses.
    pub fn write_json(&self, w: &mut crate::json::JsonWriter) {
        w.u64_field("pid", self.pid as u64);
        w.str_field("path", &self.path);
        match self.sha256_hex() {
            Some(h) => w.str_field("sha256", &h),
            None => w.null_field("sha256"),
        }
        w.str_field("signature_type", self.signature_type.as_str());
        w.bool_field("signature_valid", self.signature_valid);
        w.opt_str_field("signer", self.signer.as_deref());
        w.opt_str_field("team_id", self.team_id.as_deref());
        w.opt_str_field("bundle_id", self.bundle_id.as_deref());
        w.str_field("trust", self.trust.as_str());
        w.opt_str_field("user", self.user.as_deref());
        if !self.platform_meta.is_empty() {
            w.begin_object_field("platform");
            for (k, v) in &self.platform_meta {
                w.str_field(k, v);
            }
            w.end_object();
        }
    }
}

/// Query sent from a kernel module to the daemon on identity-cache miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityQuery {
    pub pid: u32,
    /// Process start time if the kernel can cheaply supply it; used to detect
    /// pid reuse between the query and the response.
    pub start_time_us: u64,
    /// Path the kernel already knows, if any. Windows ALE layers provide one;
    /// the Linux netfilter path can usually derive one; macOS supplies an
    /// audit token instead.
    pub hint_path: Option<String>,
    /// Opaque platform token (macOS audit token, Windows process handle id)
    /// forwarded verbatim to the platform resolver.
    pub platform_token: Vec<u8>,
}

impl IdentityQuery {
    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.pid);
        w.u64(self.start_time_us);
        w.opt_string(self.hint_path.as_deref());
        w.bytes(&self.platform_token);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Ok(IdentityQuery {
            pid: r.u32()?,
            start_time_us: r.u64()?,
            hint_path: r.opt_string()?,
            platform_token: r.bytes()?.to_vec(),
        })
    }
}

/// An entry in the signer trust database that maps publishers to trust levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Signer subject, Team ID, or `sha256:...` of a specific binary.
    pub subject: String,
    pub level: TrustLevel,
    /// Optional note explaining why this anchor exists, surfaced by
    /// `ufwctl identity trust list`.
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_mask_roundtrip() {
        let m = TrustMask::from_levels([TrustLevel::Trusted, TrustLevel::System]);
        assert!(m.contains(TrustLevel::Trusted));
        assert!(m.contains(TrustLevel::System));
        assert!(!m.contains(TrustLevel::Unknown));
        assert!(!m.is_any());
        assert_eq!(m.levels().count(), 2);
        assert!(TrustMask::ANY.is_any());
        assert!(TrustMask::EMPTY.is_empty());
    }

    #[test]
    fn at_least_is_monotone() {
        let m = TrustMask::at_least(TrustLevel::Known);
        assert!(!m.contains(TrustLevel::Untrusted));
        assert!(!m.contains(TrustLevel::Unknown));
        assert!(m.contains(TrustLevel::Known));
        assert!(m.contains(TrustLevel::Trusted));
        assert!(m.contains(TrustLevel::System));
    }

    #[test]
    fn identity_wire_roundtrip() {
        let mut id = AppIdentity::unresolved(4242, 1_000_000);
        id.path = "/usr/bin/curl".into();
        id.sha256 = Some(hash::sha256(b"elf"));
        id.signature_type = SignatureType::ElfContentHash;
        id.signature_valid = true;
        id.signer = Some("Debian".into());
        id.trust = TrustLevel::Known;
        id.platform_meta.insert("selinux".into(), "unconfined_t".into());

        let mut w = Writer::new();
        id.encode(&mut w);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        let back = AppIdentity::decode(&mut r).unwrap();
        assert_eq!(id, back);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn unresolved_is_untrusted_not_unknown() {
        let id = AppIdentity::unresolved(1, 0);
        assert_eq!(id.trust, TrustLevel::Untrusted);
        assert_eq!(id.signature_type, SignatureType::Indeterminate);
    }

    #[test]
    fn expiry_uses_microseconds() {
        let mut id = AppIdentity::unresolved(1, 0);
        id.ttl_secs = 10;
        assert!(!id.is_expired(9_999_999));
        assert!(id.is_expired(10_000_000));
    }

    #[test]
    fn image_name_handles_both_separators() {
        let mut id = AppIdentity::unresolved(1, 0);
        id.path = r"C:\Program Files\App\app.exe".into();
        assert_eq!(id.image_name(), "app.exe");
        id.path = "/usr/bin/curl".into();
        assert_eq!(id.image_name(), "curl");
        id.path = String::new();
        assert_eq!(id.image_name(), "<unknown>");
    }
}
