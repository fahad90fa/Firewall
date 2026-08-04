//! Windows identity resolution: PE path, image hash and Authenticode.
//!
//! # What this module does and does not do
//!
//! Authenticode verification is `WinVerifyTrust`, and `WinVerifyTrust` is a
//! Win32 call. This crate takes no dependencies and contains no `unsafe`, so
//! the chain-building, revocation-checking half of verification lives behind
//! [`AuthenticodeVerifier`] — a trait with one method — and the Windows build
//! installs an implementation that calls into `wintrust.dll`.
//!
//! Everything that does *not* need Win32 is implemented here and is the same
//! code on every platform: locating the image, hashing it, parsing enough of
//! the PE header to tell a real executable from a file with an `.exe`
//! extension, reading the embedded certificate table's presence, and mapping
//! the verifier's answer onto a [`TrustLevel`].
//!
//! The split is deliberate rather than a placeholder. It means the trust
//! logic — the part that decides whether a binary may talk to the network —
//! is testable without a Windows host, and the platform-specific part is
//! small enough to audit as a unit.
//!
//! # Why a path is never enough
//!
//! `C:\Windows\System32\svchost.exe` is the most impersonated path on the
//! platform. A policy that matches on it and nothing else is matching on a
//! string an attacker controls. So the resolver always attempts a hash, always
//! records whether a signature was present *and valid*, and reports
//! `Untrusted` — not `Unknown` — when a signature exists and fails.

use std::path::Path;

use ufw_shared::identity_types::{AppIdentity, IdentityQuery, SignatureType, TrustLevel};
use ufw_shared::now_us;

use super::{hash_file, normalize_path, IdentityResolver, ResolverOptions, TrustDatabase};

/// The result of asking the platform to verify a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    /// Whether the chain built and validated, including revocation checking.
    pub valid: bool,
    /// Subject common name of the leaf certificate.
    pub signer: Option<String>,
    /// Issuer common name, recorded as metadata for forensics.
    pub issuer: Option<String>,
    /// Package family name for a Windows Store application.
    pub package_family: Option<String>,
    /// Why verification failed, when it did.
    pub failure: Option<String>,
}

impl SignatureInfo {
    pub fn unsigned() -> Self {
        SignatureInfo {
            valid: false,
            signer: None,
            issuer: None,
            package_family: None,
            failure: None,
        }
    }
}

/// The Win32 half of verification.
///
/// The Windows build supplies an implementation backed by `WinVerifyTrust`
/// with `WTD_REVOKE_WHOLECHAIN`; every other build gets
/// [`UnavailableVerifier`], which reports "cannot evaluate" rather than
/// "unsigned".
pub trait AuthenticodeVerifier: Send + Sync + std::fmt::Debug {
    /// Verify the image at `path`. `None` means no signature was found at
    /// all; `Some` carries the outcome of evaluating one that was.
    fn verify(&self, path: &Path) -> Option<SignatureInfo>;
}

/// Used on builds without the Win32 backend.
#[derive(Debug)]
pub struct UnavailableVerifier;

impl AuthenticodeVerifier for UnavailableVerifier {
    fn verify(&self, _path: &Path) -> Option<SignatureInfo> {
        Some(SignatureInfo {
            valid: false,
            signer: None,
            issuer: None,
            package_family: None,
            failure: Some("Authenticode verification is unavailable in this build".into()),
        })
    }
}

#[derive(Debug)]
pub struct WindowsResolver {
    options: ResolverOptions,
    verifier: Box<dyn AuthenticodeVerifier>,
}

impl WindowsResolver {
    pub fn new(options: ResolverOptions) -> Self {
        WindowsResolver {
            options,
            verifier: Box::new(UnavailableVerifier),
        }
    }

    pub fn with_verifier(
        options: ResolverOptions,
        verifier: Box<dyn AuthenticodeVerifier>,
    ) -> Self {
        WindowsResolver { options, verifier }
    }
}

/// Whether a file starts with the `MZ`/`PE\0\0` pair that makes it a real PE
/// image.
///
/// A `.exe` extension is a naming convention; the header is the format. This
/// is cheap and rules out the simplest form of "drop a script where a binary
/// is expected".
pub fn is_pe_image(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut mz = [0u8; 2];
    if file.read_exact(&mut mz).is_err() || &mz != b"MZ" {
        return false;
    }
    // e_lfanew, the offset of the PE header, sits at 0x3C.
    if file.seek(SeekFrom::Start(0x3C)).is_err() {
        return false;
    }
    let mut offset = [0u8; 4];
    if file.read_exact(&mut offset).is_err() {
        return false;
    }
    let pe_offset = u32::from_le_bytes(offset) as u64;
    if file.seek(SeekFrom::Start(pe_offset)).is_err() {
        return false;
    }
    let mut sig = [0u8; 4];
    file.read_exact(&mut sig).is_ok() && &sig == b"PE\0\0"
}

impl IdentityResolver for WindowsResolver {
    fn name(&self) -> &'static str {
        "windows-authenticode"
    }

    fn resolve(&self, query: &IdentityQuery, trust: &TrustDatabase) -> AppIdentity {
        let now = now_us();
        let mut identity = AppIdentity::unresolved(query.pid, now);

        // On Windows the ALE layers hand the driver the image path, so the
        // hint is the primary source rather than a fallback. Verifying that
        // the path still resolves to a PE image is what keeps it honest.
        let Some(raw_path) = query.hint_path.clone() else {
            return identity;
        };
        let path = Path::new(&raw_path);
        identity.path = normalize_path(path);
        identity.start_time_us = query.start_time_us;

        if !path.exists() {
            // The image was replaced or deleted while the process ran.
            identity
                .platform_meta
                .insert("image_missing".into(), "true".into());
            identity.signature_type = SignatureType::Indeterminate;
            identity.trust = TrustLevel::Untrusted;
            return identity;
        }

        if !is_pe_image(path) {
            identity
                .platform_meta
                .insert("not_a_pe_image".into(), "true".into());
        }

        identity.sha256 = hash_file(path, self.options.max_hash_bytes);

        match self.verifier.verify(path) {
            None => {
                identity.signature_type = SignatureType::None;
                identity.signature_valid = false;
            }
            Some(info) => {
                identity.signature_type = if info.failure.is_some() && info.signer.is_none() {
                    // Present but unevaluable is not the same as absent.
                    SignatureType::Indeterminate
                } else {
                    SignatureType::Authenticode
                };
                identity.signature_valid = info.valid;
                identity.signer = info.signer.clone();
                identity.bundle_id = info.package_family.clone();
                if let Some(issuer) = info.issuer {
                    identity.platform_meta.insert("issuer".into(), issuer);
                }
                if let Some(failure) = info.failure {
                    identity
                        .platform_meta
                        .insert("signature_failure".into(), failure);
                }
            }
        }

        identity.trust = trust.classify(
            identity.signature_type,
            identity.signature_valid,
            identity.sha256.as_ref(),
            None,
            identity.signer.as_deref(),
            self.options.default_signed_trust,
        );

        identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct StubVerifier(Option<SignatureInfo>);

    impl AuthenticodeVerifier for StubVerifier {
        fn verify(&self, _path: &Path) -> Option<SignatureInfo> {
            self.0.clone()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ufw-win-{}-{}-{name}",
            std::process::id(),
            now_us()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal file with a valid `MZ` header and `PE\0\0` signature.
    fn write_pe(dir: &Path, name: &str) -> PathBuf {
        let mut bytes = vec![0u8; 0x100];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let path = dir.join(name);
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    fn query(path: &Path) -> IdentityQuery {
        IdentityQuery {
            pid: 4242,
            start_time_us: 99,
            hint_path: Some(path.to_string_lossy().to_string()),
            platform_token: Vec::new(),
        }
    }

    fn signed(signer: &str) -> SignatureInfo {
        SignatureInfo {
            valid: true,
            signer: Some(signer.to_string()),
            issuer: Some("Example CA".into()),
            package_family: None,
            failure: None,
        }
    }

    #[test]
    fn a_validly_signed_image_reaches_its_trust_anchor() {
        let dir = temp_dir("signed");
        let exe = write_pe(&dir, "app.exe");
        let mut db = TrustDatabase::new();
        db.insert("Contoso Ltd", TrustLevel::Trusted);

        let resolver = WindowsResolver::with_verifier(
            ResolverOptions::default(),
            Box::new(StubVerifier(Some(signed("Contoso Ltd")))),
        );
        let id = resolver.resolve(&query(&exe), &db);

        assert_eq!(id.signature_type, SignatureType::Authenticode);
        assert!(id.signature_valid);
        assert_eq!(id.signer.as_deref(), Some("Contoso Ltd"));
        assert_eq!(id.trust, TrustLevel::Trusted);
        assert!(id.sha256.is_some());
        assert_eq!(
            id.platform_meta.get("issuer").map(String::as_str),
            Some("Example CA")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signature_that_fails_verification_is_untrusted() {
        let dir = temp_dir("tampered");
        let exe = write_pe(&dir, "app.exe");
        let mut db = TrustDatabase::new();
        db.insert("Contoso Ltd", TrustLevel::Trusted);

        let tampered = SignatureInfo {
            valid: false,
            signer: Some("Contoso Ltd".into()),
            issuer: None,
            package_family: None,
            failure: Some("TRUST_E_BAD_DIGEST".into()),
        };
        let resolver = WindowsResolver::with_verifier(
            ResolverOptions::default(),
            Box::new(StubVerifier(Some(tampered))),
        );
        let id = resolver.resolve(&query(&exe), &db);

        // A trusted signer name on a broken signature must not grant trust.
        assert_eq!(id.trust, TrustLevel::Untrusted);
        assert_eq!(
            id.platform_meta
                .get("signature_failure")
                .map(String::as_str),
            Some("TRUST_E_BAD_DIGEST")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsigned_image_is_unknown_not_untrusted() {
        let dir = temp_dir("unsigned");
        let exe = write_pe(&dir, "app.exe");
        let resolver = WindowsResolver::with_verifier(
            ResolverOptions::default(),
            Box::new(StubVerifier(None)),
        );
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());
        assert_eq!(id.signature_type, SignatureType::None);
        assert_eq!(id.trust, TrustLevel::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_image_is_untrusted() {
        let resolver = WindowsResolver::new(ResolverOptions::default());
        let id = resolver.resolve(
            &query(Path::new(r"C:\nope\gone.exe")),
            &TrustDatabase::new(),
        );
        assert_eq!(id.trust, TrustLevel::Untrusted);
        assert!(id.platform_meta.contains_key("image_missing"));
    }

    #[test]
    fn a_non_pe_file_is_flagged_even_when_it_is_named_exe() {
        let dir = temp_dir("notpe");
        let fake = dir.join("app.exe");
        std::fs::write(&fake, b"#!/bin/sh\necho hi\n").unwrap();

        let resolver = WindowsResolver::with_verifier(
            ResolverOptions::default(),
            Box::new(StubVerifier(None)),
        );
        let id = resolver.resolve(&query(&fake), &TrustDatabase::new());
        assert!(id.platform_meta.contains_key("not_a_pe_image"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pe_detection_reads_the_header_not_the_extension() {
        let dir = temp_dir("detect");
        let real = write_pe(&dir, "real.dat");
        let fake = dir.join("fake.exe");
        std::fs::write(&fake, b"MZ but no PE header").unwrap();

        assert!(is_pe_image(&real), "a real PE with the wrong extension");
        assert!(!is_pe_image(&fake), "a fake PE with the right extension");
        assert!(!is_pe_image(&dir.join("missing.exe")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_unavailable_verifier_reports_indeterminate_not_unsigned() {
        let dir = temp_dir("unavailable");
        let exe = write_pe(&dir, "app.exe");
        let resolver = WindowsResolver::new(ResolverOptions::default());
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());
        // "Cannot evaluate" must not be reported as "no signature": one is a
        // build limitation, the other is a fact about the binary.
        assert_eq!(id.signature_type, SignatureType::Indeterminate);
        assert_eq!(id.trust, TrustLevel::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_package_family_lands_in_the_bundle_id_field() {
        let dir = temp_dir("store");
        let exe = write_pe(&dir, "app.exe");
        let mut info = signed("Microsoft Corporation");
        info.package_family = Some("Contoso.App_8wekyb3d8bbwe".into());
        let resolver = WindowsResolver::with_verifier(
            ResolverOptions::default(),
            Box::new(StubVerifier(Some(info))),
        );
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());
        assert_eq!(id.bundle_id.as_deref(), Some("Contoso.App_8wekyb3d8bbwe"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
