//! macOS identity resolution: code signature, Team ID and bundle identity.
//!
//! Same split as the Windows resolver, for the same reason: the authoritative
//! answer comes from `SecCodeCopySigningInformation` on a
//! `SecStaticCodeCreateWithPath` (or, better, on the flow's
//! `sourceAppAuditToken`), and that is a Security.framework call. It lives
//! behind [`CodeSignatureReader`]; the macOS build installs an implementation
//! and every other build gets one that reports "cannot evaluate".
//!
//! What is implemented here without the framework is more than a stub. The
//! *bundle* half of macOS identity is plain filesystem structure — an
//! executable inside `Foo.app/Contents/MacOS/` with an `Info.plist` beside it
//! that names its `CFBundleIdentifier` — and that is parsed directly. It
//! matters because a policy is far more likely to name
//! `com.contoso.browser` than a path, and because the bundle identifier
//! recovered from disk can be *checked against* the one the code signature
//! asserts. A mismatch between the two is worth reporting: it means the
//! binary was moved into a bundle it was not signed for.

use std::path::{Path, PathBuf};

use ufw_shared::identity_types::{AppIdentity, IdentityQuery, SignatureType, TrustLevel};
use ufw_shared::now_us;

use super::{hash_file, normalize_path, IdentityResolver, ResolverOptions, TrustDatabase};

/// What `SecCodeCopySigningInformation` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignature {
    /// Whether the static code satisfied its designated requirement.
    pub valid: bool,
    /// Code directory hash (`cdhash`), the identity of the signed code.
    pub cdhash: Option<Vec<u8>>,
    /// Apple Developer Team ID.
    pub team_id: Option<String>,
    /// `CFBundleIdentifier` as asserted by the signature.
    pub signing_id: Option<String>,
    /// Leaf certificate authority string, e.g.
    /// `"Developer ID Application: Contoso Ltd (ABCDE12345)"`.
    pub authority: Option<String>,
    /// The designated requirement, recorded for forensics.
    pub designated_requirement: Option<String>,
    /// Whether the binary is a platform binary shipped by Apple.
    pub platform_binary: bool,
    pub failure: Option<String>,
}

impl CodeSignature {
    pub fn unsigned() -> Self {
        CodeSignature {
            valid: false,
            cdhash: None,
            team_id: None,
            signing_id: None,
            authority: None,
            designated_requirement: None,
            platform_binary: false,
            failure: None,
        }
    }
}

/// The Security.framework half of resolution.
pub trait CodeSignatureReader: Send + Sync + std::fmt::Debug {
    /// `None` means the binary carries no signature at all.
    fn read(&self, path: &Path, audit_token: &[u8]) -> Option<CodeSignature>;
}

/// Used on builds without the Security.framework backend.
#[derive(Debug)]
pub struct UnavailableReader;

impl CodeSignatureReader for UnavailableReader {
    fn read(&self, _path: &Path, _audit_token: &[u8]) -> Option<CodeSignature> {
        Some(CodeSignature {
            failure: Some("code signature evaluation is unavailable in this build".into()),
            ..CodeSignature::unsigned()
        })
    }
}

#[derive(Debug)]
pub struct MacOsResolver {
    options: ResolverOptions,
    reader: Box<dyn CodeSignatureReader>,
}

impl MacOsResolver {
    pub fn new(options: ResolverOptions) -> Self {
        MacOsResolver {
            options,
            reader: Box::new(UnavailableReader),
        }
    }

    pub fn with_reader(options: ResolverOptions, reader: Box<dyn CodeSignatureReader>) -> Self {
        MacOsResolver { options, reader }
    }
}

/// Walk up from an executable to the `.app` bundle containing it.
///
/// The layout is fixed: `Foo.app/Contents/MacOS/foo`. Anything else is not a
/// bundled application, and guessing further would invent identity that is not
/// there.
pub fn enclosing_bundle(executable: &Path) -> Option<PathBuf> {
    let macos_dir = executable.parent()?;
    if macos_dir.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos_dir.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    let bundle = contents.parent()?;
    if bundle.extension()? != "app" {
        return None;
    }
    Some(bundle.to_path_buf())
}

/// Extract `CFBundleIdentifier` from an `Info.plist`.
///
/// Handles the XML form, which is what ships in practice. A binary plist is
/// left to the framework reader; returning `None` here simply means the
/// signature's `signing_id` is the only source, which is the safer of the two
/// anyway.
pub fn bundle_identifier(info_plist: &str) -> Option<String> {
    let key_pos = info_plist.find("<key>CFBundleIdentifier</key>")?;
    let after = &info_plist[key_pos..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")? + start;
    let value = after[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

impl IdentityResolver for MacOsResolver {
    fn name(&self) -> &'static str {
        "macos-codesign"
    }

    fn resolve(&self, query: &IdentityQuery, trust: &TrustDatabase) -> AppIdentity {
        let now = now_us();
        let mut identity = AppIdentity::unresolved(query.pid, now);

        // The Network Extension supplies an audit token rather than a path;
        // the path comes back from the framework or from the module's hint.
        let Some(raw_path) = query.hint_path.clone() else {
            return identity;
        };
        let path = Path::new(&raw_path);
        identity.path = normalize_path(path);
        identity.start_time_us = query.start_time_us;

        if !path.exists() {
            identity
                .platform_meta
                .insert("image_missing".into(), "true".into());
            identity.signature_type = SignatureType::Indeterminate;
            identity.trust = TrustLevel::Untrusted;
            return identity;
        }

        identity.sha256 = hash_file(path, self.options.max_hash_bytes);

        // Bundle identity read from disk, independent of the signature.
        let disk_bundle_id = enclosing_bundle(path).and_then(|bundle| {
            identity
                .platform_meta
                .insert("bundle_path".into(), bundle.to_string_lossy().to_string());
            std::fs::read_to_string(bundle.join("Contents/Info.plist"))
                .ok()
                .as_deref()
                .and_then(bundle_identifier)
        });

        match self.reader.read(path, &query.platform_token) {
            None => {
                identity.signature_type = SignatureType::None;
                identity.signature_valid = false;
                identity.bundle_id = disk_bundle_id;
            }
            Some(sig) => {
                identity.signature_type = if sig.failure.is_some() && sig.authority.is_none() {
                    SignatureType::Indeterminate
                } else {
                    SignatureType::MachOCodeSign
                };
                identity.signature_valid = sig.valid;
                identity.team_id = sig.team_id.clone();
                identity.signer = sig.authority.clone();

                // Prefer the signed identifier; it is the one an attacker
                // cannot change without invalidating the signature.
                identity.bundle_id = sig.signing_id.clone().or(disk_bundle_id.clone());

                if let (Some(signed), Some(on_disk)) = (&sig.signing_id, &disk_bundle_id) {
                    if signed != on_disk {
                        // The executable is sitting in a bundle it was not
                        // signed for. Worth surfacing loudly.
                        identity.platform_meta.insert(
                            "bundle_id_mismatch".into(),
                            format!("signed={signed} on_disk={on_disk}"),
                        );
                        identity.signature_valid = false;
                    }
                }
                if let Some(cdhash) = &sig.cdhash {
                    identity
                        .platform_meta
                        .insert("cdhash".into(), ufw_shared::hash::hex(cdhash));
                }
                if let Some(dr) = sig.designated_requirement {
                    identity
                        .platform_meta
                        .insert("designated_requirement".into(), dr);
                }
                if sig.platform_binary {
                    identity
                        .platform_meta
                        .insert("platform_binary".into(), "true".into());
                }
                if let Some(failure) = sig.failure {
                    identity
                        .platform_meta
                        .insert("signature_failure".into(), failure);
                }

                // An Apple platform binary that validated is as trusted as
                // anything on the system gets, and does not need a trust-
                // database entry to say so.
                if sig.platform_binary && identity.signature_valid {
                    identity.trust = TrustLevel::System;
                    return identity;
                }
            }
        }

        identity.trust = trust.classify(
            identity.signature_type,
            identity.signature_valid,
            identity.sha256.as_ref(),
            identity.team_id.as_deref(),
            identity.signer.as_deref(),
            self.options.default_signed_trust,
        );

        identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StubReader(Option<CodeSignature>);

    impl CodeSignatureReader for StubReader {
        fn read(&self, _path: &Path, _token: &[u8]) -> Option<CodeSignature> {
            self.0.clone()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ufw-mac-{}-{}-{name}",
            std::process::id(),
            now_us()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build `Foo.app/Contents/{Info.plist,MacOS/foo}`.
    fn write_bundle(root: &Path, app: &str, bundle_id: &str) -> PathBuf {
        let bundle = root.join(format!("{app}.app"));
        let macos = bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(
            bundle.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>{app}</string>
  <key>CFBundleIdentifier</key>
  <string>{bundle_id}</string>
</dict>
</plist>
"#
            ),
        )
        .unwrap();
        let exe = macos.join(app.to_ascii_lowercase());
        std::fs::write(&exe, b"\xcf\xfa\xed\xfe mach-o").unwrap();
        exe
    }

    fn query(path: &Path) -> IdentityQuery {
        IdentityQuery {
            pid: 501,
            start_time_us: 42,
            hint_path: Some(path.to_string_lossy().to_string()),
            platform_token: vec![1, 2, 3, 4],
        }
    }

    fn signed(team: &str, signing_id: &str) -> CodeSignature {
        CodeSignature {
            valid: true,
            cdhash: Some(vec![0xab; 20]),
            team_id: Some(team.to_string()),
            signing_id: Some(signing_id.to_string()),
            authority: Some(format!("Developer ID Application: Contoso Ltd ({team})")),
            designated_requirement: Some(format!("identifier \"{signing_id}\"")),
            platform_binary: false,
            failure: None,
        }
    }

    #[test]
    fn bundle_identifier_is_parsed_from_info_plist() {
        let plist = r#"
<dict>
  <key>CFBundleName</key><string>Browser</string>
  <key>CFBundleIdentifier</key><string>com.contoso.browser</string>
</dict>"#;
        assert_eq!(
            bundle_identifier(plist).as_deref(),
            Some("com.contoso.browser")
        );
        assert_eq!(bundle_identifier("<dict></dict>"), None);
        assert_eq!(
            bundle_identifier("<key>CFBundleIdentifier</key><string></string>"),
            None
        );
    }

    #[test]
    fn the_enclosing_bundle_is_found_only_for_the_real_layout() {
        let dir = temp_dir("layout");
        let exe = write_bundle(&dir, "Browser", "com.contoso.browser");
        assert_eq!(
            enclosing_bundle(&exe).map(|p| p.file_name().unwrap().to_string_lossy().to_string()),
            Some("Browser.app".to_string())
        );
        // A binary that merely lives somewhere is not in a bundle.
        assert_eq!(enclosing_bundle(Path::new("/usr/bin/curl")), None);
        assert_eq!(enclosing_bundle(Path::new("/tmp/Foo.app/foo")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signed_bundled_app_resolves_to_its_team_and_identifier() {
        let dir = temp_dir("signed");
        let exe = write_bundle(&dir, "Browser", "com.contoso.browser");
        let mut db = TrustDatabase::new();
        db.insert("ABCDE12345", TrustLevel::Trusted);

        let resolver = MacOsResolver::with_reader(
            ResolverOptions::default(),
            Box::new(StubReader(Some(signed(
                "ABCDE12345",
                "com.contoso.browser",
            )))),
        );
        let id = resolver.resolve(&query(&exe), &db);

        assert_eq!(id.signature_type, SignatureType::MachOCodeSign);
        assert!(id.signature_valid);
        assert_eq!(id.team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(id.bundle_id.as_deref(), Some("com.contoso.browser"));
        assert_eq!(id.trust, TrustLevel::Trusted);
        assert!(id.platform_meta.contains_key("cdhash"));
        assert!(id.platform_meta.contains_key("designated_requirement"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_binary_planted_in_someone_elses_bundle_is_caught() {
        // The signature says one identifier, the bundle on disk says another:
        // the executable was moved into a bundle it was not signed for.
        let dir = temp_dir("mismatch");
        let exe = write_bundle(&dir, "Browser", "com.contoso.browser");
        let mut db = TrustDatabase::new();
        db.insert("ABCDE12345", TrustLevel::Trusted);

        let resolver = MacOsResolver::with_reader(
            ResolverOptions::default(),
            Box::new(StubReader(Some(signed("ABCDE12345", "com.evil.tool")))),
        );
        let id = resolver.resolve(&query(&exe), &db);

        assert!(id.platform_meta.contains_key("bundle_id_mismatch"));
        assert!(!id.signature_valid);
        assert_eq!(id.trust, TrustLevel::Untrusted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_apple_platform_binary_is_system_trusted_without_a_database_entry() {
        let dir = temp_dir("platform");
        let exe = dir.join("softwareupdate");
        std::fs::write(&exe, b"\xcf\xfa\xed\xfe").unwrap();

        let sig = CodeSignature {
            valid: true,
            platform_binary: true,
            authority: Some("Software Signing".into()),
            ..CodeSignature::unsigned()
        };
        let resolver =
            MacOsResolver::with_reader(ResolverOptions::default(), Box::new(StubReader(Some(sig))));
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());
        assert_eq!(id.trust, TrustLevel::System);
        assert!(id.platform_meta.contains_key("platform_binary"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsigned_binary_still_reports_its_bundle_identity() {
        let dir = temp_dir("unsigned");
        let exe = write_bundle(&dir, "Sketchy", "com.sketchy.app");
        let resolver =
            MacOsResolver::with_reader(ResolverOptions::default(), Box::new(StubReader(None)));
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());

        assert_eq!(id.signature_type, SignatureType::None);
        assert_eq!(id.trust, TrustLevel::Unknown);
        // The identifier is still useful for a log line, but it came from disk
        // and buys no trust.
        assert_eq!(id.bundle_id.as_deref(), Some("com.sketchy.app"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_image_is_untrusted() {
        let resolver = MacOsResolver::new(ResolverOptions::default());
        let id = resolver.resolve(&query(Path::new("/nope/gone")), &TrustDatabase::new());
        assert_eq!(id.trust, TrustLevel::Untrusted);
    }

    #[test]
    fn the_unavailable_reader_reports_indeterminate() {
        let dir = temp_dir("unavailable");
        let exe = dir.join("bin");
        std::fs::write(&exe, b"x").unwrap();
        let resolver = MacOsResolver::new(ResolverOptions::default());
        let id = resolver.resolve(&query(&exe), &TrustDatabase::new());
        assert_eq!(id.signature_type, SignatureType::Indeterminate);
        assert_eq!(id.trust, TrustLevel::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
