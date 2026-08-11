//! Release manifest: supply-chain integrity for the shipped artifacts.
//!
//! Signing proves each artifact came from us. A manifest proves the *set* is
//! the set we shipped — that a deployer received exactly these files, this many
//! bytes each, hashing to these values, and not a substituted driver alongside a
//! genuine daemon. The two are complementary: a per-file signature says "this
//! binary is authentic", the manifest says "and it is the only binary, at this
//! version, that belongs in this release".
//!
//! The format is deliberately small and canonical: artifacts sorted by name,
//! each `{name, size, sha256}`, serialized with the workspace's own JSON writer.
//! Canonical ordering is what makes the manifest's own signature reproducible —
//! sign the bytes of [`Manifest::to_json`], and any party can recompute them and
//! check the MAC. The signature uses [`crate::hash::hmac_sha256`], the same
//! length-extension-resistant primitive the fleet bundles use, so a manifest
//! cannot be extended with an extra artifact after signing.
//!
//! This is build-time tooling — the `ufw-manifest` binary drives it over files —
//! but the logic lives here, tested against byte slices, so the format has one
//! authoritative implementation rather than a shell script and a verifier that
//! can drift.

use crate::hash::{self, constant_time_eq, hmac_sha256, sha256};
use crate::json::{self, JsonWriter};

/// One shipped file: its name, its size, and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The set of artifacts in a release, plus the release version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    /// Build a manifest by hashing each `(name, content)` pair. Duplicate names
    /// are an error — a manifest with two entries for one name cannot verify a
    /// file unambiguously. Artifacts are stored sorted by name so the
    /// serialization, and therefore the signature, is independent of the order
    /// the build produced them in.
    pub fn build(version: &str, entries: &[(String, Vec<u8>)]) -> Result<Self, String> {
        let mut artifacts = Vec::with_capacity(entries.len());
        for (name, content) in entries {
            if artifacts.iter().any(|a: &Artifact| &a.name == name) {
                return Err(format!("duplicate artifact name `{name}`"));
            }
            artifacts.push(Artifact {
                name: name.clone(),
                size: content.len() as u64,
                sha256: sha256(content),
            });
        }
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Manifest {
            version: version.to_string(),
            artifacts,
        })
    }

    pub fn find(&self, name: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }

    /// Does `content` match the recorded size and hash for `name`? A name the
    /// manifest does not list returns false: an artifact nobody vouched for is
    /// not verified simply because it happens to exist.
    pub fn verify_artifact(&self, name: &str, content: &[u8]) -> bool {
        match self.find(name) {
            Some(a) => {
                a.size == content.len() as u64 && constant_time_eq(&a.sha256, &sha256(content))
            }
            None => false,
        }
    }

    /// The canonical serialization. Stable for a given manifest regardless of
    /// how it was built, which is what the signature is computed over.
    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::with_capacity(256 + self.artifacts.len() * 128);
        w.begin_object();
        w.str_field("version", &self.version);
        w.begin_array_field("artifacts");
        for a in &self.artifacts {
            w.begin_object();
            w.str_field("name", &a.name);
            w.u64_field("size", a.size);
            w.str_field("sha256", &hash::hex(&a.sha256));
            w.end_object();
        }
        w.end_array();
        w.end_object();
        w.finish()
    }

    /// Parse a manifest. Re-sorts by name so a hand-edited or reordered file
    /// still produces the canonical form (and thus the same signature) when
    /// re-serialized.
    pub fn parse(text: &str) -> Result<Self, String> {
        let root = json::parse(text).map_err(|e| format!("invalid JSON: {e}"))?;
        let version = root
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or("manifest is missing a string `version`")?
            .to_string();
        let items = root
            .get("artifacts")
            .and_then(|v| v.as_array())
            .ok_or("manifest is missing an `artifacts` array")?;

        let mut artifacts = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("artifact {i} is missing `name`"))?
                .to_string();
            let size = item
                .get("size")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("artifact `{name}` is missing `size`"))?;
            let hex = item
                .get("sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("artifact `{name}` is missing `sha256`"))?;
            let bytes = hash::unhex(hex)
                .ok_or_else(|| format!("artifact `{name}` has a malformed sha256"))?;
            if bytes.len() != 32 {
                return Err(format!("artifact `{name}` sha256 is not 32 bytes"));
            }
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&bytes);
            artifacts.push(Artifact {
                name,
                size,
                sha256: sha,
            });
        }
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Manifest { version, artifacts })
    }
}

/// The detached signature over a manifest: `hex(HMAC-SHA256(key, to_json))`.
pub fn sign(manifest: &Manifest, key: &[u8]) -> String {
    hash::hex(&hmac_sha256(key, manifest.to_json().as_bytes()))
}

/// Verify a manifest's detached signature in constant time. A malformed hex
/// signature verifies false rather than erroring, so a caller cannot tell a
/// wrong-length signature from a wrong-value one by the response.
pub fn verify(manifest: &Manifest, key: &[u8], signature_hex: &str) -> bool {
    let expected = hmac_sha256(key, manifest.to_json().as_bytes());
    match hash::unhex(signature_hex) {
        Some(sig) => constant_time_eq(&expected, &sig),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<(String, Vec<u8>)> {
        vec![
            ("ufwd".into(), b"daemon binary bytes".to_vec()),
            ("ufw.ko".into(), b"kernel module bytes".to_vec()),
            ("ufwctl".into(), b"cli binary bytes".to_vec()),
        ]
    }

    #[test]
    fn build_hashes_and_sorts() {
        let m = Manifest::build("1.2.3", &sample()).unwrap();
        assert_eq!(m.version, "1.2.3");
        // Sorted by name regardless of input order.
        let names: Vec<&str> = m.artifacts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["ufw.ko", "ufwctl", "ufwd"]);
        let d = m.find("ufwd").unwrap();
        assert_eq!(d.size, "daemon binary bytes".len() as u64);
        assert_eq!(d.sha256, sha256(b"daemon binary bytes"));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let e = Manifest::build(
            "1",
            &[("x".into(), b"a".to_vec()), ("x".into(), b"b".to_vec())],
        )
        .unwrap_err();
        assert!(e.contains("duplicate"), "{e}");
    }

    #[test]
    fn canonical_form_is_order_independent() {
        let a = Manifest::build("1", &sample()).unwrap();
        let mut reversed = sample();
        reversed.reverse();
        let b = Manifest::build("1", &reversed).unwrap();
        // Different build order, identical bytes — which is what makes the
        // signature reproducible.
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn json_round_trips() {
        let m = Manifest::build("2.0.0", &sample()).unwrap();
        let parsed = Manifest::parse(&m.to_json()).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn verify_artifact_catches_tampering() {
        let m = Manifest::build("1", &sample()).unwrap();
        assert!(m.verify_artifact("ufwd", b"daemon binary bytes"));
        // One flipped byte.
        assert!(!m.verify_artifact("ufwd", b"daemon binary bytez"));
        // Right prefix, wrong length.
        assert!(!m.verify_artifact("ufwd", b"daemon binary byte"));
        // An artifact the manifest never listed is not "verified".
        assert!(!m.verify_artifact("evil.so", b"anything"));
    }

    #[test]
    fn a_signature_round_trips_and_rejects_tampering() {
        let key = b"a-release-signing-key-32-bytes!!";
        let m = Manifest::build("1", &sample()).unwrap();
        let sig = sign(&m, key);
        assert!(verify(&m, key, &sig));

        // A different key does not verify.
        assert!(!verify(&m, b"the-wrong-key-entirely-32-bytes!", &sig));

        // A manifest with one more artifact does not verify under the old
        // signature — the length-extension attack HMAC exists to stop.
        let mut tampered = sample();
        tampered.push(("backdoor.ko".into(), b"evil".to_vec()));
        let m2 = Manifest::build("1", &tampered).unwrap();
        assert!(!verify(&m2, key, &sig));

        // A malformed signature is false, not an error.
        assert!(!verify(&m, key, "not-hex"));
        assert!(!verify(&m, key, ""));
    }

    #[test]
    fn parse_rejects_malformed_manifests() {
        for (src, needle) in [
            ("{}", "version"),
            (r#"{"version":"1"}"#, "artifacts"),
            (
                r#"{"version":"1","artifacts":[{"size":1,"sha256":"00"}]}"#,
                "name",
            ),
            (
                r#"{"version":"1","artifacts":[{"name":"x","sha256":"00"}]}"#,
                "size",
            ),
            (
                r#"{"version":"1","artifacts":[{"name":"x","size":1,"sha256":"zz"}]}"#,
                "malformed sha256",
            ),
            (
                r#"{"version":"1","artifacts":[{"name":"x","size":1,"sha256":"00"}]}"#,
                "not 32 bytes",
            ),
        ] {
            let e = Manifest::parse(src).unwrap_err();
            assert!(
                e.contains(needle),
                "for {src:?} expected {needle:?}, got {e:?}"
            );
        }
    }
}
