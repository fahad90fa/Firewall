//! `ufw-manifest` — generate and verify a release integrity manifest.
//!
//! Build-time tooling. It hashes the shipped artifacts into a canonical
//! manifest and signs that manifest with an HMAC key, so a deployer can prove
//! the set of files they received is exactly the set that was released. The
//! logic lives in `ufw_shared::manifest`, tested there; this is the thin
//! file-I/O wrapper.
//!
//! ```text
//!   # After building and signing the individual artifacts:
//!   ufw-manifest generate --version 1.2.3 --key release.key \
//!       --out dist/manifest.json dist/ufwd dist/ufwctl dist/ufw.ko
//!
//!   # On the receiving side, before installing:
//!   ufw-manifest verify --key release.key --manifest dist/manifest.json --dir dist
//! ```
//!
//! The key is the raw bytes of `--key` (a file of random bytes, kept secret).
//! It never appears in the manifest or the signature; only the HMAC does.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ufw_shared::manifest::{self, Manifest};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("generate") => generate(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("-h") | Some("--help") | None => {
            usage();
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown subcommand `{other}` (try --help)")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ufw-manifest: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "\
ufw-manifest — release integrity manifest

USAGE:
    ufw-manifest generate --version <V> [--key <FILE>] --out <FILE> [--sig <FILE>] <artifact>...
    ufw-manifest verify   [--key <FILE>] --manifest <FILE> [--sig <FILE>] [--dir <DIR>]

generate hashes each artifact into a canonical manifest at --out. With --key it
also writes a detached HMAC signature (default: <out>.sig).

verify recomputes each artifact's hash from --dir (default: the manifest's
directory) and, with --key and --sig, checks the manifest signature. It exits
non-zero if any artifact is missing, altered, or the signature does not match."
    );
}

/// A tiny `--flag value` extractor over the argument list. Positional arguments
/// (the ones without a leading `--`) are collected separately.
struct Args {
    flags: Vec<(String, String)>,
    positional: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut flags = Vec::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("--{name} needs a value"))?;
            flags.push((name.to_string(), value.clone()));
            i += 2;
        } else {
            positional.push(a.clone());
            i += 1;
        }
    }
    Ok(Args { flags, positional })
}

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn require(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }
}

fn generate(args: &[String]) -> Result<(), String> {
    let a = parse_args(args)?;
    let version = a.require("version")?;
    let out = PathBuf::from(a.require("out")?);
    if a.positional.is_empty() {
        return Err("no artifacts given".into());
    }

    let mut entries = Vec::with_capacity(a.positional.len());
    for path in &a.positional {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let name = basename(path);
        entries.push((name, bytes));
    }

    let manifest = Manifest::build(version, &entries)?;
    let json = manifest.to_json();
    std::fs::write(&out, &json).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!(
        "wrote {} ({} artifact(s), version {version})",
        out.display(),
        manifest.artifacts.len()
    );

    if let Some(keyfile) = a.get("key") {
        let key = std::fs::read(keyfile).map_err(|e| format!("cannot read key {keyfile}: {e}"))?;
        let sig = manifest::sign(&manifest, &key);
        let sig_path = a
            .get("sig")
            .map(PathBuf::from)
            .unwrap_or_else(|| with_suffix(&out, ".sig"));
        std::fs::write(&sig_path, format!("{sig}\n"))
            .map_err(|e| format!("cannot write {}: {e}", sig_path.display()))?;
        println!("wrote {} (HMAC-SHA256)", sig_path.display());
    }
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    let a = parse_args(args)?;
    let manifest_path = PathBuf::from(a.require("manifest")?);
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("cannot read {}: {e}", manifest_path.display()))?;
    let manifest = Manifest::parse(&text)?;

    // The signature, when a key is supplied. Checked first: if the manifest
    // itself is forged, its list of hashes cannot be trusted to verify anything.
    if let Some(keyfile) = a.get("key") {
        let key = std::fs::read(keyfile).map_err(|e| format!("cannot read key {keyfile}: {e}"))?;
        let sig_path = a
            .get("sig")
            .map(PathBuf::from)
            .unwrap_or_else(|| with_suffix(&manifest_path, ".sig"));
        let sig = std::fs::read_to_string(&sig_path)
            .map_err(|e| format!("cannot read {}: {e}", sig_path.display()))?;
        if !manifest::verify(&manifest, &key, sig.trim()) {
            return Err(format!(
                "SIGNATURE MISMATCH: {} does not sign {}",
                sig_path.display(),
                manifest_path.display()
            ));
        }
        println!("signature ok");
    }

    let dir = a
        .get("dir")
        .map(PathBuf::from)
        .or_else(|| manifest_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    let mut ok = 0usize;
    for artifact in &manifest.artifacts {
        let path = dir.join(&artifact.name);
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("cannot read artifact {}: {e}", path.display()))?;
        if !manifest.verify_artifact(&artifact.name, &bytes) {
            return Err(format!(
                "ARTIFACT MISMATCH: {} does not match the manifest",
                path.display()
            ));
        }
        ok += 1;
    }
    println!(
        "verified {ok} artifact(s) against {}",
        manifest_path.display()
    );
    Ok(())
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}
