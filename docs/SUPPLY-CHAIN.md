# Supply-chain assurance

A firewall is trusted infrastructure, so its provenance should be auditable.
This project is built to make that cheap.

## Zero external crates by default

The default build uses **no third-party Rust crates** — the YAML/JSON/TOML
parsers, the SHA-256, the HTTP server, and everything else are hand-rolled in
this workspace. That is a deliberate supply-chain decision: nothing outside
this repository executes in the default binaries.

The only external dependencies in `Cargo.lock` (`ring`, `rustls`, and their
transitive crates) are pulled in **only** by the opt-in `tls` feature, used
when the WAF terminates real HTTPS (`--features tls`). The installer never
enables it, so a stock install stays dependency-free.

## Software Bill of Materials (SBOM)

Generate a CycloneDX 1.5 SBOM straight from the committed lockfile — no network,
no external tooling:

```sh
scripts/gen-sbom.sh > sbom.cdx.json
```

Each component records its `purl`, its source (workspace members have none —
they are first-party), and the crate's SHA-256 where the lockfile pins one. The
document's serial number is derived from the lockfile's checksum, so the same
`Cargo.lock` always produces byte-identical output — the SBOM itself is
reproducible.

## Reproducible builds

The release binaries are deterministic given a pinned toolchain. To reproduce:

```sh
# 1. Pin the toolchain (record the exact version you shipped with).
rustup toolchain install 1.XX.0        # match rust-toolchain if present
# 2. Build from the committed lockfile so dependency resolution can't drift.
cargo build --release --locked
# 3. Strip build-path and timestamp non-determinism.
export SOURCE_DATE_EPOCH=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/build"
cargo build --release --locked
```

Two builds of the same commit, with the same toolchain and these flags, produce
bit-identical artifacts. Compare with `sha256sum target/release/*` across
machines to verify.

## Verifying an install

- The installed binaries live under `PREFIX/bin` (default `/usr/local/bin`);
  hash them and compare against a build you reproduced.
- The kernel parsers are continuously fuzzed in CI (`.github/workflows/fuzz.yml`)
  so the highest-risk attack surface — untrusted packet parsing — is exercised
  against crashes on every change.
