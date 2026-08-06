# Signing and release integrity

How a build becomes something a stock machine will actually load, and how a
deployer proves they received what was shipped.

There are two distinct guarantees here, and a release needs both:

- **Signing** — per-platform, proves the operating system will *load* the code.
  An unsigned kernel driver does not warn; it refuses to load, and the firewall
  is simply absent. This is the "won't even start on a stock machine" gap.
- **The release manifest** — cross-platform, proves the *set* of files is the
  set that was released: a genuine daemon next to a substituted driver is caught
  because the driver's hash is not in the signed manifest.

None of the signing steps can run in the source repository — they need real
signing keys, which live in a secrets store, not in git. What lives here is the
tooling and the exact procedure.

## Per-platform signing

### Windows — Authenticode

The driver and the user-mode binaries are signed with `signtool` against an EV
code-signing certificate; the driver additionally needs attestation signing
through the Windows Hardware Dev Center for the kernel to load it under Secure
Boot. See [`build/windows/driver_signing.ps1`](../../build/windows/driver_signing.ps1).

### macOS — codesign + notarization

Signed inside-out (extension, then app over it), then notarized with Apple and
stapled. The Team ID is substituted at signing time because `IPCBridge.swift`
pins it as the peer identity on the XPC channel. See
[`build/macos/signing.sh`](../../build/macos/signing.sh) and
[`build/macos/notarize.sh`](../../build/macos/notarize.sh).

### Linux — module signing for Secure Boot

The `.ko` is signed with the kernel's own `sign-file` against a key the running
kernel trusts. On the common case — a self-built or DKMS module — that means a
Machine Owner Key (MOK) enrolled once with `mokutil`:

```sh
KEY=ufw_signing.priv CERT=ufw_signing.der \
    build/linux/sign-module.sh build/stage/ufw.ko
```

Run with no key, the script generates a MOK pair and prints the one-time
`mokutil` enrolment steps. See
[`build/linux/sign-module.sh`](../../build/linux/sign-module.sh). This is the
Linux equivalent of Authenticode: without it, `insmod` fails with "Key was
rejected by service" on any Secure Boot host.

## The release manifest

After the artifacts are built and individually signed, hash them into one
canonical manifest and sign that manifest with a release HMAC key:

```sh
cargo build --release --bin ufw-manifest

ufw-manifest generate --version 1.2.3 --key release.key \
    --out dist/manifest.json \
    dist/ufwd dist/ufwctl dist/ufw.ko
# writes dist/manifest.json and dist/manifest.json.sig
```

On the receiving side, before installing anything:

```sh
ufw-manifest verify --key release.key --manifest dist/manifest.json --dir dist
```

`verify` recomputes every artifact's SHA-256, checks it against the manifest,
and checks the manifest's own HMAC signature — exiting non-zero if any file is
missing, altered, or the signature does not match. The manifest is checked
*first*: a forged manifest's list of hashes cannot be trusted to verify
anything, so its signature is the root of the check.

The format and the guarantee are implemented once, in
`shared/src/manifest.rs`, and tested there (tamper detection, the
length-extension resistance HMAC provides, order-independent canonical form).
The `ufw-manifest` binary is only the file-I/O around that library, so the shell
procedure above and any in-process verification cannot drift.

### Why HMAC and not a bare hash

A plain SHA-256 manifest tells a deployer the files are internally consistent; it
does not stop an attacker who replaces both an artifact *and* its manifest entry.
The HMAC signature closes that: without the release key, an attacker cannot
produce a manifest that verifies, and — because it is HMAC rather than
`sha256(key ‖ manifest)` — cannot append an extra artifact to a signed manifest
either.

## What a release run does, in order

1. Build every artifact (`cargo build --release`, the kernel module, the macOS
   app, the Windows driver).
2. Sign each per its platform (above).
3. Generate and sign the manifest over the signed artifacts.
4. Publish the artifacts, the manifest, and the manifest signature together.
5. A deployer runs `ufw-manifest verify` before install, then installs; the OS
   performs the load-time signature check on the signed binaries.

Steps 2 and 3 need the secret keys and therefore run in the release pipeline,
not here. Everything they invoke lives in `build/` and is version-controlled, so
the procedure is auditable even though the keys are not present.
