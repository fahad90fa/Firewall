# Release provenance & signed apt repository

There are two independent ways to verify a Unified Firewall build. The first is
**live on every release with no key for us to manage**; the second is the
traditional apt trust path.

## 1. Keyless build provenance (recommended, no key required)

Every tagged release runs `.github/workflows/release.yml`, which builds the
`.deb` and produces a **SLSA build-provenance attestation** signed by GitHub's
OIDC identity and recorded in the public **Rekor transparency log**. No private
key lives on anyone's laptop — nothing to leak, rotate, or forget to publish —
and it happens automatically. Anyone can verify that a given `.deb` was built
from a specific commit by our workflow:

```sh
gh attestation verify unified-firewall_0.1.0_amd64.deb --repo fahad90fa/Firewall
```

This proves *provenance* (who built it, from what source, in what workflow),
which is exactly the "is this the real artifact?" question. It pairs with the
shipped SBOM (`sbom.cdx.json`) for the "what's inside?" question.

## 2. Signed apt repository (traditional apt trust)

A bare `.deb` has no cryptographic provenance — which is why a software centre
labels it "unsigned / untrusted third party." The fix is to serve it from an
**apt repository whose `Release` file is GPG-signed** by a key the user has
explicitly trusted. Then `apt update` / `apt install` verify the package chain
automatically. Unlike the keyless attestation above, this path needs a
maintainer-held GPG key (below).

## Maintainer: sign & publish

1. Have a signing key in your gpg keyring (create one once):
   ```sh
   gpg --quick-generate-key "Unified Firewall <releases@unifiedfirewall.dev>" ed25519 sign never
   ```
2. Build the `.deb` (and, optionally, the SBOM):
   ```sh
   bash build/linux/build-deb.sh
   sh   scripts/gen-sbom.sh > sbom.cdx.json      # optional, shipped alongside
   ```
3. Generate the **signed flat repo** (you hold the key; nothing private is
   written to the repo):
   ```sh
   GPG_KEY="releases@unifiedfirewall.dev" build/linux/sign-release.sh
   # → dist/apt/ : the .deb, Packages[.gz], Release, InRelease, Release.gpg,
   #               unified-firewall-archive-keyring.asc, *.sha256, sbom.cdx.json
   ```
   The script refuses to finish unless `gpg --verify InRelease` passes.
4. Publish `dist/apt/`'s contents at a stable URL. To serve it from the same
   Vercel site as the download page, copy it in:
   ```sh
   mkdir -p website/public/apt && cp -r dist/apt/. website/public/apt/
   ```
   → reachable at `https://<your-site>/apt/`.

For reproducible `Release` files across rebuilds, pass a fixed
`RELEASE_DATE="$(date -Ru)"`.

## Customer: trust the repo & install

```sh
# 1. trust the publisher's key (one time)
curl -fsSL https://<your-site>/apt/unified-firewall-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/unified-firewall.gpg

# 2. add the repo, pinned to that key
echo "deb [signed-by=/usr/share/keyrings/unified-firewall.gpg] https://<your-site>/apt ./" \
  | sudo tee /etc/apt/sources.list.d/unified-firewall.list

# 3. install — apt now verifies the signature and checksums
sudo apt update
sudo apt install unified-firewall
```

Updates then arrive through `apt upgrade` like any other package, cryptographically
verified — no more downloading a loose `.deb`.

## What this does and doesn't prove

- **Does:** prove the package you install is the one the key-holder published,
  unmodified in transit or at rest. This is the standard Debian trust model.
- **Doesn't:** attest *what the code does* — that's the job of the source, the
  SBOM (`sbom.cdx.json`, shipped in the repo), and a third-party audit.
- Per-`.deb` embedded signatures (`debsigs`) are a possible addition, but the
  signed `Release` is the mechanism `apt` actually checks, so it's the one that
  matters.

## Verification note

In the build sandbox used to author this, `gpg-agent` is unavailable, so the
signing step could not be exercised there; the repo-index generation (Packages,
Release, checksums) is verified, and the signing commands are the canonical
`gpg --clearsign` / `-abs` that run on any host with a keyring.
