# /apt/ — signed apt repository (published here)

This directory is served at `https://<your-site>/apt/`. It is where the
**GPG-signed apt repository** is published so customers can install and update
`unified-firewall` with cryptographic verification (see the download page's
"Verified install" section and [`docs/apt-repo.md`](../../../docs/apt-repo.md)).

It ships intentionally **empty** (this README only). Publishing is a maintainer
step because it requires the private GPG signing key, which is never committed:

```sh
# from the repo root, with your signing key in gpg:
bash build/linux/build-deb.sh
GPG_KEY="releases@unifiedfirewall.dev" build/linux/sign-release.sh
cp -r dist/apt/. website/public/apt/     # populate this directory
# then redeploy the site (Vercel copies public/ → the served root)
```

After that, this directory holds: the `.deb`, `Packages[.gz]`, `Release`,
`InRelease`, `Release.gpg`, `unified-firewall-archive-keyring.asc`, the
`.sha256` checksums, and `sbom.cdx.json`. Until then, the verified-install
commands on the download page will 404 — that is expected and safe; the loose
`.deb` download works regardless.
