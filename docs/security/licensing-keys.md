# Licensing signature keys (Ed25519)

The license token is protected two ways:

- **HMAC-SHA256** (`LICENSE_SIGNING_SECRET`) — always present. A *deterrent*: the
  secret is server-side, so the client can't verify it and can't forge a token
  that the *server* would later accept, but a root owner can still edit their own
  cached state. This is the default-build behavior.
- **Ed25519** (`LICENSE_ED25519_PKCS8`) — optional but recommended. The server
  signs the token payload with a private key; the firewall built with
  `--features tls` (which the `.deb` ships) verifies it with an **embedded public
  key**. The client can now *cryptographically* confirm the server issued this
  exact grant for this exact machine, and editing `license.json` to extend an
  expiry fails verification. The client holds only the public key — it can verify
  but never forge.

## Where each half lives

| | HMAC | Ed25519 |
| --- | --- | --- |
| private/secret | `LICENSE_SIGNING_SECRET` (Supabase secret) | `LICENSE_ED25519_PKCS8` (Supabase secret) |
| public part | — (symmetric) | embedded in the firewall: `LICENSE_ED25519_PUBKEY_HEX` in `cli/src/bin/ufw-nft/license.rs` |
| who verifies | nobody client-side | the `--features tls` firewall |

## Generate / rotate the Ed25519 keypair

```sh
# private key
openssl genpkey -algorithm ed25519 -out ufwlic.pem

# PUBLIC key, 32 raw bytes as hex → paste into LICENSE_ED25519_PUBKEY_HEX
openssl pkey -in ufwlic.pem -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo

# PRIVATE key, PKCS8 DER base64 → set as the Supabase secret (never commit)
openssl pkey -in ufwlic.pem -outform DER | base64 -w0; echo
```

Then:

```sh
supabase secrets set LICENSE_ED25519_PKCS8="<the base64 from above>"
supabase functions deploy activate   # and validate — they now include sig_ed25519
```

Update `LICENSE_ED25519_PUBKEY_HEX` in `license.rs` to the new public key and
rebuild the `.deb` (`--features tls`). Rotating invalidates tokens signed by the
old key at their next online re-check — clients just re-activate.

## Behavior when the key isn't set

Fully backward-compatible. If `LICENSE_ED25519_PKCS8` is unset, the functions
return an empty `sig_ed25519`, and the firewall falls back to the HMAC-deterrent
behavior — nothing breaks, you just don't get the stronger guarantee until you
set the secret and redeploy.

## Threat note

Ed25519 raises the bar from "deterrent" to "the client cannot forge or silently
edit a grant," which is a real improvement. It still does **not** defend against
an owner who patches the firewall binary itself — that's out of scope for
client-side licensing (see `docs/security/threat-model.md`, adversary A4). The
honest ceiling is unchanged; the floor is higher.
