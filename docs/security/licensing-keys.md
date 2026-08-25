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

## Hardware binding (anti-clone)

A signed token binds a grant to a *machine-id*. But `/etc/machine-id` is a plain
file an owner can copy. So activation also records a **hardware anchor**: a
salted SHA-256 over the host's stable, firmware-rooted identifiers —
`/sys/class/dmi/id/product_uuid`, the board/product serials, and machine-id —
computed in `hardware_binding()` (`cli/src/bin/ufw-nft/license.rs`).

- Each source is best-effort and read-only. A board that doesn't expose the DMI
  fields contributes fewer sources and the anchor degrades toward machine-id —
  never an error.
- On every enforcement decision the firewall recomputes the anchor and compares
  it to the one recorded at activation. If they differ, the license was copied
  to different hardware and enforcement is refused (`status: moved_hardware`).
  `ufw-nft license status` shows whether the anchor matches this machine.
- Backward-compatible: a store written by an older client has no anchor, and the
  check is skipped for it.

This raises the cost of cloning a paid license from "copy a file" to "spoof the
firmware identity of the licensed board" — a deterrent layer, not an unbreakable
bind.

## The honest answer to "root can bypass it": server-gated value

No client-side check survives an owner with root who is willing to patch the
binary — that is true of every software license and we do not pretend otherwise
(threat-model adversary A4). The durable defense is **not** local: it is that the
parts of the product with ongoing value authenticate to the backend with the
license, so a bypassed local client simply does not receive them —

- fleet policy distribution and the fleet control plane,
- threat-intelligence / signature feed updates,
- managed telemetry aggregation and the hosted console.

A cracked binary can skip its own local gate; it cannot fabricate the server's
signature feed or fleet plane. So the local checks (Ed25519 + hardware binding)
are the *deterrent* that keeps honest installs honest, and the server-side gate
is what actually protects the recurring-revenue surface. Design the paid value to
live behind the server relationship, not behind a client boolean.

## Threat note

Ed25519 + hardware binding raise the bar from "deterrent" to "the client cannot
forge or silently edit a grant, and cannot move it to another machine by copying
a file." That is a real improvement to the floor. The **ceiling** is unchanged
and stated honestly: an owner who patches the firewall binary itself defeats any
client-side licensing — which is exactly why the paid value is server-gated
rather than trusted to the client (see above, and `threat-model.md` A4).
