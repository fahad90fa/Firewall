#!/bin/sh
# Sign the Unified Firewall kernel module for Secure Boot.
#
# On a machine with Secure Boot enabled — which is the default on essentially
# every server and laptop shipped in the last decade — the kernel refuses to
# load an unsigned module. An unsigned `ufw.ko` does not fail loudly; it fails
# at `insmod` with "Key was rejected by service", and the firewall simply is not
# there. That is the "won't even start on a stock machine" gap, in its Linux
# form. This script closes it.
#
# # What signing a module is, and is not
#
# Signing attaches a signature the *running kernel* can check against a key in
# its keyring. It is not the same as the release manifest (`ufw-manifest`),
# which proves the file is the one we shipped: this proves the kernel is willing
# to load it. A release needs both — the manifest for the human deciding to
# install, the module signature for the kernel deciding to load.
#
# # The two ways the key gets trusted
#
#   * MOK (Machine Owner Key): you generate a keypair, enrol the public half
#     with `mokutil`, reboot once to confirm at the firmware prompt, and from
#     then on the kernel trusts modules signed by it. This is the path for a
#     self-built or DKMS module, and the one documented below.
#   * A vendor key already in the kernel's builtin or platform keyring. That is
#     for a distribution shipping the module, not for a local build.
#
# Usage:
#   KEY=ufw_signing.priv CERT=ufw_signing.der \
#       build/linux/sign-module.sh path/to/ufw.ko
#
# With no KEY/CERT set, the script generates a fresh MOK pair beside the module
# and tells you how to enrol it — so a first-time signer has a working key
# without hunting for the incantation.

set -eu

MODULE="${1:-}"
HASH="${HASH:-sha256}"
KDIR="${KDIR:-/lib/modules/$(uname -r)/build}"
KEY="${KEY:-}"
CERT="${CERT:-}"

usage() {
    cat >&2 <<'USAGE'
usage: KEY=<priv.pem> CERT=<cert.der> build/linux/sign-module.sh <module.ko>

  KEY    PEM private key. If unset, a MOK keypair is generated next to the
         module and enrolment instructions are printed.
  CERT   DER certificate matching KEY.
  HASH   Digest for the signature (default: sha256).
  KDIR   Kernel build tree holding scripts/sign-file
         (default: /lib/modules/$(uname -r)/build).
USAGE
    exit 2
}

[ -n "$MODULE" ] || usage
[ -f "$MODULE" ] || { echo "sign-module: $MODULE does not exist" >&2; exit 1; }

SIGN_FILE="$KDIR/scripts/sign-file"
if [ ! -x "$SIGN_FILE" ]; then
    echo "sign-module: $SIGN_FILE not found or not executable." >&2
    echo "             It ships with the kernel headers/build package" >&2
    echo "             (linux-headers-\$(uname -r) on Debian, kernel-devel on Fedora)." >&2
    exit 1
fi

# Generate a MOK pair if the caller did not supply one. The certificate carries
# a long validity because a firewall signing key that silently expires would
# take the module offline at the next reboot after expiry, which is exactly the
# unreachable-host failure this whole effort exists to avoid.
GENERATED=0
if [ -z "$KEY" ] || [ -z "$CERT" ]; then
    KEY="${MODULE%.ko}_mok.priv"
    CERT="${MODULE%.ko}_mok.der"
    if [ ! -f "$KEY" ]; then
        echo "sign-module: generating a MOK keypair at $KEY / $CERT"
        openssl req -new -x509 -newkey rsa:2048 -nodes -days 36500 \
            -subj "/CN=Unified Firewall module signing/" \
            -keyout "$KEY" -outform DER -out "$CERT" >/dev/null 2>&1
        GENERATED=1
    fi
fi

"$SIGN_FILE" "$HASH" "$KEY" "$CERT" "$MODULE"
echo "sign-module: signed $MODULE with $HASH"

# Confirm the signature is actually attached: `modinfo` shows the signer on a
# signed module and nothing on an unsigned one, so this catches a sign-file that
# succeeded silently against the wrong module format.
if command -v modinfo >/dev/null 2>&1; then
    if modinfo "$MODULE" 2>/dev/null | grep -q '^signer:'; then
        echo "sign-module: signature verified present:"
        modinfo "$MODULE" 2>/dev/null | grep -E '^(signer|sig_hash):' | sed 's/^/  /'
    else
        echo "sign-module: WARNING — no signature is attached after signing." >&2
        exit 1
    fi
fi

if [ "$GENERATED" -eq 1 ]; then
    cat <<EOF

The module is signed, but the kernel does not yet trust the key. Enrol it once:

    sudo mokutil --import $CERT
    # choose a one-time password, then reboot; at the blue MOK Manager screen
    # choose "Enrol MOK", enter that password, and confirm.

After the reboot, this key is trusted for every module you sign with it —
including DKMS rebuilds — until you remove it with 'mokutil --delete'.
EOF
fi
