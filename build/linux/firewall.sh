#!/bin/sh
# `firewall` — the short way into ufw-nft, the project's real nftables
# enforcement CLI. Installed by install.sh (or `make install`) as
# /usr/local/bin/firewall.
#
#   firewall                        open the live dashboard (rules, denials,
#                                   attack analysis) at http://127.0.0.1:8787
#   firewall apply default_allow    enforce a policy (bare names resolve
#                                   under /etc/unified-firewall/policies)
#   firewall trial default_deny 60  try a policy with a 60s auto-revert
#   firewall status                 the loaded ruleset with live counters
#   firewall revert                 remove everything this tool loaded
#   firewall check <policy>         validate without loading anything
#
# Every subcommand talks to nftables or reads the kernel log, both of which
# need root, so this wrapper re-execs itself under sudo — you get one
# password prompt instead of one confusing "Operation not permitted".

set -eu

UFW_NFT="${UFW_NFT:-/usr/local/bin/ufw-nft}"

case "${1:-}" in
    -h|--help|-V|--version)
        exec "$UFW_NFT" "$@"
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "firewall: this needs root, and sudo is not available — run it as root" >&2
        exit 1
    fi
    if [ $# -eq 0 ]; then
        exec sudo -- "$UFW_NFT" dashboard
    fi
    exec sudo -- "$UFW_NFT" "$@"
fi

if [ $# -eq 0 ]; then
    exec "$UFW_NFT" dashboard
fi
exec "$UFW_NFT" "$@"
