#!/usr/bin/env bash
# Fetch OpenSSL source trees consumed by the dev stack
# (docker-compose.yml mounts ./openssl/{3.4.0,3.6.0,4.0.0} into the
# dev-3.4 / dev-3.6 / dev-4.0 services as /workspace/openssl-src).
#
# Usage:
#   docker/dev_pkcs12/scripts/fetch-openssl.sh                # all three
#   docker/dev_pkcs12/scripts/fetch-openssl.sh 3.4.0 4.0.0    # subset
#
# Run from the repo root or anywhere — the script anchors paths to
# its own location. Re-run is idempotent: existing trees are left
# alone unless --force is passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # docker/dev_pkcs12/
OPENSSL_DIR="$DEV_DIR/openssl"

DEFAULT_VERSIONS=(3.4.0 3.6.0 4.0.0)
FORCE=0
VERSIONS=()

for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) VERSIONS+=("$arg") ;;
    esac
done

[ "${#VERSIONS[@]}" -eq 0 ] && VERSIONS=("${DEFAULT_VERSIONS[@]}")

mkdir -p "$OPENSSL_DIR"

fetch_one() {
    local ver="$1"
    local dest="$OPENSSL_DIR/$ver"
    local tarball="openssl-$ver.tar.gz"
    local url="https://github.com/openssl/openssl/releases/download/openssl-$ver/$tarball"

    if [ -d "$dest" ] && [ "$FORCE" -eq 0 ]; then
        echo "[fetch-openssl] $ver: $dest already exists — skipping (pass --force to overwrite)"
        return 0
    fi

    if [ -d "$dest" ] && [ "$FORCE" -eq 1 ]; then
        echo "[fetch-openssl] $ver: --force set, removing $dest"
        rm -rf "$dest"
    fi

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" RETURN

    echo "[fetch-openssl] $ver: downloading $url"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$tmpdir/$tarball" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$tmpdir/$tarball" "$url"
    else
        echo "[fetch-openssl] ERROR: neither curl nor wget available" >&2
        return 1
    fi

    echo "[fetch-openssl] $ver: extracting to $dest"
    tar -xzf "$tmpdir/$tarball" -C "$tmpdir"
    mv "$tmpdir/openssl-$ver" "$dest"
    echo "[fetch-openssl] $ver: ready at $dest"
}

for v in "${VERSIONS[@]}"; do
    fetch_one "$v"
done

echo "[fetch-openssl] done."
