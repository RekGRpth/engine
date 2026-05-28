#!/bin/sh
# Provider-mode three-stack matrix end-to-end for the CryptoPro
# proprietary keybag PBE OID 1.2.840.113549.1.12.1.80.
#
# Mints a fresh exportable GOST 2012-256 keyset in the `cryptopro`
# service, exports it to .pfx via `certmgr -export -pfx`, then for
# each provider service (`dev-3.4`, `dev-3.6`, `dev-4.0`) runs
# `openssl pkcs12 -in <pfx> -password pass:123456 -nodes` and
# asserts:
#   1. The PEM stream contains both BEGIN PRIVATE KEY and
#      BEGIN CERTIFICATE.
#   2. The recovered key DER round-trips `openssl pkey -in ... -outform
#      DER` (proves the unwrapped PKCS#8 is structurally valid).
#   3. The recovered cert SHA-1 matches the CSP-side thumbprint
#      captured before export (proves the wrong cert was not pulled
#      from a stale store).
#
# Hard-fails on any of three provider services. PFX is kept at
# `docker/dev_pkcs12/cryptopro/data/<seed>.pfx` (host-mounted) for post-mortem
# even on failure; key container + uMy entry are removed via trap.
#
# Run from the repo root: `docker/dev_pkcs12/scripts/cryptopro_keybag_decode.sh`.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
COMPOSE="docker compose -f $REPO_ROOT/docker/dev_pkcs12/docker-compose.yml"
DEV_SERVICES="dev-3.4 dev-3.6 dev-4.0"
CRYPTOPRO=cryptopro
CSP_PIN=123456
PFX_PASSWORD=123456

SEED="cryptopro-keybag-$(date +%s)"
CONTAINER_PATH='\\.\HDIMAGE\'"${SEED}"
PFX_HOST_REL="docker/dev_pkcs12/cryptopro/data/${SEED}.pfx"
PFX_HOST_ABS="${REPO_ROOT}/${PFX_HOST_REL}"
PFX_IN_CRYPTOPRO="/workspace/data/${SEED}.pfx"
# /workspace/data is bind-mounted into every dev service in compose,
# but live dev containers may pre-date that mount. To keep this driver
# runnable without forcing a `compose up --force-recreate` (which
# would nuke gost-engine-build-* volumes), copy the PFX into each dev
# container's /tmp via `docker cp` instead of relying on the shared
# mount.
PFX_IN_DEV="/tmp/${SEED}.pfx"

# Provider-mode test config used by every `openssl pkcs12` invocation
# below. Seeded idempotently from the script so a cold dev container
# (or one whose /tmp got wiped) still has it. CRYPT_PARAMS deliberately
# omitted — the keybag pipeline pins its S-boxes internally
# (`gost_md.c::gost_digest_init` for md_gost94,
# `cryptopro_cfb_decrypt`/`_ecb_decrypt` for gost89).
TEST_CNF=/tmp/gostfull.cnf
read_test_cnf() {
    cat <<'EOF'
HOME = .
openssl_conf = openssl_def

[openssl_def]
providers = provider_section

[provider_section]
default = default_sect
legacy = legacy_sect
gostprov = gostprov_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[gostprov_sect]
module = /workspace/src/build/bin/gostprov.so
activate = 1
EOF
}

# ---------- preflight ----------
ensure_container_up() {
    name=$1
    state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
    if [ "$state" != "running" ]; then
        echo "FAIL: container '$name' not running (state=$state)" >&2
        echo "  hint: $COMPOSE up -d $name" >&2
        exit 1
    fi
}
ensure_container_up gost-engine-cryptopro
for svc in $DEV_SERVICES; do
    case $svc in
        dev-3.4) ensure_container_up gost-engine-dev-3.4 ;;
        dev-3.6) ensure_container_up gost-engine-dev-3.6 ;;
        dev-4.0) ensure_container_up gost-engine-dev-4.0 ;;
    esac
done

# ---------- seed test cnf in each dev container ----------
for svc in $DEV_SERVICES; do
    read_test_cnf | $COMPOSE exec -T "$svc" tee "$TEST_CNF" >/dev/null
done

# ---------- cleanup trap ----------
cleanup() {
    rc=$?
    set +e
    echo
    echo "[cleanup] removing CSP cert + container for ${SEED}"
    $COMPOSE exec -T "$CRYPTOPRO" \
        certmgr -delete -dn "CN=${SEED}" -silent >/dev/null 2>&1 || true
    $COMPOSE exec -T "$CRYPTOPRO" \
        csptest -keyset -deletekeyset -container "$CONTAINER_PATH" \
            >/dev/null 2>&1 || true
    if [ $rc -ne 0 ]; then
        echo "[cleanup] PFX retained for post-mortem: ${PFX_HOST_REL}"
    fi
    return $rc
}
trap cleanup EXIT

# ---------- step 1: mint exportable container ----------
echo "[csp] minting exportable GOST 2012-256 keyset: ${SEED}"
$COMPOSE exec -T "$CRYPTOPRO" \
    csptest -keyset -newkeyset \
        -container "$CONTAINER_PATH" \
        -provtype 80 \
        -keytype exchange \
        -exportable \
        -password "$CSP_PIN" >/dev/null

# ---------- step 2: self-signed cert into the container ----------
echo "[csp] minting self-signed cert"
$COMPOSE exec -T "$CRYPTOPRO" \
    csptest -keyset \
        -container "$CONTAINER_PATH" \
        -provtype 80 \
        -password "$CSP_PIN" \
        -makecert >/dev/null

# ---------- step 3: install into uMy ----------
echo "[csp] installing cert into uMy store"
$COMPOSE exec -T "$CRYPTOPRO" \
    certmgr -install -container "$CONTAINER_PATH" >/dev/null

# ---------- step 4: capture SHA-1 thumbprint ----------
CSP_THUMBPRINT=$($COMPOSE exec -T "$CRYPTOPRO" \
    certmgr -list -dn "CN=${SEED}" \
    | awk '/SHA1 Thumbprint/ {print $NF}')
if [ -z "$CSP_THUMBPRINT" ]; then
    echo "FAIL: certmgr did not report SHA1 thumbprint for CN=${SEED}" >&2
    exit 1
fi
# Normalise: lowercase, no separators.
CSP_THUMB_NORM=$(echo "$CSP_THUMBPRINT" | tr 'A-F' 'a-f' | tr -d ': ')
echo "[csp] thumbprint = ${CSP_THUMB_NORM}"

# ---------- step 5: export PFX ----------
echo "[csp] exporting PFX to ${PFX_IN_CRYPTOPRO}"
$COMPOSE exec -T "$CRYPTOPRO" sh -c \
    "echo '${CSP_PIN}' | certmgr -export -pfx \
        -container '${CONTAINER_PATH}' \
        -dest '${PFX_IN_CRYPTOPRO}' \
        -pin '${PFX_PASSWORD}'" >/dev/null

if [ ! -s "$PFX_HOST_ABS" ]; then
    echo "FAIL: PFX not created on host at ${PFX_HOST_REL}" >&2
    exit 1
fi
PFX_BYTES=$(wc -c <"$PFX_HOST_ABS" | tr -d ' ')
echo "[csp] PFX = ${PFX_BYTES} bytes"

# ---------- step 5b: stage PFX into each dev container ----------
for svc in $DEV_SERVICES; do
    case $svc in
        dev-3.4) cname=gost-engine-dev-3.4 ;;
        dev-3.6) cname=gost-engine-dev-3.6 ;;
        dev-4.0) cname=gost-engine-dev-4.0 ;;
    esac
    docker cp "$PFX_HOST_ABS" "${cname}:${PFX_IN_DEV}" >/dev/null
done

# ---------- step 6: decode in each provider stack ----------
PASS=0
FAIL=0
for svc in $DEV_SERVICES; do
    echo
    echo "[$svc] decoding ${SEED}.pfx via openssl pkcs12"
    PEM_PATH="/tmp/${SEED}-${svc}.pem"
    DER_PATH="/tmp/${SEED}-${svc}.key.der"

    if ! $COMPOSE exec -T "$svc" sh -c \
        "OPENSSL_CONF=${TEST_CNF} /opt/openssl/bin/openssl pkcs12 \
            -in '${PFX_IN_DEV}' \
            -password 'pass:${PFX_PASSWORD}' \
            -nodes -out '${PEM_PATH}'"; then
        echo "[$svc] FAIL: openssl pkcs12 returned non-zero"
        FAIL=$((FAIL+1))
        continue
    fi

    # Assertion 1: both BEGIN markers present
    KEY_HITS=$($COMPOSE exec -T "$svc" \
        grep -c '^-----BEGIN PRIVATE KEY-----$' "$PEM_PATH" || echo 0)
    CERT_HITS=$($COMPOSE exec -T "$svc" \
        grep -c '^-----BEGIN CERTIFICATE-----$' "$PEM_PATH" || echo 0)
    if [ "$KEY_HITS" -lt 1 ] || [ "$CERT_HITS" -lt 1 ]; then
        echo "[$svc] FAIL: missing markers (key=$KEY_HITS cert=$CERT_HITS)"
        FAIL=$((FAIL+1))
        continue
    fi
    echo "[$svc]   markers ok (key=$KEY_HITS cert=$CERT_HITS)"

    # Assertion 2: openssl pkey accepts the recovered private key
    if ! $COMPOSE exec -T "$svc" sh -c \
        "OPENSSL_CONF=${TEST_CNF} /opt/openssl/bin/openssl pkey \
            -in '${PEM_PATH}' -outform DER -out '${DER_PATH}'" \
        2>/dev/null; then
        echo "[$svc] FAIL: openssl pkey rejected the recovered key"
        FAIL=$((FAIL+1))
        continue
    fi
    KEY_DER_BYTES=$($COMPOSE exec -T "$svc" \
        sh -c "wc -c <'${DER_PATH}'" | tr -d ' \r')
    if [ "${KEY_DER_BYTES:-0}" -lt 16 ]; then
        echo "[$svc] FAIL: pkey DER too small ($KEY_DER_BYTES B)"
        FAIL=$((FAIL+1))
        continue
    fi
    echo "[$svc]   pkey round-trip ok (${KEY_DER_BYTES} B DER)"

    # Assertion 3: cert SHA-1 fingerprint matches CSP-side thumbprint
    # `openssl x509 -fingerprint -sha1` prints either
    # `SHA1 Fingerprint=...` (older builds) or `sha1 Fingerprint=...`
    # (newer 3.x/4.x); strip whichever prefix appears.
    FP_RAW=$($COMPOSE exec -T "$svc" sh -c \
        "OPENSSL_CONF=${TEST_CNF} /opt/openssl/bin/openssl x509 \
            -in '${PEM_PATH}' -fingerprint -sha1 -noout" 2>/dev/null \
        | sed -n 's/^[Ss][Hh][Aa]1 Fingerprint=//p')
    FP_NORM=$(echo "$FP_RAW" | tr 'A-F' 'a-f' | tr -d ': \r')
    if [ "$FP_NORM" != "$CSP_THUMB_NORM" ]; then
        echo "[$svc] FAIL: cert SHA-1 mismatch"
        echo "[$svc]   csp:      ${CSP_THUMB_NORM}"
        echo "[$svc]   recovered: ${FP_NORM}"
        FAIL=$((FAIL+1))
        continue
    fi
    echo "[$svc]   cert SHA-1 matches CSP (${FP_NORM})"

    PASS=$((PASS+1))
    echo "[$svc] PASS"
done

echo
echo "==============================================="
echo "  cryptopro keybag decode: ${PASS}/3 pass, ${FAIL}/3 fail"
echo "  PFX: ${PFX_HOST_REL} (${PFX_BYTES} B)"
echo "  CSP thumbprint: ${CSP_THUMB_NORM}"
echo "==============================================="
[ "$FAIL" -eq 0 ]
