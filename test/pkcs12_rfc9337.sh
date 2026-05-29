#!/bin/sh
# RFC 9337 / 9548 CLI-level smoke test for `openssl pkcs12 -export`.
# Complements test_pkcs12_rfc9337.c: that one exercises the libcrypto
# API (PKCS12_create + PKCS12_parse), this one exercises the CLI binary
# the user actually invokes.
#
# For each (cipher, macalg) ∈ {kuznyechik-ctr-acpkm, magma-ctr-acpkm}
# × {md_gost12_256, md_gost12_512}: encode, decode, assert key+cert
# come back and that the on-the-wire OIDs are GOST.
#
# Env (set by ctest from tests.cmake):
#   OPENSSL_PROGRAM   path to openssl binary
#   OPENSSL_CONF      points at engine.cnf so gost loads on every call
#   OPENSSL_ENGINES   path to gost.so

set -eu

: "${OPENSSL_PROGRAM:?OPENSSL_PROGRAM not set}"
OS="$OPENSSL_PROGRAM"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

PASS=secret
"$OS" req -x509 -newkey gost2012_512 -pkeyopt paramset:A \
    -keyout key.pem -out cert.pem -nodes -days 1 \
    -subj "/CN=pkcs12-cli-test" >/dev/null 2>&1

CIPHERS="kuznyechik-ctr-acpkm magma-ctr-acpkm"
MACALGS="md_gost12_256 md_gost12_512"

assert_roundtrip() {
    pfx=$1; pass=$2; label=$3
    out=$("$OS" pkcs12 -in "$pfx" -passin "pass:$pass" -nodes 2>&1)
    case "$out" in
        *"BEGIN CERTIFICATE"*"BEGIN PRIVATE KEY"*) ;;
        *) printf 'FAIL [%s]: round-trip missing key or cert:\n%s\n' \
              "$label" "$out" >&2; return 1;;
    esac
    case "$out" in *"CN=pkcs12-cli-test"*) ;;
        *) printf 'FAIL [%s]: subject mismatch\n' "$label" >&2; return 1;;
    esac
}

assert_oids() {
    pfx=$1; want_cipher=$2; want_prf=$3; label=$4
    a=$("$OS" asn1parse -inform DER -in "$pfx" -strparse 26 2>&1)
    case "$a" in *"$want_cipher"*) ;;
        *) printf 'FAIL [%s]: cipher OID/name %s not in PFX\n' \
              "$label" "$want_cipher" >&2; return 1;;
    esac
    case "$a" in *"$want_prf"*) ;;
        *) printf 'FAIL [%s]: PRF %s not in PFX\n' "$label" "$want_prf" >&2;
           return 1;;
    esac
}

run_case() {
    cipher=$1; macalg=$2
    label="$cipher / $macalg"
    out=p12_$$_$cipher-$macalg.p12

    "$OS" pkcs12 -export -inkey key.pem -in cert.pem \
        -keypbe "$cipher" -certpbe "$cipher" \
        -macalg "$macalg" -passout "pass:$PASS" -out "$out" >/dev/null 2>&1

    assert_oids "$out" "$cipher" "HMAC GOST 34.11-2012" "$label"
    assert_roundtrip "$out" "$PASS" "$label"
    printf 'ok  [%s]\n' "$label"
}

fail=0
for cipher in $CIPHERS; do
    for macalg in $MACALGS; do
        run_case "$cipher" "$macalg" || fail=$((fail+1))
    done
done

if [ "$fail" -gt 0 ]; then
    printf '%d case(s) failed\n' "$fail" >&2
    exit 1
fi
echo "all CLI cases passed"
