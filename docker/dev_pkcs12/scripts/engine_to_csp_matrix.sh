#!/bin/sh
# Tier-1 engine → CSP matrix for RFC 9337/9548 GOST-native PFX in
# provider mode. OMAC ciphers are out of scope on this matrix —
# end-to-end support under provider-only loading needs the
# `gost2015_acpkm_omac_init` → `EVP_MAC_fetch` refactor that ships
# separately.
#
# Matrix: 3 stacks (`dev-3.4`, `dev-3.6`, `dev-4.0`) × 2 ciphers
# {kuznyechik-ctr-acpkm, magma-ctr-acpkm} × 2 macalgs {md_gost12_256,
# md_gost12_512} = **12 cells**, all expected PASS.
#
# Provider-only loading is forced via `OPENSSL_CONF=/opt/openssl/
# gost-provider.cnf` injected into the dev `docker compose exec`.
# For each cell:
#
#   1. genkey gost2012_256 paramset:A in the dev container.
#   2. self-signed cert with subject `CN=<seed>`.
#   3. `openssl pkcs12 -export -keypbe <cipher> -certpbe <cipher>
#       -macalg <macalg> -password pass:123456`.
#   4. capture engine-side cert SHA-1 fingerprint.
#   5. stage PFX into the host's `docker/dev_pkcs12/cryptopro/data/`
#      (bind-mounted into the cryptopro container at /workspace/data).
#   6. cryptopro: `certmgr -install -pfx -file ... -pin ${PIN} -newpin
#      ${PIN} -carrier "\\.\HDIMAGE\<seed>" -silent`.
#   7. `certmgr -list -dn CN=<seed>` → assert:
#      a. SHA1 thumbprint matches engine-side cert,
#      b. `PrivateKey Link: Yes`.
#   8. cleanup: `certmgr -delete -dn CN=<seed>` +
#      `csptest -keyset -deletekeyset -container "\\.\HDIMAGE\<seed>"`.
#
# Any FAIL is a hard fail (no XFAIL axis remains).
#
# PFX kept under `docker/dev_pkcs12/cryptopro/data/<seed>.pfx` for post-mortem on
# failure (cleanup trap removes only success-cell PFXes); CSP carrier +
# uMy entry are removed on every cell exit.
#
# Run from the repo root: `docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh`.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
COMPOSE="docker compose -f $REPO_ROOT/docker/dev_pkcs12/docker-compose.yml"
CRYPTOPRO=cryptopro
DEV_SERVICES="dev-3.4 dev-3.6 dev-4.0"
CIPHERS="kuznyechik-ctr-acpkm magma-ctr-acpkm"
MACALGS="md_gost12_256 md_gost12_512"
PIN=123456
TS=$(date +%s)
DATA_HOST="$REPO_ROOT/docker/dev_pkcs12/cryptopro/data"
DATA_CSP=/workspace/data

# Force provider-only loading on every dev stack. Default OPENSSL_CONF
# on 3.x points at gost-engine.cnf (engine API); this override switches
# it to the parallel gost-provider.cnf written by entrypoint.sh on
# every stack. On 4.0 the default is already provider-shaped, so the
# override is a no-op there but keeps the call site uniform across
# stacks.
DEV_PROV_CONF=/opt/openssl/gost-provider.cnf
DEV_EXEC_ENV="-e OPENSSL_CONF=${DEV_PROV_CONF}"

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

# ---------- short-name maps ----------
svc_short() {
    case $1 in
        dev-3.4) echo 34 ;;
        dev-3.6) echo 36 ;;
        dev-4.0) echo 40 ;;
    esac
}
cipher_short() {
    case $1 in
        kuznyechik-ctr-acpkm) echo kz ;;
        magma-ctr-acpkm) echo mg ;;
    esac
}
macalg_short() {
    case $1 in
        md_gost12_256) echo s256 ;;
        md_gost12_512) echo s512 ;;
    esac
}

# ---------- per-cell driver ----------
PASS=0
FAIL=0
RESULTS=""

run_cell() {
    svc=$1
    cipher=$2
    macalg=$3

    seed="engcsp-${TS}-$(svc_short "$svc")-$(cipher_short "$cipher")-$(macalg_short "$macalg")"
    cn="$seed"
    dev_work="/tmp/${seed}"
    csp_carrier='\\.\HDIMAGE\'"${seed}"
    pfx_host="${DATA_HOST}/${seed}.pfx"
    pfx_csp="${DATA_CSP}/${seed}.pfx"

    case $svc in
        dev-3.4) cname=gost-engine-dev-3.4 ;;
        dev-3.6) cname=gost-engine-dev-3.6 ;;
        dev-4.0) cname=gost-engine-dev-4.0 ;;
    esac

    label="[${svc}/${cipher}/${macalg}]"
    echo
    echo "$label seed=${seed}"

    # ---------- step 0: provider sanity ----------
    # Assert gostprov is active under OPENSSL_CONF=$DEV_PROV_CONF before
    # any genkey/export. If the provider didn't load (wrong MODULESDIR,
    # missing config, etc.) every downstream step fails opaquely; catch
    # that here with a single grep so the failure label is unambiguous.
    prov_out=$($COMPOSE exec -T $DEV_EXEC_ENV "$svc" \
        /opt/openssl/bin/openssl list -providers 2>&1)
    if ! echo "$prov_out" | grep -qE '^[[:space:]]*gostprov$'; then
        echo "$label  PROVIDER SANITY FAIL — gostprov not active under $DEV_PROV_CONF"
        echo "$prov_out" | sed "s|^|$label    |"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (gostprov not active)"
        return 0
    fi

    cell_cleanup() {
        $COMPOSE exec -T "$CRYPTOPRO" \
            /opt/cprocsp/bin/amd64/certmgr -delete -dn "CN=${cn}" -silent \
            >/dev/null 2>&1 || true
        $COMPOSE exec -T "$CRYPTOPRO" sh -lc "
            for c in \$(/opt/cprocsp/bin/amd64/csptest -keyset -enum_cont -fqcn -verifyc 2>/dev/null | grep -F '${seed}'); do
                /opt/cprocsp/bin/amd64/csptest -keyset -deletekeyset -container \"\$c\" >/dev/null 2>&1 || true
            done
        " >/dev/null 2>&1 || true
        $COMPOSE exec -T "$svc" rm -rf "$dev_work" >/dev/null 2>&1 || true
    }

    # ---------- step 1-3: gen + export ----------
    # Provider-only loading is enforced via $DEV_EXEC_ENV:
    # OPENSSL_CONF=$DEV_PROV_CONF makes openssl pick gostprov from
    # OpenSSL's MODULESDIR (gostprov.so is installed there by the
    # CMAKE_INSTALL_PREFIX/LIBDIR override in entrypoint.sh). No
    # OPENSSL_MODULES override needed.
    export_log=$(mktemp)
    export_rc=0
    $COMPOSE exec -T $DEV_EXEC_ENV "$svc" bash -lc "
        set -eu
        mkdir -p '$dev_work'
        cd '$dev_work'
        openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out key.pem
        openssl req -x509 -new -key key.pem -subj /CN=${cn} -days 365 -out cert.pem
        openssl pkcs12 -export \
            -inkey key.pem -in cert.pem \
            -keypbe '${cipher}' -certpbe '${cipher}' \
            -macalg '${macalg}' \
            -password pass:${PIN} \
            -out bundle.p12
    " >"$export_log" 2>&1 || export_rc=$?
    if [ $export_rc -ne 0 ]; then
        echo "$label  EXPORT FAIL (rc=$export_rc) — engine couldn't emit PFX"
        tail -10 "$export_log" | sed "s|^|$label    |"
        rm -f "$export_log"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (export rc=$export_rc)"
        cell_cleanup
        return 0
    fi
    rm -f "$export_log"

    # ---------- step 4: capture engine-side SHA-1 ----------
    eng_sha1=$($COMPOSE exec -T $DEV_EXEC_ENV "$svc" sh -lc "
        cd '$dev_work'
        openssl x509 -in cert.pem -fingerprint -sha1 -noout
    " 2>/dev/null | sed -n 's/^[Ss][Hh][Aa]1 Fingerprint=//p' | tr 'A-F' 'a-f' | tr -d ': \r')
    if [ -z "$eng_sha1" ]; then
        echo "$label  SHA1 capture failed"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (sha1 capture)"
        cell_cleanup
        return 0
    fi
    echo "$label  engine cert SHA-1 = ${eng_sha1}"

    # ---------- step 5: stage PFX onto host (= /workspace/data inside CSP) ----------
    docker cp "${cname}:${dev_work}/bundle.p12" "$pfx_host" >/dev/null 2>&1
    if [ ! -s "$pfx_host" ]; then
        echo "$label  PFX stage failed"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (pfx stage)"
        cell_cleanup
        return 0
    fi
    pfx_bytes=$(wc -c <"$pfx_host" | tr -d ' ')
    echo "$label  PFX = ${pfx_bytes} B → ${pfx_csp}"

    # ---------- step 6: import into CSP ----------
    import_out=$($COMPOSE exec -T "$CRYPTOPRO" \
        /opt/cprocsp/bin/amd64/certmgr -install -pfx \
            -file "$pfx_csp" \
            -pin "$PIN" -newpin "$PIN" \
            -carrier "$csp_carrier" -silent 2>&1) || import_rc=$?
    import_rc=${import_rc:-0}
    import_ec=$(echo "$import_out" | sed -n 's/^\[ErrorCode: \(0x[0-9A-Fa-f]*\)\].*$/\1/p' | tail -1)

    if [ "$import_ec" != "0x00000000" ]; then
        echo "$label  CSP IMPORT FAIL (ErrorCode=${import_ec})"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (csp ${import_ec})"
        echo "$import_out" | tail -8 | sed "s|^|$label    |"
        cell_cleanup
        return 0
    fi

    # ---------- step 7: assert PrivateKey Link + SHA-1 match ----------
    list_out=$($COMPOSE exec -T "$CRYPTOPRO" \
        /opt/cprocsp/bin/amd64/certmgr -list -dn "CN=${cn}" 2>&1)
    csp_sha1=$(echo "$list_out" \
        | awk '/SHA1 Thumbprint/ {print $NF; exit}' \
        | tr 'A-F' 'a-f' | tr -d ': \r')
    pk_link=$(echo "$list_out" | awk '/PrivateKey Link/ {print $NF; exit}')

    if [ "$csp_sha1" != "$eng_sha1" ]; then
        echo "$label  SHA1 MISMATCH (eng=${eng_sha1} csp=${csp_sha1})"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (sha1 mismatch)"
        cell_cleanup
        return 0
    fi
    if [ "$pk_link" != "Yes" ]; then
        echo "$label  PK LINK NOT YES (got '${pk_link}')"
        FAIL=$((FAIL+1))
        RESULTS="${RESULTS}\nFAIL   ${label}  (pk link='${pk_link}')"
        cell_cleanup
        return 0
    fi

    # ---------- success ----------
    echo "$label  PASS"
    PASS=$((PASS+1))
    RESULTS="${RESULTS}\nPASS   ${label}"
    rm -f "$pfx_host"
    cell_cleanup
}

# ---------- main loop ----------
total=0
for svc in $DEV_SERVICES; do
    for cipher in $CIPHERS; do
        for macalg in $MACALGS; do
            total=$((total+1))
            run_cell "$svc" "$cipher" "$macalg" || true
        done
    done
done

# ---------- summary ----------
echo
echo "==============================================="
echo "  engine → CSP matrix — ${total} cells"
echo "  PASS:  ${PASS}   (CSP accepted PFX with key link)"
echo "  FAIL:  ${FAIL}   (any failure is hard fail)"
echo "==============================================="
printf '%b\n' "${RESULTS}" | tail -n +2 | sort

[ "$FAIL" -eq 0 ]
