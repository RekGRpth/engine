#!/bin/bash
set -e

SRC=/workspace/src
BUILD="$SRC/build"
OPENSSL_SRC=/workspace/openssl-src
OPENSSL_BUILD=/workspace/openssl-build
OPENSSL_PREFIX=/opt/openssl

# Resolve OpenSSL MAJOR.MINOR from the bind-mounted source. MAJOR gates
# engine-API options that 4.0 dropped; MINOR drives per-version patch
# selection in the bootstrap below.
OPENSSL_MAJOR="$(awk -F= '/^MAJOR=/ {print $2}' "$OPENSSL_SRC/VERSION.dat" 2>/dev/null || echo unknown)"
OPENSSL_MINOR="$(awk -F= '/^MINOR=/ {print $2}' "$OPENSSL_SRC/VERSION.dat" 2>/dev/null || echo unknown)"
echo "[entrypoint] OpenSSL source version: ${OPENSSL_MAJOR}.${OPENSSL_MINOR}"

# First-run bootstrap #1: out-of-tree build OpenSSL from the bind-
# mounted source into /opt/openssl. The named volume on /opt/openssl
# means subsequent starts skip this entirely. Build artefacts go in
# their own named volume so the bind-mounted source tree on the host
# stays clean.
if [ ! -x "$OPENSSL_PREFIX/bin/openssl" ]; then
    # The bind-mounted source is owned by the host UID; git refuses to
    # operate on it under root unless told it's safe. Set once per
    # bootstrap run.
    git config --global safe.directory '*'

    # Per-version pkcs12 provider PBE patch selection.
    # 3.x family → strict `git apply -p2` (CI parity rule). 4.0+ →
    # `patch --fuzz=3` to absorb upstream drift across future minors.
    # 3.6 needs `tls1.3.patch` first (mirrors CI PATCH_OPENSSL=1).
    # 3.4 stays no-tls1.3 — the current tls1.3.patch is line-numbered
    # for 3.6 and does not strict-apply on 3.4. A per-version tls1.3
    # split is out of scope here.
    PROVIDER_PBE_PATCH="$SRC/patches/pkcs12/openssl-pkcs12-provider-pbe-${OPENSSL_MAJOR}.${OPENSSL_MINOR}.patch"
    TLS13_PATCH="$SRC/patches/openssl-tls1.3.patch"

    if [ ! -f "$PROVIDER_PBE_PATCH" ]; then
        echo "[entrypoint] no per-version pkcs12 patch (${PROVIDER_PBE_PATCH##*/}) — leaving OpenSSL source unpatched."
    elif grep -q "EVP_CTRL_PBE_PRF_NID:" "$OPENSSL_SRC/crypto/evp/evp_enc.c" 2>/dev/null; then
        echo "[entrypoint] $(basename "$PROVIDER_PBE_PATCH") already applied — skipping patch step."
    else
        if [ "$OPENSSL_MAJOR" = "3" ] && [ "$OPENSSL_MINOR" = "6" ] && \
           ! grep -q "EVP_CTRL_TLSTREE" "$OPENSSL_SRC/crypto/evp/evp_enc.c" 2>/dev/null; then
            echo "[entrypoint] Applying $(basename "$TLS13_PATCH") (tls1.3 prerequisite for 3.6) ..."
            (cd "$OPENSSL_SRC" && git apply -p2 "$TLS13_PATCH")
        fi

        echo "[entrypoint] Applying $(basename "$PROVIDER_PBE_PATCH") ..."
        # 3.4 has no prereq → strict git apply succeeds. 3.6's diff was
        # captured post-tls1.3 against raw HEAD, so applying to a tree
        # with tls1.3 already in place shifts evp_enc.c hunks by ~8
        # lines — needs --fuzz=3 like 4.0.
        if [ "$OPENSSL_MAJOR" = "3" ] && [ "$OPENSSL_MINOR" = "4" ]; then
            (cd "$OPENSSL_SRC" && git apply -p2 "$PROVIDER_PBE_PATCH")
        else
            (cd "$OPENSSL_SRC" && patch -p2 --fuzz=3 --no-backup-if-mismatch < "$PROVIDER_PBE_PATCH")
        fi
    fi

    echo "[entrypoint] Building OpenSSL from $OPENSSL_SRC ..."
    mkdir -p "$OPENSSL_BUILD"
    cd "$OPENSSL_BUILD"

    # `enable-engine` is a 3.x-only Configure flag — 4.0 demoted the
    # engine API and rejects the option. Provider mode is the
    # supported extension surface on 4.0.
    EXTRA_CONFIG_OPTS=()
    if [ "$OPENSSL_MAJOR" = "3" ]; then
        EXTRA_CONFIG_OPTS+=(enable-engine)
    fi

    "$OPENSSL_SRC/Configure" \
        --prefix="$OPENSSL_PREFIX" \
        --openssldir="$OPENSSL_PREFIX" \
        shared \
        "${EXTRA_CONFIG_OPTS[@]}" \
        -g -O0 -fno-omit-frame-pointer

    make -j"$(nproc)"
    make install_sw install_ssldirs

    # The stock /opt/openssl/openssl.cnf ends inside a named section
    # so an `openssl_conf = ...` line at the end would be parsed as
    # part of that section and silently ignored. A fresh file at a
    # known path (pinned via OPENSSL_CONF in the image ENV) sidesteps
    # this and keeps the upstream openssl.cnf untouched.
    if [ "$OPENSSL_MAJOR" = "4" ]; then
        cat > "$OPENSSL_PREFIX/gost-engine.cnf" <<'GOSTCONF'
HOME = .
openssl_conf = openssl_def

[openssl_def]
providers = providers

[providers]
gostprov = gostprov_section
default = default_section

[gostprov_section]
activate = 1

[default_section]
activate = 1
GOSTCONF
    else
        cat > "$OPENSSL_PREFIX/gost-engine.cnf" <<'GOSTCONF'
HOME = .
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
default_algorithms = ALL
GOSTCONF
    fi
fi

# Provider-mode config — written on every stack (3.4 / 3.6 / 4.0).
# Provider-only loading is opt-in via
# `OPENSSL_CONF=/opt/openssl/gost-provider.cnf` at call sites; on 3.x
# the default `OPENSSL_CONF` still points at the engine config above
# to keep engine-mode CI / tests green. On 4.0 the default
# `OPENSSL_CONF` is gost-engine.cnf but its contents are already the
# provider-mode shape — gost-provider.cnf is then a same-content alias
# kept for naming uniformity across stacks.
# Written outside the bootstrap-once gate so existing named volumes
# (already past the first-run install) pick this up on next restart
# without needing a volume wipe.
mkdir -p "$OPENSSL_PREFIX"
cat > "$OPENSSL_PREFIX/gost-provider.cnf" <<'GOSTCONF'
HOME = .
openssl_conf = openssl_def

[openssl_def]
providers = providers

[providers]
gostprov = gostprov_section
default = default_section

[gostprov_section]
activate = 1

[default_section]
activate = 1
GOSTCONF

# First-run bootstrap #2: configure, build, install gost engine /
# provider so the engine_section in /opt/openssl/gost-engine.cnf can
# resolve `gost` immediately. The 4.0 path skips engine and only
# builds provider — engine library is not buildable against 4.0.
if [ ! -f "$BUILD/CMakeCache.txt" ]; then
    echo "[entrypoint] Initial cmake configure for gost-engine ..."
    mkdir -p "$BUILD"
    cd "$BUILD"

    CMAKE_OPTS=(
        -G Ninja
        -DCMAKE_BUILD_TYPE=Debug
        -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX"
        -DOPENSSL_ENGINES_DIR="$OPENSSL_PREFIX/lib64/engines-3"
        # Redirect install layout into OpenSSL's prefix so
        # `gostprov.so` lands at $OPENSSL_PREFIX/lib64/ossl-modules/ —
        # the path `openssl version -m` reports as MODULESDIR. Without
        # this, CMake defaults to /usr/local/lib/ossl-modules and
        # `openssl list -providers` cannot resolve gostprov.
        # OPENSSL_MODULES_DIR itself (CMakeLists.txt:25) is a
        # non-cache `set()` so `-DOPENSSL_MODULES_DIR=...` is clobbered
        # at configure time; setting CMAKE_INSTALL_PREFIX +
        # CMAKE_INSTALL_LIBDIR steers the relative path it resolves to.
        -DCMAKE_INSTALL_PREFIX="$OPENSSL_PREFIX"
        -DCMAKE_INSTALL_LIBDIR=lib64
    )
    if [ "$OPENSSL_MAJOR" = "4" ]; then
        CMAKE_OPTS+=(-DGOST_BUILD_ENGINE=OFF -DGOST_BUILD_PROVIDER=ON)
    fi

    cmake "$SRC" "${CMAKE_OPTS[@]}"
    ninja -j"$(nproc)"
    ninja install
fi

exec "$@"
