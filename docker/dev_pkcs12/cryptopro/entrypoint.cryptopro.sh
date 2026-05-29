#!/bin/bash
# Entrypoint for the cryptopro service. Idempotent on restart; same
# shape as docker/dev_pkcs12/scripts/entrypoint.sh for consistency.
#
# Responsibilities:
#   1. Seed CPSD software RNG with the baked test gamma so
#      `csptest -keyset -newkeyset` works headless. A fresh install
#      leaves /var/opt/cprocsp/dsrf/db{1,2}/ empty → CPSD returns
#      NTE_FAIL and the only fallback (BIO_TUI) is an interactive
#      TUI capture.
#   2. Drop BIO_TUI from the registered RNGs so CPSD (level 3) doesn't
#      get preempted by BIO_TUI (level 5) under -silent invocations.
#      Idempotent — once removed, subsequent restarts no-op.
#   3. Log CryptoPro CSP license state on first start (trial mode is
#      expected — no serial wired in; the line is for
#      `docker compose logs cryptopro` visibility).
#   4. Ensure /workspace/data exists. Docker creates the bind-mount
#      target automatically, but mkdir -p makes the script
#      self-contained when the volume mapping is absent (e.g. raw
#      `docker run` smoke tests).
#   5. exec "$@" so CMD (sleep infinity) wins after init.
#
# Failures from cpconfig must NOT block container start — CSP licence
# server is a no-op for trial mode and rndm reconfigure may already
# have run on a previous boot. Wrap each in `|| true`.
#
# **Anti-rule:** never run `/etc/init.d/cprocsp start`. cpinstance's
# integrity check false-positives on libcapi20.so.4.0.5 under docker
# overlay-fs and renames it to corrupted.libcapi20.so.4.0.5, breaking
# csptest. CSP libraries work fine without the init.d service.
set -e

# Step 1 — seed CPSD gamma if /var/opt/cprocsp/dsrf is empty. The
# image ships /opt/cprocsp/share/test_gamma/db1/kis_1 (864-byte gamma
# baked at Dockerfile build time). Both db1 and db2 get the same
# gamma — CPSD config maps both, and either suffices in practice.
GAMMA_SRC=/opt/cprocsp/share/test_gamma/db1/kis_1
if [ -f "$GAMMA_SRC" ]; then
    for db in db1 db2; do
        target=/var/opt/cprocsp/dsrf/$db/kis_1
        if [ ! -f "$target" ]; then
            cp "$GAMMA_SRC" "$target"
            echo "[entrypoint.cryptopro] seeded CPSD gamma at $target"
        fi
    done
else
    echo "[entrypoint.cryptopro] WARN: $GAMMA_SRC absent — keygen will fail until /var/opt/cprocsp/dsrf/db{1,2}/kis_1 is populated"
fi

# Step 2 — remove BIO_TUI so CPSD wins. Idempotent: cpconfig returns
# non-zero if BIO_TUI is already gone, hence `|| true`.
cpconfig -hardware rndm -del BIO_TUI 2>/dev/null \
    && echo "[entrypoint.cryptopro] removed BIO_TUI (interactive TUI RNG) from rndm registry" \
    || true

# Step 3 — log license state. Trial/Demo (no serial wired in).
echo "[entrypoint.cryptopro] CryptoPro CSP license state:"
cpconfig -license -view 2>&1 || true

# Step 4 — bind-mount safety net.
mkdir -p /workspace/data

# Step 5 — hand off to CMD.
exec "$@"
