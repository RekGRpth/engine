# PKCS#12 RFC 9337 / RFC 9548 patches for OpenSSL libcrypto

Source-level OpenSSL patches that close the libcrypto gaps blocking
`openssl pkcs12 -export` per RFC 9337 / 9548 with GOST symmetric
ciphers in provider mode. The patches themselves are documented
below; running the verification matrices in the local dev
environment is covered in
[Verification matrices](#verification-matrices).

## Patches

### `openssl-pkcs12-provider-pbe-{3.4,3.6,4.0}.patch`

Three per-version patches that close the libcrypto gaps which block
RFC 9337 / 9548 PKCS#12 export with GOST symmetric ciphers from a
provider. Required on OpenSSL 4.0 (engine API removed from
`apps/pkcs12.c`) and on 3.x when the provider config is loaded
explicitly.

The three patches apply the same conceptual changes adjusted to per-
release line numbers; functionally they are the same set of fallback
hunks. The hunks themselves:

| File                          | Hunk                                                       | Effect                                                                                                                |
|-------------------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `crypto/evp/digest.c`         | `set_legacy_nid` `OBJ_txt2nid` fallback                    | Provider-only digests resolve a NID via OID/SN when no legacy `EVP_add_digest` ran                                    |
| `crypto/evp/evp_enc.c`        | `set_legacy_nid` `OBJ_txt2nid` fallback                    | Symmetric: provider-only ciphers resolve a NID even without legacy `EVP_add_cipher`                                   |
| `crypto/evp/evp_enc.c`        | `EVP_CTRL_PBE_PRF_NID` → `pbe-prf-nid` `OSSL_PARAM`        | `PKCS5_pbe2_set_iv_ex` can read the PRF NID from a provider ctx (else PRF fell back to `NID_hmacWithSHA256`)          |
| `crypto/evp/evp_lib.c`        | `evp_cipher_param_to_asn1_ex` / `..._asn1_to_param_ex`     | Provider with custom AlgorithmIdentifier shape (RFC 9337 §7.3 SEQUENCE { ukm }) gets a path to inject its DER         |
| `crypto/evp/evp_lib.c`        | `evp_cipher_cache_constants` `cipher-with-mac` slot        | Providers can advertise `EVP_CIPH_FLAG_CIPHER_WITH_MAC` for the trailing-tag flow in `PKCS12_pbe_crypt_ex` (INACTIVE)   |
| `crypto/pkcs12/p12_decr.c`    | `PKCS12_pbe_crypt_ex` `mac_len` fallback                   | Picks up `mac_len` from the ctrl rc when the libcrypto provider translation drops the engine's `*(int *)ptr` overload (INACTIVE) |

The two **INACTIVE** hunks (`cipher-with-mac` flag propagation in
`evp_lib.c` and the `mac_len` fallback in `p12_decr.c`) are the
architectural prerequisite for PKCS#12 OMAC export in provider mode.
Final activation hits `gost2015_acpkm_omac_init`
(`gost_gost2015.c:158`): it calls legacy `EVP_get_digestbynid` /
`EVP_PKEY_new_mac_key`, both of which return NULL under provider-
only loading because `kuznyechik-mac` and `magma-mac` are
registered as `EVP_MAC` (`gost_prov_mac.c:343`). Unblocking
requires an `EVP_MAC_fetch` refactor in the engine source; until
that lands, these hunks are inactive code. See the INACTIVE block
at the top of each patch for the exact refactor needed.

The non-INACTIVE hunks are required for non-OMAC RFC 9337 / 9548
ciphers (`kuznyechik-ctr-acpkm`, `magma-ctr-acpkm`) under
`openssl pkcs12 -export` when the symmetric crypto comes from a
provider.

## Application order

`docker/dev_pkcs12/scripts/entrypoint.sh` applies the patches
automatically on first container start, against the mounted OpenSSL
source under `docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/`:

1. **3.6 only** — `../openssl-tls1.3.patch` (`git apply -p2`) is
   applied first as a prerequisite. The 3.6 pkcs12 patch was
   captured against a tree with the upstream TLS 1.3 changes
   already in place; without those, the `evp_enc.c` hunks fail to
   apply. Not needed on 3.4 or 4.0.
2. **All stacks** — `openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch`
   (3.4 uses strict `git apply -p2`; 3.6 / 4.0 use
   `patch -p2 --fuzz=3` to absorb upstream drift).

OpenSSL is then configured + built out-of-tree into a named volume
per version (`/opt/openssl`); gost-engine + gostprov are built
against that prefix.

## Verification matrices

Two matrices are shipped:

- **Tier-1 in provider mode** — 12 cells (3 stacks × 2 ciphers ×
  2 outer-MAC digests) of `openssl pkcs12 -export` →
  `certmgr -install -pfx` round-trip into CryptoPro CSP. Validates
  that the patched libcrypto + gostprov produce a PFX shape CSP
  accepts, with key linkage intact.
- **ctest regression** — per-stack regression suite. 21/21 (3.4) /
  21/21 (3.6) / 9/9 (4.0).

### Prerequisites

1. Docker + docker compose v2.
2. Repository cloned somewhere on the host; if the path differs
   from the expected one, adjust it in
   `docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh`.
3. OpenSSL upstream sources mounted at
   `docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/`. Fresh clones
   of upstream tags `openssl-3.4.0`, `openssl-3.6.0`, and the 4.0
   development tree work; `docker/dev_pkcs12/openssl/` is
   gitignored from the engine repo. The tls1.3 patch on 3.6
   expects a 3.6 source tree; the pkcs12 patches expect their
   respective per-version sources.
4. The `cryptopro` service is built and up
   (`docker/dev_pkcs12/docker-compose.yml`; the image is built
   from a privately distributed `linux-amd64_deb.tgz` that this
   repo does not include). Without it, the ctest regression still
   runs and the Tier-1 matrix doesn't: there is nowhere to import
   the PFX.

### Cold start

```sh
cd <path-to-repo>
docker compose -f docker/dev_pkcs12/docker-compose.yml build dev-3.4 dev-3.6 dev-4.0 cryptopro
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4 dev-3.6 dev-4.0 cryptopro
```

`entrypoint.sh` on first start in each dev container:

1. Applies the per-version patches to the mounted OpenSSL source.
2. Configures + builds OpenSSL into `/opt/openssl` (named volume —
   subsequent starts skip this step).
3. cmake-configures + builds gost-engine + gostprov against that
   OpenSSL prefix; installs `gost.so` (3.x only) and
   `gostprov.so` into `/opt/openssl/lib64/{engines-3,ossl-modules}/`.
4. Writes both `/opt/openssl/gost-engine.cnf` (default
   `OPENSSL_CONF` on 3.x, engine-mode) and
   `/opt/openssl/gost-provider.cnf` (provider-mode, opt-in via env
   override on 3.x; default on 4.0).

The initial build runs once per named volume. To re-run it (e.g.
after a patch edit), wipe the volumes:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml down dev-3.4 dev-3.6 dev-4.0
docker volume rm \
    dev_pkcs12_openssl-prefix-3.4 dev_pkcs12_openssl-build-3.4 dev_pkcs12_gost-engine-build-3.4 \
    dev_pkcs12_openssl-prefix-3.6 dev_pkcs12_openssl-build-3.6 dev_pkcs12_gost-engine-build-3.6 \
    dev_pkcs12_openssl-prefix-4.0 dev_pkcs12_openssl-build-4.0 dev_pkcs12_gost-engine-build-4.0
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4 dev-3.6 dev-4.0
```

### Provider check (one-line probe)

Confirm `gostprov` loads under the provider config on every stack
before running the matrix:

```sh
for svc in dev-3.4 dev-3.6 dev-4.0; do
    echo "=== $svc ==="
    docker compose -f docker/dev_pkcs12/docker-compose.yml exec -T \
        -e OPENSSL_CONF=/opt/openssl/gost-provider.cnf \
        "$svc" /opt/openssl/bin/openssl list -providers
done
```

Expected: `gostprov` and `default` listed as `status: active` on all
three stacks.

### Tier-1 matrix (engine → CSP, provider mode, 12 cells)

```sh
./docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh
```

What it does, per cell:

1. `openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A`
2. `openssl req -x509 -new -key key.pem -subj /CN=<seed> -days 365`
3. `openssl pkcs12 -export -keypbe <cipher> -certpbe <cipher>
   -macalg <macalg> -password pass:123456`
4. Capture the engine-side cert SHA-1.
5. `docker cp` the PFX to the host (mounted into the cryptopro
   container at `/workspace/data`).
6. `certmgr -install -pfx -file <pfx> -pin 123456 -newpin 123456
   -carrier '\\.\HDIMAGE\<seed>' -silent`.
7. `certmgr -list -dn CN=<seed>` — assert `SHA1 Thumbprint` matches
   engine-side cert AND `PrivateKey Link: Yes`.
8. Cleanup: drop the cert from CSP `uMy` + delete the keyset
   carrier.

Matrix axes:

- **Stacks**: `dev-3.4`, `dev-3.6`, `dev-4.0` — provider mode is
  enabled via `OPENSSL_CONF=/opt/openssl/gost-provider.cnf`.
- **Ciphers**: `kuznyechik-ctr-acpkm`, `magma-ctr-acpkm`. OMAC
  variants (`*-acpkm-omac`) don't fit the provider mode — see the
  INACTIVE block at the top of each pkcs12-pbe patch.
- **`-macalg`**: `md_gost12_256`, `md_gost12_512`.

Total 12 cells. Expected:

```
===============================================
  Tier 1 — engine → CSP, 12 cells
  PASS:  12   (CSP accepted PFX with key link)
  FAIL:  0   (any failure is hard fail)
===============================================
```

Step 0 of each cell asserts that `gostprov` is active under the
configured `OPENSSL_CONF` before `genkey`: if the provider fails
to load, the cell fails with `PROVIDER SANITY FAIL`. A FAIL on any
cell is a hard fail; no XFAIL axis.

### ctest regression

Per-stack ctest run from inside each container:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'

docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.6 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'

docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-4.0 \
    bash -lc 'cd build && ctest --output-on-failure -j$(nproc)'
```

Expected counts:

| Stack    | Tests passing |
|----------|---------------|
| dev-3.4  | 21 / 21       |
| dev-3.6  | 21 / 21       |
| dev-4.0  |  9 /  9       |

The 4.0 count is lower because the engine-only ctests are not
registered there (`-DGOST_BUILD_ENGINE=OFF` on 4.0 — engine API was
removed from OpenSSL 4.0).

Full check (strict warnings + ctest + cppcheck + valgrind, longer):

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash /workspace/src/docker/dev_pkcs12/scripts/run-full-check.sh
```

### Engine vs provider PFX parity (optional)

On 3.x, `openssl pkcs12 -export` produces structurally identical
PFXes regardless of whether the symmetric crypto comes from the
engine module or the provider. Verified by the
`pkcs12_rfc9337_cross_mode_parity` ctest: byte-by-byte diff yields
0 differences across 346 structural bytes (only spec-mandated
random fields differ).

Re-run:

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    bash -lc 'cd build && ctest --output-on-failure -R pkcs12_rfc9337_cross_mode_parity'
```

Same on `dev-3.6`. On `dev-4.0` it doesn't apply: no engine to
compare against.
