# PKCS#12 (PFX) with GOST algorithms

Export and import of GOST-algorithm PKCS#12 containers via the stock
`openssl pkcs12` binary. Two PBE and outer-MAC schemes are covered:

- **Legacy GOST PBE (RFC 7292 + GOST 28147-89)** — `gost89` (or
  `gost89-cbc`) cipher under an RFC 7292 PBE wrapper; outer MAC is
  HMAC under one of the GOST hashes: 34.11-94, Streebog-256,
  Streebog-512.
- **RFC 9337 / RFC 9548 (TK-26)** — Kuznyechik and Magma in
  CTR-ACPKM mode under PBES2 + PBKDF2; PBKDF2 PRF is
  HMAC-Streebog-256 or HMAC-Streebog-512; outer MAC is the RFC 9548
  §3 KDF (PBKDF2 with `dkLen=96`, HMAC key = last 32 octets of the
  96-byte output).

Two independent implementations are shipped:

- **Engine** (`gost.so`, ENGINE_API) — works on OpenSSL 3.x with no
  libcrypto patch.
- **Provider** (`gostprov.so`, provider-API) — works on OpenSSL 3.4,
  3.6, and 4.0; the only option on 4.x. For RFC 9337/9548 conformance
  in provider mode, the libcrypto patch
  `patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch` is
  required (see [Provider mode](#provider-mode-openssl-3x-and-4x)).

Additionally, the provider can read (decode-only) PFX files whose
key bag uses the proprietary CryptoPro PBE OID
`1.2.840.113549.1.12.1.80` (see [CryptoPro proprietary keybag decode](#cryptopro-proprietary-keybag-decode-12840113549112180)).

## CLI usage

`openssl pkcs12` picks up algorithms from the active `openssl.cnf`
(path is taken from `OPENSSL_CONF=<path>`). Minimal configs:

Engine mode (`gost.so`, OpenSSL 3.x):

```ini
openssl_conf = openssl_def
[openssl_def]
engines = engines
[engines]
gost = gost_conf
[gost_conf]
default_algorithms = ALL
```

Provider mode (`gostprov.so`, OpenSSL 3.4 / 3.6 / 4.0):

```ini
openssl_conf = openssl_def
[openssl_def]
providers = providers
[providers]
gostprov = provider_conf
default = provider_conf
[provider_conf]
activate = 1
```

Working examples are in `test/engine.cnf` and `test/provider.cnf`.
The `gost.so` / `gostprov.so` search paths are taken from the
`OPENSSL_ENGINES` and `OPENSSL_MODULES` environment variables
respectively. The full list of engine ENGINE_CMD parameters
(`PBE_PARAMS`, `CRYPT_PARAMS`, `GOST_PK_FORMAT`) and supported
algorithms lives in `README.gost` at the repository root.

### Legacy GOST PBE (RFC 7292 + GOST 28147-89)

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe gost89 -certpbe gost89 \
    -macalg md_gost94 \
    -out bundle.p12
```

### RFC 9337 / 9548 (TK-26)

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

`-keypbe` / `-certpbe` accept any of the four CTR-ACPKM cipher names:

- `kuznyechik-ctr-acpkm`
- `kuznyechik-ctr-acpkm-omac`
- `magma-ctr-acpkm`
- `magma-ctr-acpkm-omac`

`-macalg` accepts the GOST hash names: `md_gost94`, `md_gost12_256`,
`md_gost12_512`.

## Environment variables

Baseline export:

```sh
openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

### `GOST_PBE_HMAC` — PBKDF2 PRF selection

Default PRF is HMAC-Streebog-512; PBKDF2 carries OID
`1.2.643.7.1.1.4.2`. Switch to HMAC-Streebog-256:

```sh
GOST_PBE_HMAC=md_gost12_256 openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

The PRF OID in the DER output becomes `1.2.643.7.1.1.4.1`. Accepts
`md_gost12_256`, `md_gost12_512`, `md_gost94`. Affects all four
CTR-ACPKM ciphers and `gost89*`.

### `LEGACY_GOST_PKCS12` — outer-MAC KDF

Default (unset): RFC 9548 §3 KDF (PBKDF2 with `dkLen=96`, last 32
octets → HMAC key). For pre-9548 readers, fall back to the
RFC 7292 §B.2 KDF:

```sh
LEGACY_GOST_PKCS12=1 openssl pkcs12 -export \
    -inkey priv.pem -in cert.pem \
    -keypbe kuznyechik-ctr-acpkm \
    -certpbe kuznyechik-ctr-acpkm \
    -macalg md_gost12_512 \
    -out bundle.p12
```

The MacData OIDs do not change — only the KDF that produces the
HMAC key.

## OIDs in the RFC 9337 / 9548 PFX

| Field                            | OID                       | Name                                              |
|----------------------------------|---------------------------|---------------------------------------------------|
| Keybag PBES2 outer               | `1.2.840.113549.1.5.13`   | `pbes2`                                           |
| Keybag PBES2 KDF                 | `1.2.840.113549.1.5.12`   | `pbkdf2`                                          |
| Keybag PBKDF2 PRF (256-bit)      | `1.2.643.7.1.1.4.1`       | `id-tc26-hmac-gost-3411-12-256`                   |
| Keybag PBKDF2 PRF (512-bit)      | `1.2.643.7.1.1.4.2`       | `id-tc26-hmac-gost-3411-12-512` (default)         |
| Keybag PBES2 cipher (Magma)      | `1.2.643.7.1.1.5.1.1`     | `id-tc26-cipher-gostr3412-2015-magma-ctracpkm`    |
| Keybag PBES2 cipher (Magma+OMAC) | `1.2.643.7.1.1.5.1.2`     | `id-tc26-cipher-gostr3412-2015-magma-ctracpkm-omac`                            |
| Keybag PBES2 cipher (Kuznyechik) | `1.2.643.7.1.1.5.2.1`     | `id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm`                            |
| Keybag PBES2 cipher (Kz+OMAC)    | `1.2.643.7.1.1.5.2.2`     | `id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac`                       |
| Outer MacData digest (256)       | `1.2.643.7.1.1.2.2`       | `id-tc26-gost3411-12-256`                         |
| Outer MacData digest (512)       | `1.2.643.7.1.1.2.3`       | `id-tc26-gost3411-12-512` (default)               |

The cert bag is wrapped in an `encryptedData` ContentInfo
(`1.2.840.113549.1.7.6`) and encrypted with the same PBES2 set as the
key bag.

## Cipher support matrix

| Cipher                        | Engine 3.4 | Engine 3.6 | Provider 3.4 | Provider 3.6 | Provider 4.0 |
|-------------------------------|:----------:|:----------:|:------------:|:------------:|:------------:|
| `kuznyechik-ctr-acpkm`        | ✓ | ✓ | ✓ | ✓ | ✓ |
| `kuznyechik-ctr-acpkm-omac`   | ✓ | ✓ | — | — | — |
| `magma-ctr-acpkm`             | ✓ | ✓ | ✓ | ✓ | ✓ |
| `magma-ctr-acpkm-omac`        | ✓ | ✓ | — | — | — |

OpenSSL 4.0 dropped the engine API upstream, hence no `Engine 4.0`
column.

The shipping verification matrix — provider mode × non-OMAC ciphers ×
3 OpenSSL versions (3.4 / 3.6 / 4.0) × 2 outer-MAC digests = 12
cells, all 12 pass. Reproduced by
`docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh` (see
[`docker/dev_pkcs12/README.md`](docker/dev_pkcs12/README.md)).

OMAC-cipher import into CryptoPro CSP 5.0.13003 is verified in
engine mode: `certmgr -install -pfx` accepts the PFX with
`PrivateKey Link: Yes` and exit code `0x00000000`.

## Provider mode (OpenSSL 3.x and 4.x)

The same RFC 9337 / 9548 wire format is reachable via the gost
**provider** (`gostprov.so`) instead of the engine (`gost.so`).
Provider mode is the only option on OpenSSL 4.0+, which dropped the
engine API; on 3.x both modes are available and produce
**structurally identical** PFXes (only spec-mandated random
fields differ).

### libcrypto patch (required in provider mode)

Provider mode for RFC 9337/9548 requires the libcrypto patch
`patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch` —
without it, `openssl pkcs12 -export` under `provider.cnf` fails
with `cipher has no object identifier`. Per-version variants ship
for OpenSSL 3.4, 3.6, and 4.0.

Per-hunk description and step-by-step apply instructions live in
[`patches/pkcs12/README.md`](patches/pkcs12/README.md).

### Selecting mode

Engine mode (default on 3.x):

```sh
export OPENSSL_CONF=/path/to/engine.cnf  # loads gost.so via [engine_section]
openssl pkcs12 -export ...
```

Provider mode (mandatory on 4.x, optional on 3.x):

```sh
export OPENSSL_CONF=/path/to/provider.cnf  # activates gostprov via [providers]
openssl pkcs12 -export ...
```

The CLI flags above (`-keypbe kuznyechik-ctr-acpkm`, `-macalg
md_gost12_512`, etc.) are unchanged. The only switch is the config
file. See `test/engine.cnf` and `test/provider.cnf` for working
examples.

## CryptoPro proprietary keybag decode (`1.2.840.113549.1.12.1.80`)

**Decode-only.** The provider can read PFX files emitted by
CryptoPro CSP's `certmgr -export -pfx` whose key bag uses the
proprietary PBE OID `1.2.840.113549.1.12.1.80`. The OID sits under
the `pkcs-12-pbeIds` arc but is not an RFC 7292 algorithm — it is
CryptoPro's own pre-RFC-9337 extension.

Decode is available in provider mode only; engine mode is not
supported.

When this keybag appears: on export via CSP-side `certmgr -export -pfx`
of a legacy GOST 2001 / GOST 2012-256/512 container created with
`csptest -newkeyset … -exportable`. The cert bag travels under the
standard `pbeWithSHAAnd40BitRC2-CBC` envelope (RFC 7292 OID
`1.2.840.113549.1.12.1.6`); only the key bag uses the proprietary
`.80` PBE.

### CLI usage

Decode runs in provider mode. Minimal `gostfull.cnf`:

```ini
HOME = .
openssl_conf = openssl_def

[openssl_def]
providers = provider_section

[provider_section]
default  = default_sect
legacy   = legacy_sect
gostprov = gostprov_sect

[default_sect]
activate = 1
[legacy_sect]
activate = 1
[gostprov_sect]
module   = /opt/openssl/lib64/ossl-modules/gostprov.so
activate = 1
```

```sh
OPENSSL_CONF=/path/to/gostfull.cnf \
    openssl pkcs12 \
        -in   legacy-csp-export.pfx \
        -password pass:123456 \
        -nodes \
        -out  recovered.pem
```

Output is the standard PEM bundle (`-----BEGIN CERTIFICATE-----` +
`-----BEGIN PRIVATE KEY-----`). The recovered private key is a
plain PKCS#8 `PrivateKeyInfo` and round-trips through `openssl
pkey -in recovered.pem -outform DER`.

### Verification

`docker/dev_pkcs12/scripts/cryptopro_keybag_decode.sh` mints an exportable
GOST 2012-256 keyset in CSP, exports the PFX via `certmgr -export -pfx`,
runs `openssl pkcs12` against it in each provider stack (`dev-3.4`,
`dev-3.6`, `dev-4.0`), and asserts: PEM markers present, recovered
key round-trips through `openssl pkey`, recovered cert SHA-1 matches
the CSP-captured thumbprint.

The driver runs from the host (it cannot run from inside a dev
container — there is no docker-in-docker), so it is not run as
part of the in-container `ctest` suite. CSP container + uMy entry are deleted on every exit path;
the PFX itself is retained at
`docker/dev_pkcs12/cryptopro/data/<seed>.pfx` for post-mortem on failure.
See [`docker/dev_pkcs12/README.md`](docker/dev_pkcs12/README.md) for prerequisites.

### Encode (not implemented)

Decode-only. The standard PFX export path from the engine and
provider is RFC 9337 / 9548 (see [RFC 9337 / 9548 (TK-26)](#rfc-9337--9548-tk-26)).

## References

- RFC 9337 — *Generating Password-Based Keys Using the GOST
  Algorithms* — <https://www.rfc-editor.org/rfc/rfc9337.html>. PBKDF2
  / PBES2 / PBMAC1 with HMAC-Streebog-256/512 and Kuznyechik/Magma
  CTR-ACPKM. §7.3 defines `Gost3412-15-Encryption-Parameters`.
- RFC 9548 — *Generating Transport Key Containers (PFX) Using the
  GOST Algorithms* — <https://www.rfc-editor.org/rfc/rfc9548.html>.
  PKCS#12 layout for GOST keys + integrity, including the §3
  outer-MAC KDF (PBKDF2 with `dkLen=96`, last 32 octets → HMAC key).
- RFC 7292 — *PKCS #12: Personal Information Exchange Syntax*.
  Appendix B.2 KDF is the legacy path reachable via
  `LEGACY_GOST_PKCS12=1`.
- RFC 8018 — *PKCS #5: Password-Based Cryptography Specification
  Version 2.1*. PBES2 / PBKDF2 / iteration / salt rules.
