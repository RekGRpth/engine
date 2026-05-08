# CryptoPro CSP — key + cert generation for PFX export

Companion to `readme.certmgr.md`. Covers the **one** flow we actually
need: mint a fresh exportable key container with a self-signed cert
inside the `cryptopro` service, then later pull both out as a PFX
via `certmgr -export -pfx`.

The flow below is **verified end-to-end** against CryptoPro CSP
5.0.13003 (kc1 build). Every flag and OID listed comes from
`csptest -keyset -help` / `certmgr -export -help` output, **not**
the upstream kc3 PDF (which references commands and flags that this
CSP build does not ship).

## Hard rule — exportable at creation

CryptoPro CSP **will not export a private key that wasn't created
exportable**. There is no retroactive flip; you mint the key
exportable, or you regenerate. The verified recipe below passes
`-exportable` to `csptest -keyset -newkeyset`. Skipping it is the
single most common reason `certmgr -export -pfx` fails with
`0x8009000b NTE_BAD_KEY_STATE` ("Key not valid for use in specified
state").

## Headless RNG prerequisite — CPSD gamma

A fresh CSP install cannot generate keys at all without seeded
software RNG. Two issues out of the box:

- `/var/opt/cprocsp/dsrf/db{1,2}/` are empty → CPSD RNG returns
  `0x80090020` ("internal error") on `-newkeyset`.
- The fallback `BIO_TUI` RNG (level 5) is **interactive** — it
  prompts "Press keys to provide random data…" and any `-silent`
  invocation aborts with `0x80090022` ("context was acquired as
  silent"). Piping `/dev/urandom` to stdin doesn't satisfy it.

`entrypoint.cryptopro.sh` handles both on first start:

1. Copies the baked test gamma from
   `/opt/cprocsp/share/test_gamma/db1/kis_1` into both
   `/var/opt/cprocsp/dsrf/db1/kis_1` and `…/db2/kis_1`.
2. Removes BIO_TUI from the registered RNGs so CPSD (level 3) is the
   only RNG available, ensuring deterministic non-interactive
   behaviour under `-silent`.

After the first `docker compose up cryptopro`, keygen works without
manual setup. To regenerate the gamma yourself (the test gamma is for
testing only — production should mint a fresh portion per
environment):

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    genkpim 27 01d2c1c8 /var/opt/cprocsp/dsrf/db1/
```

`genkpim <num_keys> <id_hex> <path>` is the official CryptoPro CPSD
generator. `27` = number of keys derivable from this CPSD portion;
`01d2c1c8` = 8-digit hex id label; trailing path is where `kis_1`
(the gamma) lands.

## Anti-rule — do not run `/etc/init.d/cprocsp start`

`cpinstance`'s integrity check false-positives on
`libcapi20.so.4.0.5` under docker overlay-fs and renames it to
`corrupted.libcapi20.so.4.0.5`, breaking `csptest`. The container's
CSP libraries work fine without the init.d service; entrypoint only
needs the gamma seed (above). If you accidentally trip the rename:

```bash
docker compose exec cryptopro sh -c '
    mv /opt/cprocsp/lib/amd64/corrupted.libcapi20.so.4.0.5 \
       /opt/cprocsp/lib/amd64/libcapi20.so.4.0.5
    ln -sf libcapi20.so.4.0.5 /opt/cprocsp/lib/amd64/libcapi20.so.4
    ldconfig
'
```

## Verified flow — csptest `-newkeyset` + `-makecert`

This is the actual primary path. Earlier docs referenced
`cryptcp -creatcert -keep_exportable` — that command **does not exist
in CSP 5.0.13003**. `cryptcp -help` lists `-createcert` (CA-bound,
interactive) and `-createrqst` (PKCS#10 only); neither mints a self-
signed cert in one shot. The `csptest -keycopy` "two-step exportable"
idiom is also fictional — `csptest -keycopy` has no
`-exchangeprivate`/`-signatureprivate` flags in this build.

### Step 1 — mint exportable container

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    csptest -keyset -newkeyset \
        -container '\\.\HDIMAGE\test-<seed>' \
        -provtype 80 \
        -keytype exchange \
        -exportable \
        -password 123456
```

Container path syntax: `\\.\HDIMAGE\<name>` (literal single
backslashes after shell un-escape; double-quoted single-quoted nested
heredocs eat them, mind your shell layers). `-provtype 80` = GOST
2012-256; `81` = GOST 2012-512 (note: type 81 default name is
`Crypto-Pro GOST R 34.10-2012 KC1 Strong CSP`, with "Strong"). The
`-password 123456` here **sets** the container PIN despite the help
calling it "auth".

### Step 2 — mint self-signed cert into the container

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    csptest -keyset \
        -container '\\.\HDIMAGE\test-<seed>' \
        -provtype 80 \
        -password 123456 \
        -makecert
```

`-makecert` synthesises subject/issuer DN as `E=test@cryptopro.ru,
CN=<container_name>` automatically — there is no `-rdn` flag in
csptest. Validity defaults to roughly 4 years. Acceptable for cross-
validation; not configurable from the CLI.

If you need a custom subject DN, you'd have to:

- Run `cryptcp -createrqst -rdn "CN=...,O=..."` to get a PKCS#10,
- Sign it externally (e.g. via OpenSSL with the gost engine after
  some round-tripping), and
- Install the resulting cert via
  `certmgr -install -file <cert.cer> -container '\\.\HDIMAGE\<seed>'`.

For our cross-validation flow the auto-DN is sufficient.

### Step 3 — install cert into uMy store with key-link

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -install -container '\\.\HDIMAGE\test-<seed>'
```

After this, `certmgr -list` shows the cert in the default `uMy`
store with `PrivateKey Link: Yes`.

Pull the SHA-1 thumbprint for the export step:

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -list -dn "CN=test-<seed>" \
    | awk '/SHA1 Thumbprint/ {print $NF}'
```

### Step 4 — export PFX

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro sh -c \
    "echo '123456' | certmgr -export -pfx \
        -container '\\\\.\\HDIMAGE\\test-<seed>' \
        -dest /workspace/data/test-<seed>.pfx \
        -pin 123456"
```

Critical quirks:

- **`-pin <pwd>`** is the **PFX password only**. The container PIN is
  requested **interactively** — pipe `123456\n` via stdin (`echo
  '123456' | …`). Both happen to be `123456` in this guide, but the
  channels are independent.
- **Do not pass `-silent`** — it blocks the RNG read for the PBE salt
  and aborts with `0x80090022`. Yes, even with CPSD seeded; `-silent`
  blocks any RNG read at the certmgr layer.
- The wrong-password error you'll see if stdin has the wrong (or
  empty) container PIN: `Wrong password. Tries left: 4.`
- Equivalent form via uMy / thumbprint: `certmgr -export -pfx
  -thumbprint <sha1> -dest <path> -pin 123456` (also requires stdin
  PIN feed).

### Step 5 (optional) — cleanup after a matrix cell

```bash
# remove cert from uMy
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -delete -dn "CN=test-<seed>" -silent

# delete key container
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    csptest -keyset -deletekeyset \
        -container '\\.\HDIMAGE\test-<seed>'
```

## csptest flag reference (verified)

`csptest -keyset` operations:

| Operation        | Meaning |
|------------------|---------|
| `-newkeyset`     | Create container + key set |
| `-deletekeyset`  | Remove container |
| `-makecert`      | Self-signed cert into container |
| `-fmakecert <f>` | Self-signed cert into a file |
| `--check[=mask]` | Check container integrity (1=remask, 2=keys+certs, 4=header, 8=cert license; default = all) |
| `-enum_containers` | Enumerate containers |

`csptest -keyset` options:

| Option              | Meaning |
|---------------------|---------|
| `-container <name>` | Container path (NOT `-cont`) |
| `-password <pin>`   | Container PIN — sets on `-newkeyset`, authenticates on others |
| `-exportable`       | Mark key exportable at creation |
| `-keytype <t>`      | `exchange`, `signature`, `uec`, `symmetric`, `none`. Default = both signature and exchange |
| `-provtype <id>`    | Provider type (default 80 = GOST 2012-256) |
| `-provname <name>`  | Provider name (default = type-default, e.g. `Crypto-Pro GOST R 34.10-2012 KC1 CSP`) |
| `-protected[=lvl]`  | `none`, `medium` (default), `high` |
| `-silent`           | No interactive UI — ABORTS keygen because it blocks the RNG read; only use for read-only ops |
| `-machinekeyset`    | Open `HKLM` instead of user store |
| `-fqcn`             | Output Fully Qualified Container Name |

`csptest -keycopy` flags (not used in primary flow; here for
completeness):

| Flag                | Meaning |
|---------------------|---------|
| `-contsrc <name>`   | Source container (NOT `-src`) |
| `-contdest <name>`  | Destination container (NOT `-dest`) |
| `-pinsrc <pin>`     | Source container PIN |
| `-pindest <pin>`    | Destination container PIN |
| `-archivable`       | Mark destination key archivable |
| `-typesrc/-typedest`| Provider type per side |
| `-provsrc/-provdest`| Provider name per side |

(The `-exchangeprivate` / `-signatureprivate` flags referenced in
older CryptoPro docs do not exist in CSP 5.0.13003.)

## CSP 5.0.13003 surface — quick summary

- **Provider types / names**: 80 = `Crypto-Pro GOST R 34.10-2012 KC1
  CSP`, 81 = `Crypto-Pro GOST R 34.10-2012 KC1 Strong CSP`, 75 = GOST
  2001 (legacy), all KC1.
- **`cryptcp` is included in kc1** — no `cprocsp-pki-cades-64` deb
  needed. But `cryptcp -creatcert` does not exist; use the csptest
  flow above.
- **`lsb-cprocsp-pkcs11-64` is NOT required** for PFX export.
- **License** is Demo / 90+ days, embedded in the deb. No serial env
  var wiring needed.
- **Engine-side note**: CSP-emitted PFX uses a non-standard PBE OID
  `1.2.840.113549.1.12.1.80` for the shrouded keybag. RFC 7292 only
  registers `pkcs-12-PbeIds` children 1..6. The engine's PBE
  registration is extended in this PR (CryptoPro keybag module) so
  CSP-produced PFX can be decoded by `openssl pkcs12 -in`.
