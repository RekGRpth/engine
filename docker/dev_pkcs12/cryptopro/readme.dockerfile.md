# `cryptopro` service — image + container layout

Cross-validation target: CryptoPro CSP 5.0.13003 (kc1 build) running
in a Debian-based sibling to the `dev-3.4 / dev-3.6 / dev-4.0` engine
services. Wired into `docker/dev_pkcs12/docker-compose.yml` so
`docker compose ... cryptopro` Just Works.

The CryptoPro CSP archive is proprietary and is **not** redistributed
in this repo. Download the Linux deb-only bundle (free registration)
from <https://cryptopro.ru/products/csp/downloads> and place it at
`docker/dev_pkcs12/cryptopro/cryptopro_linux-amd64_deb_*.tgz` before building.

For the CSP CLI surface itself see:

- `readme.certmgr.md` — `certmgr` reference (stores, install,
  list, export, delete, decode).
- `readme.keygen.md` — verified key + cert + PFX export flow
  (csptest -newkeyset -exportable + -makecert + certmgr -export -pfx).

## Image — `gost-engine-cryptopro:local`

Built from `docker/dev_pkcs12/cryptopro/Dockerfile.cryptopro`. Source archive
`cryptopro_linux-amd64_deb_03-05-26.tgz` lives next to the Dockerfile
(gitignored via top-level `*.tgz`). Build context is `docker/dev_pkcs12/`.

Stages:

1. `debian:bookworm` base + runtime deps (`dpkg`, `lsb-base`,
   `ca-certificates`, `curl`, `libgcrypt20`, `libpcsclite1`).
2. `COPY cryptopro_linux-amd64_deb_03-05-26.tgz /tmp/cryptopro.tgz`.
3. `tar -xzf` + `./install.sh kc1 --yes` (unattended; on non-zero
   exit dumps `/var/log/dpkg.log`).
4. `rm -rf` of the unpacked archive to keep the image lean.
5. `PATH=/opt/cprocsp/bin/amd64:/opt/cprocsp/sbin/amd64:$PATH` for
   `certmgr / cryptcp / csptest / cpconfig`.
6. `COPY test_gamma /opt/cprocsp/share/test_gamma` (CPSD software
   RNG seed — see *Headless RNG* below).
7. `ENTRYPOINT entrypoint.cryptopro.sh` + `CMD sleep infinity`.

Build:

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml build cryptopro
```

Reproducible across runs: same manifest / config digests barring the
attestation manifest's timestamp. Final image ≈ 200–300 MB.

## Service definition

```yaml
cryptopro:
  build:
    context: .
    dockerfile: cryptopro/Dockerfile.cryptopro
  image: gost-engine-cryptopro:local
  container_name: gost-engine-cryptopro
  volumes:
    - ./cryptopro/data:/workspace/data
    - cryptopro-store:/var/opt/cprocsp
  stdin_open: true
  tty: true
```

- `./cryptopro/data:/workspace/data` is the **PFX swap area** —
  bind-mounted into `dev-3.4`, `dev-3.6`, `dev-4.0` at the same path, so
  a CSP-emitted PFX can be handed directly to `openssl pkcs12 -in`
  inside an engine container without `docker cp`.
- `cryptopro-store:/var/opt/cprocsp` persists the user/system
  certificate stores and the seeded CPSD gamma across `docker compose
  down` / `up` cycles. Reset by `docker volume rm cryptopro-store`.

Bring up:

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d cryptopro
```

First-start log (visible via `docker compose logs cryptopro`):

```
[entrypoint.cryptopro] seeded CPSD gamma at /var/opt/cprocsp/dsrf/db1/kis_1
[entrypoint.cryptopro] seeded CPSD gamma at /var/opt/cprocsp/dsrf/db2/kis_1
[entrypoint.cryptopro] removed BIO_TUI (interactive TUI RNG) from rndm registry
[entrypoint.cryptopro] CryptoPro CSP license state:
License validity:
5050N4003001BT72MA83QF3T0
Expires: 94 day(s)
License type: Demo.
```

## License — Demo / Trial only

No serial env-var wiring is provided. The 90-day trial is embedded
in the deb (serial `5050N4003001BT72MA83QF3T0`, ~94 days from
install). Re-running `cpconfig -license -view` inside the container
shows the current expiry. Acceptable for cross-validation; production
users would override at deploy time, not here.

## Headless RNG — automatic on first start

CryptoPro CSP cannot generate keys on a fresh install without a
seeded software RNG. The image ships a test gamma at
`/opt/cprocsp/share/test_gamma/db1/kis_1` (864 bytes)
and the entrypoint:

1. Copies it into `/var/opt/cprocsp/dsrf/db{1,2}/kis_1` if the dsrf
   slots are empty (CPSD config maps both — the entrypoint populates
   both for redundancy).
2. Removes `BIO_TUI` from the registered RNGs so the level-3 CPSD
   doesn't get preempted by the level-5 interactive TUI capture
   under `-silent` invocations.

Both steps are **idempotent**: subsequent restarts no-op once the
gamma is in place and BIO_TUI is gone.

To use a fresh production gamma instead of the baked test gamma,
either:

- replace `docker/dev_pkcs12/cryptopro/test_gamma/db1/kis_1` before building, or
- generate fresh gamma at runtime:

  ```bash
  docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
      genkpim 27 01d2c1c8 /var/opt/cprocsp/dsrf/db1/
  ```

## Anti-rules / gotchas

- **Never run `/etc/init.d/cprocsp start`** inside the container.
  `cpinstance`'s integrity check false-positives on
  `libcapi20.so.4.0.5` under docker overlay-fs and renames it to
  `corrupted.libcapi20.so.4.0.5`, breaking `csptest`. Recovery: see
  `readme.keygen.md` "Anti-rule" section.
- **`docker compose exec cryptopro bash -lc <cmd>`** loses the
  Dockerfile `PATH` to `/etc/profile`. Use `sh -c` or absolute
  paths: `docker compose exec cryptopro sh -c '<cmd>'`.
- **`-silent` blocks the CSP RNG** at multiple call sites
  (`csptest -newkeyset`, `certmgr -export -pfx`). Drop it for keygen
  / PFX-export; use it only for read-only enumeration like
  `certmgr -list -silent`.

## Day-to-day

Quick cert-store smoke:

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -list -store mRoot
```

Expected: 8 preloaded GOST roots from `lsb-cprocsp-ca-certs`
(CryptoPro GOST Root CA, Минцифры России, Russian Trusted Root CA,
ГУЦ, etc.) — the deb seeds the store on install.

Drop into a shell:

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    sh
```

Tear down (keeps volumes):

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml stop cryptopro
```

Full reset (deletes the cert store and any minted containers):

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml down cryptopro
docker volume rm dev_pkcs12_cryptopro-store
```
