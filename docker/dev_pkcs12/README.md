# Development environment

Self-contained dev stack for building and exercising the engine
module and provider on three OpenSSL versions side-by-side without
polluting the host: three engine-side build containers
(OpenSSL 3.4 / 3.6 / 4.0) plus a sibling CryptoPro CSP container
for cross-validation.

## Layout

```
docker/dev_pkcs12/
├── docker-compose.yml          ← orchestrator (5 services)
├── Dockerfile.dev              ← engine/provider build container
├── Dockerfile.test             ← lean ctest runner
├── cryptopro/                  ← CryptoPro CSP 5.0 sibling
│   ├── Dockerfile.cryptopro
│   ├── entrypoint.cryptopro.sh
│   ├── readme.{dockerfile,certmgr,keygen}.md
│   ├── data/                   ← PFX swap area (bind-mounted into all dev services)
│   └── test_gamma/             ← seeded CPSD software RNG
└── scripts/
    ├── entrypoint.sh           ← per-version OpenSSL bootstrap + patch apply
    ├── fetch-openssl.sh        ← grab OpenSSL 3.4.0 / 3.6.0 / 4.0.0 sources
    ├── run-full-check.sh       ← strict-warnings rebuild + ctest + cppcheck + valgrind
    ├── cryptopro_keybag_decode.sh  ← CSP → engine, proprietary `.80` keybag
    └── engine_to_csp_matrix.sh ← engine → CSP, RFC 9337/9548 12-cell matrix
```

## Prerequisites

1. **OpenSSL sources** — `docker-compose.yml` bind-mounts
   `docker/dev_pkcs12/openssl/{3.4.0,3.6.0,4.0.0}/` into the dev containers
   as `/workspace/openssl-src`. Populate them once:

   ```sh
   docker/dev_pkcs12/scripts/fetch-openssl.sh           # all three
   docker/dev_pkcs12/scripts/fetch-openssl.sh 3.4.0     # subset
   ```

2. **CryptoPro CSP archive** *(optional, only for CSP-side tests)* —
   the proprietary CSP bundle is **not** redistributed in this repo.
   Download the Linux deb-only bundle (free registration) from
   <https://cryptopro.ru/products/csp/downloads> and place it at
   `docker/dev_pkcs12/cryptopro/cryptopro_linux-amd64_deb_*.tgz` before
   building the `cryptopro` service.

## Bring up

```sh
# All five services (drops you back to the shell after build):
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d

# A single stack:
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.4
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-3.6
docker compose -f docker/dev_pkcs12/docker-compose.yml up -d dev-4.0
```

`entrypoint.sh` builds the matching OpenSSL into `/opt/openssl`
inside the container (cached in a per-version named volume), applies
`patches/pkcs12/openssl-pkcs12-provider-pbe-${MAJOR}.${MINOR}.patch`, then
configures and installs gost-engine / gost-provider.

## Run tests

ctest per stack (`dev-3.4`, `dev-3.6`, `dev-4.0`):

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml exec dev-3.4 \
    sh -c 'cd build && ctest --output-on-failure'
```

CSP-side cross-validation (requires the `cryptopro` service to be up):

```sh
docker/dev_pkcs12/scripts/cryptopro_keybag_decode.sh    # CSP → engine, proprietary keybag
docker/dev_pkcs12/scripts/engine_to_csp_matrix.sh       # engine → CSP, RFC 9337/9548 12-cell
```

## Tear down

```sh
docker compose -f docker/dev_pkcs12/docker-compose.yml down                # keeps named volumes
docker compose -f docker/dev_pkcs12/docker-compose.yml down -v             # nukes OpenSSL build cache too
```
