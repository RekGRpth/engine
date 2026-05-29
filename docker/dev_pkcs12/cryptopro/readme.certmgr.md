# certmgr — CryptoPro CSP CLI reference

Source: КриптоПро CSP 5.0 R4 KC3, ЖТЯИ.00103-04 93 02 (Приложение
командной строки для работы с сертификатами). Trimmed for in-tree
use; only the surface this repo touches.

`-` and `--` prefixes are equivalent. One command per invocation.
Option order is not significant.

---

## Stores

Names are prefixed `u` (current user) or `m` (machine). Bare names
without prefix are deprecated as of CSP 5.0.

| Short        | User       | Machine     | Purpose                        |
|--------------|------------|-------------|--------------------------------|
| `My`         | `uMy` *(default)* | `mMy`  | Personal / signing certificates |
| `Root`       | `uRoot`    | `mRoot`     | Trusted root CA certificates    |
| `CA`         | `uCA`      | `mCA`       | Intermediate CAs and CRLs       |
| `AddressBook`| `uAddressBook` | `mAddressBook` | Other parties' certs       |
| `Cache`      | `uCache`   | `mCache`    | Cert/CRL cache (read + delete)  |

---

## Return values

`0` — success. Non-zero — error message on `stderr`.

```
certmgr -list -thumbprint <sha1> -silent && echo OK || echo "FAIL: $?"
```

---

## Commands

### `-install` / `-inst`

Install a certificate, CRL, or PFX bundle into a store. Optionally
links the certificate to a private-key container.

```
certmgr -install [-store] [-file] [-container] [-pin] [-newpin]
                 [-pfx] [-crl] [-autodist] [-keep_exportable]
                 [-protected <none|medium|high>] [-at_signature]
                 [-to-container] [-ask-container] [-autocont]
                 [-carrier] [-stdin] [-silent] [-trace] [-tfmt]
```

Common forms:

```bash
# .cer into a named store
certmgr -install -store uMy   -file cert.cer
certmgr -install -store uRoot -file rootca.cer
certmgr -install -store uCA   -file subca.cer

# .cer linked to a private-key container
certmgr -install -store uMy -file cert.cer \
        -container '\\.\HDIMAGE\mycontainer' -pin 12345678

# Install cert directly from the container (cert lives inside it)
certmgr -install -container '\\.\HDIMAGE\mycontainer'

# Third-party cert without key link (AddressBook)
certmgr -install -store uAddressBook -file partner.cer -container skip

# PFX (cert + key bundle), default store. Add -keep_exportable
# if the imported key needs to be re-exportable later (PFX
# round-trip tests). See readme.keygen.md.
certmgr -install -pfx -file bundle.pfx -pin 12345678

# PFX with cert auto-distributed to correct stores
certmgr -install -pfx -autodist -file bundle.pfx -pin 12345678

# PFX onto a specific carrier with a new container PIN
certmgr -install -pfx -file bundle.pfx -pin 12345678 \
        -carrier '\\.\HDIMAGE\' -newpin 87654321

# Make imported keys exportable; raise protection level
certmgr -install -pfx -file bundle.pfx -pin 12345678 \
        -keep_exportable -protected high

# Use AT_SIGNATURE key type instead of AT_KEYEXCHANGE
certmgr -install -store uMy -file cert.cer \
        -container '\\.\HDIMAGE\mycontainer' -at_signature

# CRL into the CA store
certmgr -install -crl -store uCA -file revocation.crl

# Read cert from stdin
cat cert.cer | certmgr -install -stdin

# Non-interactive (return error instead of prompting)
certmgr -install -store uMy -file cert.cer -silent
```

---

### `-list`

Display certificates / CRLs from a store, file, or container.

```
certmgr -list [-store] [-file] [-container] [-dn] [-thumbprint]
              [-keyid] [-authkeyid] [-crl] [-pfx] [-pkcs10]
              [-at_signature] [-chain] [-verbose] [-stdin] [-pin]
```

```bash
certmgr -list                                  # default uMy
certmgr -list -store uRoot
certmgr -list -store mCA -crl
certmgr -list -file cert.cer
certmgr -list -file bundle.pfx -pfx -pin 12345678
certmgr -list -file document.sig               # certs embedded in CMS sig
certmgr -list -container '\\.\HDIMAGE\mycontainer'

# Filters
certmgr -list -dn CN=John,O=MyOrg
certmgr -list -thumbprint dd45247ab9db600dca42cc36c1141262fa60e3fe
certmgr -list -keyid <hex>
certmgr -list -authkeyid <hex>

# Verbosity
certmgr -list -verbose
certmgr -list -chain
```

Output fields worth parsing:

```
SHA1 Hash       : dd45247ab9db600dca42cc36c1141262fa60e3fe
PrivateKey Link : Yes
Container       : HDIMAGE\eb5f6857.000\D160
```

`SHA1 Hash` = the thumbprint used by `-thumbprint` filter and by
`cryptcp -sign`. `PrivateKey Link: Yes` means the cert is bound to
a usable private key.

---

### `-delete`

Remove a certificate, CRL, or key container.

```
certmgr -delete [-store] [-dn] [-thumbprint] [-keyid]
                [-container] [-crl] [-all] [-silent]
```

```bash
certmgr -delete 1                              # by index from -list
certmgr -delete -dn CN=Test                    # default uMy
certmgr -delete -store uMy -dn CN=Test,O=MyOrg
certmgr -delete -thumbprint <sha1> -silent     # exact, scriptable
certmgr -delete -container '\\.\HDIMAGE\testcontainer'
certmgr -delete -crl -store uCA -dn CN=MyCRL
certmgr -delete -store uMy -all                # everything matching
```

Without `-dn`, `-thumbprint`, or `-keyid` `-delete` will try to
remove every cert in the store and prompt for confirmation. Always
verify with `-list` first.

---

### `-export`

Export a certificate, CRL, or PFX bundle from a store / container
to a file.

> **PFX export prerequisite.** The private key must have been
> marked **exportable at container-creation time**. Re-export of a
> non-exportable key is not possible. See `readme.keygen.md` for the
> `cryptcp -creatcert -keep_exportable` flow.

```
certmgr -export [-store] [-container] [-dn] [-thumbprint]
                [-keyid] [-authkeyid] [-pfx] [-crl] [-all]
                [-base64] [-pin] [-at_signature] [-silent]
                -dest <path>
```

```bash
certmgr -export -store uMy -dest out.cer                # DER (default)
certmgr -export -store uMy -dest out.pem -base64        # PEM
certmgr -export -store uMy -dn CN=Test -dest test.cer
certmgr -export -thumbprint <sha1> -dest cert.cer
certmgr -export -container '\\.\HDIMAGE\mycontainer' -dest cert.cer
certmgr -export -store uMy -all -dest all_certs.p7b

# CRL
certmgr -export -crl -store mCA -dest revocation.crl
certmgr -export -crl -store mCA -dest revocation.pem -base64

# PFX (cert + key)
certmgr -export -pfx -thumbprint <sha1> -dest bundle.pfx -pin 12345678
```

---

### `-decode`

Re-encode between DER (binary) and Base64 (PEM).

```
certmgr -decode -src <in> -dest <out> [-der | -base64]
```

```bash
certmgr -decode -src cert.cer    -dest cert.pem -base64    # DER → PEM
certmgr -decode -src cert.pem    -dest cert.cer -der       # PEM → DER
```

---

### `-enumstores`

List logical store names available at a location.

```bash
certmgr -enumstores user
certmgr -enumstores machine
certmgr -enumstores all_locations
```

---

### `-updatestore`

Update a store to Windows-compatible format. **Unix/Linux only.**

```bash
certmgr -updatestore -store uMy
certmgr -updatestore -store uRoot -file store.cer
```

---

### `-help`

```bash
certmgr -help                 # general
certmgr -help -install        # per-command
```

---

## Options reference

| Option | Meaning |
|--------|---------|
| `-all` | Match every cert / CRL that fits the criteria |
| `-ask-container` | Interactive container picker |
| `-at_signature` | Use `AT_SIGNATURE` private-key type instead of `AT_KEYEXCHANGE` |
| `-authkeyid <hex>` | Filter by issuer (authority) key identifier |
| `-autocont` | Auto-find the container that matches the cert |
| `-autodist` | When importing PFX, auto-route certs to correct stores |
| `-base64` | Use Base64 encoding (default is DER) |
| `-carrier <path>` | Carrier path for PFX import, e.g. `\\.\HDIMAGE\` |
| `-certificate` | Work with certificates (default) |
| `-chain` | Show full certificate chain |
| `-container <name>` | `\\.\<reader>\<name>`. Use `skip` to install without key link |
| `-crl` | Work with CRLs instead of certificates |
| `-der` | Use DER encoding (default for `-decode`) |
| `-dest <path>` | Output file for `-decode` / `-export` |
| `-dn <field=value,...>` | DN search criteria (see DN fields) |
| `-file <path>` | Input file (DER / Base64 / serialized store / PFX / CRL) |
| `-keep_exportable` | Mark imported keys as exportable |
| `-keyid <hex>` | Filter by key identifier |
| `-newpin <pin>` | New container PIN for PFX-imported keys |
| `-pfx` | Work with PFX bundles |
| `-pin <pin>` | Container PIN or PFX password |
| `-pkcs10` | Work with PKCS#10 certificate requests |
| `-protected <mode>` | Container protection: `none`, `medium`, `high` |
| `-provname <name>` | Cryptographic provider name |
| `-provtype <id>` | Provider type (default `75`) |
| `-silent` | Non-interactive — return error instead of prompting |
| `-src <path>` | Source file for `-decode` |
| `-stdin` | Read input from stdin |
| `-store <name>` | Store name (see Stores table) |
| `-tfmt <flags>` | Log format flags (see security admin guide) |
| `-thumbprint <sha1>` | Filter by SHA-1 thumbprint (hex) |
| `-to-container` | Also write the cert into the container during install |
| `-trace <mode>` | Internal logging level |
| `-use-cont-ext` | Use container extension for certificates |
| `-verbose` | Detailed output |

---

## DN fields

Used with `-dn`. Multiple fields comma-separated.

| Field | Meaning |
|-------|---------|
| `CN`    | Common Name |
| `O`     | Organization |
| `OU`    | Organizational Unit |
| `C`     | Country (2-letter) |
| `L`     | Locality / city |
| `S`     | State / province |
| `E`     | Email |
| `SN`    | Surname |
| `T`     | Title |
| `OGRN`  | Legal-entity registration number (RU) |
| `SNILS` | Personal insurance number (RU) |

Example: `-dn CN=Test,O=MyOrg,C=RU`.

---

## Recipes

Wrapper assumed: `docker compose -f docker/dev_pkcs12/docker-compose.yml exec
cryptopro certmgr ...`. `/workspace/data` is the host-shared swap
area, bind-mounted from `docker/dev_pkcs12/cryptopro/data/`.

### Export a cert as PEM and copy to host

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -export -thumbprint <sha1> \
    -dest /workspace/data/backup.pem -base64 -silent
```

### Import a PFX bundle, raise protection, mark keys exportable

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -install -pfx -file /workspace/data/bundle.pfx \
    -pin 123456 -newpin 123456 \
    -keep_exportable -protected medium -silent
```

### Find and remove an expired cert

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -list                              # eyeball "Not valid after"
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -delete -thumbprint <sha1> -silent
```

### Re-encode a cert

```bash
docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
    certmgr -decode -src /workspace/data/cert.cer \
    -dest /workspace/data/cert.pem -base64
```

### Enumerate every known store on a fresh container

```bash
for store in uMy uRoot uCA uAddressBook uCache mMy mRoot mCA; do
    echo "== $store =="
    docker compose -f docker/dev_pkcs12/docker-compose.yml exec cryptopro \
        certmgr -list -store "$store" 2>/dev/null || echo "(empty)"
done
```
