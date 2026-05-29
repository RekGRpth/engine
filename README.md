# engine

A reference implementation of the Russian GOST crypto algorithms for OpenSSL

Compatibility: OpenSSL 3.0

License: same as the corresponding version of OpenSSL.

Mailing list: http://www.wagner.pp.ru/list-archives/openssl-gost/

Some useful links: https://www.altlinux.org/OSS-GOST-Crypto

DO NOT TRY BUILDING MASTER BRANCH AGAINST openssl 1.1.1! Use 1_1_1 branch instead!

# provider

A reference implementation in the same spirit as the engine, specified
above.

This is currently work in progress, with only a subset of all intended
functionality implemented: symmetric ciphers, hashes and MACs.

For more information, see [README.prov.md](README.prov.md)

# PKCS#12 (PFX)

Engine-side support for the legacy GOST 28147-89 PBE form (RFC 7292) and
RFC 9337 / RFC 9548 GOST PKCS#12 containers via the stock `openssl pkcs12`
command. CLI usage,
configuration knobs, and the on-the-wire OID table are documented in
[README.pkcs12.md](README.pkcs12.md).
