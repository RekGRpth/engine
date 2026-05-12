/**********************************************************************
 *                  gost_cryptopro_keybag.h                            *
 *                                                                    *
 *  Decode-only support for the CryptoPro proprietary PKCS#12         *
 *  shrouded-keybag PBE algorithm (OID 1.2.840.113549.1.12.1.80).     *
 *  Encode is intentionally not implemented — RFC 9337 / RFC 9548     *
 *  Kuznyechik / Magma CTR-ACPKM (ratified 2015+) supersedes this     *
 *  2009-era GOST 28147-89 / GOST R 34.11-94-based PBE on every       *
 *  axis (strength, standardisation, maintenance), so emitting it     *
 *  from the engine adds no value over the stock RFC 9337 path.       *
 *                                                                    *
 *  Algorithm pipeline (from gostpfx.py::decode_cryptopro_pfx):       *
 *    1. PBE KDF — iterated GOST R 34.11-94 over UTF-16LE password ‖  *
 *       salt ‖ BE u16 counter (typically 2000 rounds) → K.           *
 *    2. GOST 28147-89 CFB decrypt under K, IV=salt[:8],              *
 *       S-box CryptoPro-A → CPBlob DER.                              *
 *    3. Strip 16-byte CPBlob header (algtype magic at bytes [4:6]:   *
 *       0x46aa = 256-bit, 0x42aa = 512-bit) → CPExportBlob DER.      *
 *    4. CEK unwrap: Ke = KDF_GOSTR3411_2012_256(K, label=0x26bdb878, *
 *       UKM) per Р 50.1.113-2016; GOST 28147-89 ECB-decrypt CEK_ENC  *
 *       under Ke (two 32-byte halves for 512-bit).                   *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#ifndef GOST_CRYPTOPRO_KEYBAG_H
#define GOST_CRYPTOPRO_KEYBAG_H

/* OID literals — single source of truth. */
#define OID_PBE_CRYPTOPRO_KEYBAG       "1.2.840.113549.1.12.1.80"
#define SN_PBE_CRYPTOPRO_KEYBAG        "pbe-cryptopro-keybag"
#define LN_PBE_CRYPTOPRO_KEYBAG        "CryptoPro shrouded-keybag PBE"

#define OID_CRYPTOPRO_KEYBAG_UNWRAP    "1.2.643.7.1.99.1.1"
#define SN_CRYPTOPRO_KEYBAG_UNWRAP     "cryptopro-keybag-unwrap"
#define LN_CRYPTOPRO_KEYBAG_UNWRAP     "CryptoPro shrouded-keybag CEK unwrap"

/* OID/NID registration. Resolves both
 * `pbe-cryptopro-keybag` and `cryptopro-keybag-unwrap` into NIDs
 * (creating them if absent, looking them up if `OBJ_create` reports
 * `OBJ_R_OID_EXISTS` from a prior load). Idempotent — safe to invoke
 * twice in the same process if the provider is loaded under two names.
 * Must be called from `OSSL_provider_init` BEFORE `register_cryptopro
 * _keybag_pbe` because the latter consumes the NIDs cached here. */
int bind_cryptopro_keybag_oids(void);

/* PBE algorithm registration. Wires the OID
 * `1.2.840.113549.1.12.1.80` to `EVP_PBE_TYPE_OUTER` with a
 * libcrypto-global keygen that derives K via `legacy_pbe_kdf` from the
 * password+salt+iters in `bagParams`, then injects K and salt[:8] into
 * the `cryptopro-keybag-unwrap` cipher's per-ctx state via
 * `EVP_CipherInit_ex2`. Must be called AFTER the provider's cipher
 * dispatch is published (i.e. after `*out = provider_functions` in
 * `OSSL_provider_init`'s caller chain — in practice we call it before
 * the chain returns, after `bind_cryptopro_keybag_oids`). */
int register_cryptopro_keybag_pbe(void);

/* Provider cipher dispatch table for `cryptopro-keybag-unwrap`
 * (NID resolved via OID 1.2.643.7.1.99.1.1). Decrypt-only.
 * Callbacks live in `gost_cryptopro_keybag.c`; this declaration
 * lets `gost_prov_cipher.c` reference the table from
 * `GOST_prov_ciphers[]` without seeing the per-ctx struct. */
#include <openssl/core_dispatch.h>
extern const OSSL_DISPATCH cryptopro_keybag_unwrap_cipher_functions[];

#endif /* GOST_CRYPTOPRO_KEYBAG_H */
