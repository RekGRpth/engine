/**********************************************************************
 *                  gost_cryptopro_keybag.c                            *
 *                                                                    *
 *  Decode-only support for the CryptoPro proprietary PKCS#12         *
 *  shrouded-keybag PBE algorithm (1.2.840.113549.1.12.1.80).         *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#include <openssl/asn1.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <string.h>
#include "gost89.h"
#include "gost_cryptopro_keybag.h"
#include "gost_cryptopro_keybag_asn1.h"

#ifndef NID_id_GostR3411_94
# include <openssl/obj_mac.h>
#endif

static int nid_pbe_cryptopro_keybag    = NID_undef;
static int nid_cryptopro_keybag_unwrap = NID_undef;

/* Forward declarations — definitions live further down in this file. */
int legacy_pbe_kdf(const char *pass, int passlen,
                   const unsigned char *salt, size_t salt_len,
                   int iters, unsigned char out_K[32]);
int kdf_gostr3411_2012_256(const unsigned char K[32],
                           const unsigned char *label, size_t label_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char out_Ke[32]);

/* Resolve `oid` into a NID by either creating it (when this is the
 * first call) or looking it up (when a prior bind already added it).
 * The engine can be loaded twice in the same process — once via
 * `-engine gost`, then implicitly through `OPENSSL_CONF` — so every
 * `OBJ_create` must tolerate `OBJ_R_OID_EXISTS`.
 */
static int resolve_or_create_nid(const char *oid, const char *sn,
                                 const char *ln, int *out_nid)
{
    int nid = OBJ_create(oid, sn, ln);
    if (nid != NID_undef) {
        *out_nid = nid;
        return 1;
    }

    unsigned long e = ERR_peek_last_error();
    if (ERR_GET_REASON(e) == OBJ_R_OID_EXISTS) {
        ERR_clear_error();
        ASN1_OBJECT *o = OBJ_txt2obj(oid, 1);
        if (o != NULL) {
            nid = OBJ_obj2nid(o);
            ASN1_OBJECT_free(o);
            if (nid != NID_undef) {
                *out_nid = nid;
                return 1;
            }
        }
    }
    return 0;
}

int bind_cryptopro_keybag_oids(void)
{
    if (!resolve_or_create_nid(OID_PBE_CRYPTOPRO_KEYBAG,
                               SN_PBE_CRYPTOPRO_KEYBAG,
                               LN_PBE_CRYPTOPRO_KEYBAG,
                               &nid_pbe_cryptopro_keybag))
        return 0;

    if (!resolve_or_create_nid(OID_CRYPTOPRO_KEYBAG_UNWRAP,
                               SN_CRYPTOPRO_KEYBAG_UNWRAP,
                               LN_CRYPTOPRO_KEYBAG_UNWRAP,
                               &nid_cryptopro_keybag_unwrap))
        return 0;

    return 1;
}

/* EVP_PBE keygen callback for OID 1.2.840.113549.1.12.1.80. Invoked
 * from libcrypto's `EVP_PBE_CipherInit_ex` when PKCS#12 unwrap meets
 * a SafeBag whose `bagParams.algorithm` matches our PBE OID. The
 * caller has already fetched `cipher` (cryptopro-keybag-unwrap) from
 * the active libctx and `md` (md_gost94) from the engine/provider.
 * Our job: derive K from the password+salt+iters and inject K +
 * salt[:8] (as IV) into the cipher context's per-ctx state via
 * `EVP_CipherInit_ex`. The subsequent `EVP_DecryptUpdate` /
 * `EVP_DecryptFinal` walks through our cipher dispatch (15a-5) and
 * yields PKCS#8 PrivateKeyInfo DER. */
static int cryptopro_keybag_keygen(EVP_CIPHER_CTX *cctx,
                                   const char *pass, int passlen,
                                   ASN1_TYPE *param,
                                   const EVP_CIPHER *cipher,
                                   const EVP_MD *md, int en_de)
{
    CPParamsValue *pbe = NULL;
    unsigned char K[32];
    unsigned char iv[8];
    long iters;
    const unsigned char *salt;
    int salt_len;
    int ret = 0;

    /* `md` is fixed at NID_id_GostR3411_94 by `register_cryptopro_keybag_pbe`
     * — `legacy_pbe_kdf` consults it directly via EVP_get_digestbynid, so
     * we don't need the param-supplied handle here. */
    (void)md;

    if (cctx == NULL || cipher == NULL || param == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }
    if (param->type != V_ASN1_SEQUENCE || param->value.sequence == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }

    /* Unpack `bagParams.parameters` as CPParamsValue { salt, iters }. */
    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(CPParamsValue), param);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }

    salt     = ASN1_STRING_get0_data(pbe->salt);
    salt_len = ASN1_STRING_length(pbe->salt);
    iters    = ASN1_INTEGER_get(pbe->iters);

    /* Bound checks. CSP keybag salt is fixed at 16 B; iter counts
     * observed at 2000 (CSP default) but spec leaves it open. Reject
     * pathological values that would let a malicious PFX tie up the
     * KDF loop indefinitely. */
    if (salt_len < 8 || iters < 1 || iters > 1000000) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        goto done;
    }

    if (pass == NULL)
        passlen = 0;
    else if (passlen == -1)
        passlen = (int)strlen(pass);

    if (!legacy_pbe_kdf(pass, passlen, salt, (size_t)salt_len, (int)iters, K))
        goto done;

    memcpy(iv, salt, 8);

    /* Re-init the cctx with K and IV. The cipher is already attached
     * — EVP_CipherInit_ex with `cipher != NULL` and a matching cipher
     * is a re-init that propagates K/IV into the provider dispatch
     * via DECRYPT_INIT (15a-5). */
    if (!EVP_CipherInit_ex(cctx, cipher, NULL, K, iv, en_de))
        goto done;

    ret = 1;

done:
    OPENSSL_cleanse(K,  sizeof(K));
    OPENSSL_cleanse(iv, sizeof(iv));
    CPParamsValue_free(pbe);
    return ret;
}

int register_cryptopro_keybag_pbe(void)
{
    if (nid_pbe_cryptopro_keybag == NID_undef
        || nid_cryptopro_keybag_unwrap == NID_undef)
        return 0;

    /* `EVP_PBE_alg_add_type` is libcrypto-global (no provider-side
     * equivalent exists; verified against `crypto/evp/evp_pbe.c:269-272`
     * on 4.0.0). The cipher_nid here is resolved later via
     * `EVP_CIPHER_fetch(libctx, OBJ_nid2sn(.unwrap), propq)` against
     * whichever libctx hosts the keygen call — typically the global
     * default in `openssl pkcs12`. */
    return EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER,
                                nid_pbe_cryptopro_keybag,
                                nid_cryptopro_keybag_unwrap,
                                NID_id_GostR3411_94,
                                cryptopro_keybag_keygen);
}

void unregister_cryptopro_keybag_pbe(void)
{
    /* Wholesale wipe — libcrypto exposes no targeted-remove API. See
     * the .h file's contract note for why this is acceptable in our
     * provider lifecycle. */
    EVP_PBE_cleanup();
}

/* ASCII-fast UTF-8 → UTF-16LE: each input byte < 0x80 becomes
 * (byte, 0x00). Returns malloc'd buffer of size 2*passlen and writes
 * the length to *out_len. Caller frees with OPENSSL_free.
 *
 * CryptoPro CSP container passwords are practically always ASCII;
 * non-ASCII input is rejected with NULL — proper UTF-8 transcoding
 * can land in a follow-up if a real-world Cyrillic-password .pfx
 * surfaces. */
static unsigned char *pwd_to_utf16le(const char *pass, int passlen,
                                     size_t *out_len)
{
    unsigned char *buf;
    int i;

    buf = OPENSSL_malloc((size_t)passlen * 2);
    if (buf == NULL)
        return NULL;
    for (i = 0; i < passlen; i++) {
        if ((unsigned char)pass[i] >= 0x80) {
            OPENSSL_free(buf);
            return NULL;
        }
        buf[2 * i]     = (unsigned char)pass[i];
        buf[2 * i + 1] = 0;
    }
    *out_len = (size_t)passlen * 2;
    return buf;
}

/* CryptoPro proprietary PBE KDF — iterated GOST R 34.11-94 over
 * `K_{i-1} ‖ salt ‖ counter (BE u16)`. Initial K_0 = UTF-16LE(password).
 * Counter starts at 1, runs through `iters` (typically 2000). Output is
 * the 32-byte K of the final iteration. Mirrors
 * `gostpfx.py::_legacy_pbe_kdf` / `decode_cryptopro_pfx` stage 1. */
int legacy_pbe_kdf(const char *pass, int passlen,
                   const unsigned char *salt, size_t salt_len,
                   int iters, unsigned char out_K[32])
{
    int ret = 0;
    int c;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char *pwd_utf16 = NULL;
    size_t pwd_utf16_len = 0;
    unsigned char K[32];
    const unsigned char *cur_key;
    size_t cur_key_len;

    if (pass == NULL || salt == NULL || iters < 1 || passlen < 0)
        return 0;

    /* On 3.x with the gost engine loaded, `EVP_get_digestbynid` finds
     * md_gost94 via the legacy lookup table — try that first to keep
     * the engine path unchanged. On 4.0 the engine API is gone: only
     * the provider is loaded, so md_gost94 is reachable solely via
     * `EVP_MD_fetch` (the provider exposes it through
     * `gost_prov_digest.c::GostR3411_94_digest`). Cache the fetched
     * handle in a function-local static so we pay the lookup cost
     * once per process. */
    {
        static EVP_MD *md_fetched = NULL;
        md = EVP_get_digestbynid(NID_id_GostR3411_94);
        if (md == NULL) {
            if (md_fetched == NULL)
                md_fetched = EVP_MD_fetch(NULL, SN_id_GostR3411_94, NULL);
            md = md_fetched;
        }
        if (md == NULL)
            goto done;
    }

    pwd_utf16 = pwd_to_utf16le(pass, passlen, &pwd_utf16_len);
    if (pwd_utf16 == NULL)
        goto done;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto done;

    cur_key     = pwd_utf16;
    cur_key_len = pwd_utf16_len;

    for (c = 1; c <= iters; c++) {
        unsigned char ctr_be[2];
        unsigned int outlen = 32;

        ctr_be[0] = (unsigned char)((c >> 8) & 0xff);
        ctr_be[1] = (unsigned char)(c & 0xff);

        if (!EVP_DigestInit_ex(mdctx, md, NULL))
            goto done;
        if (!EVP_DigestUpdate(mdctx, cur_key, cur_key_len))
            goto done;
        if (!EVP_DigestUpdate(mdctx, salt, salt_len))
            goto done;
        if (!EVP_DigestUpdate(mdctx, ctr_be, 2))
            goto done;
        if (!EVP_DigestFinal_ex(mdctx, K, &outlen))
            goto done;
        if (outlen != 32)
            goto done;

        cur_key     = K;
        cur_key_len = 32;
    }

    memcpy(out_K, K, 32);
    ret = 1;

done:
    if (pwd_utf16 != NULL) {
        OPENSSL_cleanse(pwd_utf16, pwd_utf16_len);
        OPENSSL_free(pwd_utf16);
    }
    OPENSSL_cleanse(K, sizeof(K));
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/* Single-block KDF_GOSTR3411_2012_256 per Р 50.1.113-2016 (i=1, L=256):
 * Ke = HMAC-Streebog-256(K, 0x01 ‖ label ‖ 0x00 ‖ seed ‖ 0x01 0x00).
 * Used in CryptoPro CSP keybag CEK unwrap — `label` is the constant
 * `0x26bdb878`, `seed` is the per-bag UKM. */
int kdf_gostr3411_2012_256(const unsigned char K[32],
                           const unsigned char *label, size_t label_len,
                           const unsigned char *seed, size_t seed_len,
                           unsigned char out_Ke[32])
{
    int ret = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    const unsigned char prefix = 0x01;
    const unsigned char zero   = 0x00;
    const unsigned char suffix[2] = { 0x01, 0x00 };
    size_t outlen = 0;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL)
        goto done;

    params[0] = OSSL_PARAM_construct_utf8_string("digest",
                                                 (char *)"md_gost12_256", 0);
    params[1] = OSSL_PARAM_construct_end();

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto done;

    if (!EVP_MAC_init(ctx, K, 32, params))
        goto done;

    if (!EVP_MAC_update(ctx, &prefix, 1))
        goto done;
    if (!EVP_MAC_update(ctx, label, label_len))
        goto done;
    if (!EVP_MAC_update(ctx, &zero, 1))
        goto done;
    if (!EVP_MAC_update(ctx, seed, seed_len))
        goto done;
    if (!EVP_MAC_update(ctx, suffix, 2))
        goto done;

    if (!EVP_MAC_final(ctx, out_Ke, &outlen, 32))
        goto done;
    if (outlen != 32)
        goto done;

    ret = 1;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

/* GOST 28147-89 CFB-decrypt under CryptoPro-A S-box. Pinned S-box —
 * does NOT consult engine's `CRYPT_PARAMS` runtime config — so the
 * dispatch behaves correctly regardless of how openssl/engine config
 * is set up by the caller. Mirrors `gostpfx.py::_cfb_decrypt`. Handles
 * a partial trailing block (last `inl % 8` bytes) the same way: XOR
 * only the available keystream bytes. */
static int cryptopro_cfb_decrypt(const unsigned char K[32],
                                 const unsigned char iv[8],
                                 const unsigned char *in,
                                 unsigned char *out, size_t inl)
{
    gost_ctx ctx;
    unsigned char fb[8];
    unsigned char keystream[8];
    size_t i;
    int j;

    gost_init(&ctx, &Gost28147_CryptoProParamSetA);
    gost_key_nomask(&ctx, K);
    memcpy(fb, iv, 8);

    for (i = 0; i + 8 <= inl; i += 8) {
        gostcrypt(&ctx, fb, keystream);
        for (j = 0; j < 8; j++)
            out[i + j] = in[i + j] ^ keystream[j];
        memcpy(fb, in + i, 8);   /* CFB feedback uses ciphertext */
    }
    if (i < inl) {
        size_t rem = inl - i;
        size_t k;
        gostcrypt(&ctx, fb, keystream);
        for (k = 0; k < rem; k++)
            out[i + k] = in[i + k] ^ keystream[k];
    }

    OPENSSL_cleanse(keystream, sizeof(keystream));
    OPENSSL_cleanse(fb, sizeof(fb));
    gost_destroy(&ctx);
    return 1;
}

/* GOST 28147-89 ECB-decrypt under CryptoPro-A S-box. `len` must be a
 * multiple of 8. Used to unwrap the export CEK. No diversification, no
 * IMIT — this is plain ECB, the keybag CEK_MAC field is left
 * unverified per gostpfx.py L919-924 (the recovered key is verified
 * out-of-band by re-deriving the public key, not via CEK_MAC). */
static int cryptopro_ecb_decrypt(const unsigned char Ke[32],
                                 const unsigned char *in,
                                 unsigned char *out, size_t len)
{
    gost_ctx ctx;

    if (len == 0 || len % 8 != 0)
        return 0;

    gost_init(&ctx, &Gost28147_CryptoProParamSetA);
    gost_key_nomask(&ctx, Ke);
    gost_dec(&ctx, in, out, (int)(len / 8));
    gost_destroy(&ctx);
    return 1;
}

/* Build a PKCS#8 PrivateKeyInfo DER for a recovered GOST private key.
 *
 * Output shape matches what `gost_ameth.c::internal_priv_encode` emits
 * in default (non-PK_WRAP) mode and what `gostpfx.py::_key_to_pem`
 * produces:
 *
 *   PrivateKeyInfo ::= SEQUENCE {
 *     version             INTEGER (0),
 *     privateKeyAlgorithm AlgorithmIdentifier {
 *         algorithm OBJECT IDENTIFIER (algo_nid),
 *         parameters SEQUENCE { curve OID, digest OID }
 *     },
 *     privateKey OCTET STRING (raw 32/64 bytes — already in the
 *                              little-endian wire format CSP exports)
 *   }
 *
 * On success `*out_der` points to a libcrypto-allocated buffer the
 * caller must `OPENSSL_free`; returns the DER length. On failure
 * returns -1 and leaves `*out_der` NULL.
 *
 * Byte order: `raw` is consumed as-is. CryptoPro CSP's CEK_ENC, after
 * ECB-decrypt, is already little-endian (the same orientation that
 * `priv_encode_gost` writes after its BE→LE flip), so no further byte
 * reversal is needed.
 */
static int build_gost_pkcs8(const unsigned char *raw, int raw_len,
                            int algo_nid,
                            const ASN1_OBJECT *curve_obj,
                            const ASN1_OBJECT *digest_obj,
                            unsigned char **out_der)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_STRING *params = NULL;
    ASN1_OBJECT *algobj = NULL;
    CPPrivateKeyParameters *pkparams = NULL;
    unsigned char *params_der = NULL;
    int params_len = 0;
    unsigned char *penc = NULL;
    int der_len = -1;

    if (out_der == NULL || raw == NULL || curve_obj == NULL
        || digest_obj == NULL)
        return -1;
    *out_der = NULL;

    /* Build SEQUENCE { curve OID, digest OID } DER via the existing
     * CPPrivateKeyParameters schema (mirror of the GOST AlgId params). */
    pkparams = CPPrivateKeyParameters_new();
    if (pkparams == NULL)
        goto done;
    ASN1_OBJECT_free(pkparams->curve);
    ASN1_OBJECT_free(pkparams->digest);
    pkparams->curve  = OBJ_dup(curve_obj);
    pkparams->digest = OBJ_dup(digest_obj);
    if (pkparams->curve == NULL || pkparams->digest == NULL)
        goto done;

    params_len = i2d_CPPrivateKeyParameters(pkparams, &params_der);
    if (params_len < 0)
        goto done;

    params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (params == NULL)
        goto done;
    if (!ASN1_STRING_set(params, params_der, params_len))
        goto done;

    algobj = OBJ_dup(OBJ_nid2obj(algo_nid));
    if (algobj == NULL)
        goto done;

    penc = OPENSSL_malloc((size_t)raw_len);
    if (penc == NULL)
        goto done;
    memcpy(penc, raw, (size_t)raw_len);

    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (p8 == NULL)
        goto done;

    /* Hands ownership of algobj, params, penc to p8. */
    if (!PKCS8_pkey_set0(p8, algobj, /*version*/ 0, V_ASN1_SEQUENCE,
                         params, penc, raw_len)) {
        /* Set0 failed — we still own everything. */
        goto done;
    }
    /* Ownership transferred — null out so the cleanup path skips them. */
    algobj = NULL;
    params = NULL;
    penc = NULL;

    der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, out_der);
    if (der_len < 0) {
        OPENSSL_free(*out_der);
        *out_der = NULL;
    }

done:
    OPENSSL_free(params_der);
    CPPrivateKeyParameters_free(pkparams);
    ASN1_STRING_free(params);
    ASN1_OBJECT_free(algobj);
    OPENSSL_free(penc);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return der_len;
}

/* ------------------------------------------------------------------
 * Provider cipher dispatch — `cryptopro-keybag-unwrap` (decrypt-only).
 *
 * Init takes K (32 B = the PBE-derived KEK from `legacy_pbe_kdf`) and
 * IV (8 B = the PBE salt's first 8 bytes). Update takes the encrypted
 * keybag bagValue (variable length), runs the 4-stage pipeline (CFB
 * decrypt → CPBlob walk → KDF + ECB unwrap → PKCS#8 synth), and
 * writes the recovered PKCS#8 PrivateKeyInfo DER to `out`. Final is a
 * no-op.
 *
 * Designed to be called by `EVP_PBE_CipherInit_ex` upstream — the
 * libcrypto PBE handler `cryptopro_keybag_keygen` (15a-6) derives K
 * from the password+salt+iters via `legacy_pbe_kdf`, then calls this
 * cipher's DECRYPT_INIT to load K + IV, after which `EVP_DecryptUpdate`
 * runs the unwrap in one call.
 * ------------------------------------------------------------------*/

typedef struct cryptopro_keybag_unwrap_ctx_st {
    void *provctx;
    unsigned char K[32];
    unsigned char iv[8];
    int has_key;
    int has_iv;
} CRYPTOPRO_KEYBAG_UNWRAP_CTX;

static OSSL_FUNC_cipher_newctx_fn          cryptopro_keybag_unwrap_newctx;
static OSSL_FUNC_cipher_freectx_fn         cryptopro_keybag_unwrap_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn    cryptopro_keybag_unwrap_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn    cryptopro_keybag_unwrap_decrypt_init;
static OSSL_FUNC_cipher_update_fn          cryptopro_keybag_unwrap_update;
static OSSL_FUNC_cipher_final_fn           cryptopro_keybag_unwrap_final;
static OSSL_FUNC_cipher_get_params_fn      cryptopro_keybag_unwrap_get_params;
static OSSL_FUNC_cipher_gettable_params_fn cryptopro_keybag_unwrap_gettable_params;
static OSSL_FUNC_cipher_get_ctx_params_fn  cryptopro_keybag_unwrap_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn
    cryptopro_keybag_unwrap_gettable_ctx_params;

static void *cryptopro_keybag_unwrap_newctx(void *provctx)
{
    CRYPTOPRO_KEYBAG_UNWRAP_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void cryptopro_keybag_unwrap_freectx(void *vctx)
{
    CRYPTOPRO_KEYBAG_UNWRAP_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    OPENSSL_cleanse(ctx->K, sizeof(ctx->K));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    OPENSSL_free(ctx);
}

static int cryptopro_keybag_unwrap_encrypt_init(void *vctx,
        const unsigned char *key, size_t keylen,
        const unsigned char *iv,  size_t ivlen,
        const OSSL_PARAM params[])
{
    /* Decrypt-only — RFC 9337 / RFC 9548 (Kuznyechik / Magma CTR-ACPKM
     * + Streebog HMAC, ratified 2015+) supersedes this 2009-era
     * proprietary GOST 28147-89-based keybag PBE on strength,
     * standardisation, and maintenance; emitting it from the engine
     * adds no value over the stock RFC 9337 path. Refuse encrypt
     * init to make the constraint explicit. */
    (void)vctx; (void)key; (void)keylen; (void)iv; (void)ivlen; (void)params;
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    return 0;
}

static int cryptopro_keybag_unwrap_decrypt_init(void *vctx,
        const unsigned char *key, size_t keylen,
        const unsigned char *iv,  size_t ivlen,
        const OSSL_PARAM params[])
{
    CRYPTOPRO_KEYBAG_UNWRAP_CTX *ctx = vctx;

    (void)params;
    if (ctx == NULL)
        return 0;

    if (key != NULL) {
        if (keylen != sizeof(ctx->K))
            return 0;
        memcpy(ctx->K, key, sizeof(ctx->K));
        ctx->has_key = 1;
    }
    if (iv != NULL) {
        if (ivlen != sizeof(ctx->iv))
            return 0;
        memcpy(ctx->iv, iv, sizeof(ctx->iv));
        ctx->has_iv = 1;
    }
    return 1;
}

/* Run the 4-stage unwrap pipeline. Single-call: the entire encrypted
 * bagValue arrives in one Update; output PKCS#8 DER is written to
 * `out`; *outl set to DER length. Final is a no-op. */
static int cryptopro_keybag_unwrap_update(void *vctx,
        unsigned char *out, size_t *outl, size_t outsize,
        const unsigned char *in, size_t inl)
{
    CRYPTOPRO_KEYBAG_UNWRAP_CTX *ctx = vctx;
    unsigned char *plain = NULL;
    CPBlob *cpb = NULL;
    CPExportBlob *eb = NULL;
    const unsigned char *eb_p;
    int payload_len;
    const unsigned char *payload;
    int is_512;
    int algo_nid;
    int raw_len;
    unsigned char Ke[32];
    unsigned char raw_key[64];
    unsigned char *pkcs8_der = NULL;
    int pkcs8_len = -1;
    int ret = 0;
    static const unsigned char kdf_label[4] = { 0x26, 0xbd, 0xb8, 0x78 };

    if (ctx == NULL || out == NULL || outl == NULL || in == NULL || inl == 0
        || !ctx->has_key || !ctx->has_iv) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* (i) CFB-decrypt under K, IV=salt[:8]. */
    plain = OPENSSL_malloc(inl);
    if (plain == NULL)
        goto done;
    if (!cryptopro_cfb_decrypt(ctx->K, ctx->iv, in, plain, inl))
        goto done;

    /* (ii) Walk CPBlob; pull out the 16-byte-headered payload. */
    {
        const unsigned char *p = plain;
        cpb = d2i_CPBlob(NULL, &p, (long)inl);
    }
    if (cpb == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto done;
    }
    payload_len = ASN1_STRING_length(cpb->value);
    payload     = ASN1_STRING_get0_data(cpb->value);
    if (payload_len < 16) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto done;
    }

    /* Magic at bytes [4:6] selects key length. */
    if (payload[4] == 0x46 && payload[5] == 0xAA) {
        is_512 = 0;
        algo_nid = NID_id_GostR3410_2012_256;
        raw_len = 32;
    } else if (payload[4] == 0x42 && payload[5] == 0xAA) {
        is_512 = 1;
        algo_nid = NID_id_GostR3410_2012_512;
        raw_len = 64;
    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto done;
    }

    /* (iii) Walk CPExportBlob from payload[16:]. */
    eb_p = payload + 16;
    eb = d2i_CPExportBlob(NULL, &eb_p, payload_len - 16);
    if (eb == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto done;
    }

    /* (iv) Ke = KDF_GOSTR3411_2012_256(K, label=0x26bdb878, ukm). */
    {
        const unsigned char *ukm = ASN1_STRING_get0_data(eb->value->ukm);
        size_t ukm_len = (size_t)ASN1_STRING_length(eb->value->ukm);
        if (!kdf_gostr3411_2012_256(ctx->K, kdf_label, sizeof(kdf_label),
                                    ukm, ukm_len, Ke))
            goto done;
    }

    /* (v) ECB-decrypt the wrapped CEK under Ke. 256-bit case is one
     * 32-byte block of raw key; 512-bit case is 64 bytes (two halves
     * but the same Ke applies — gost_dec runs across all blocks). */
    {
        int cek_len = ASN1_STRING_length(eb->value->cek->enc);
        const unsigned char *cek_enc = ASN1_STRING_get0_data(eb->value->cek->enc);
        if (cek_len != raw_len) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            goto done;
        }
        if (!cryptopro_ecb_decrypt(Ke, cek_enc, raw_key, (size_t)raw_len))
            goto done;
    }

    /* (vi) Synthesize PKCS#8 PrivateKeyInfo. */
    {
        ASN1_OBJECT *curve_obj  = eb->value->oids->privateKeyAlgorithm->params->curve;
        ASN1_OBJECT *digest_obj = eb->value->oids->privateKeyAlgorithm->params->digest;
        pkcs8_len = build_gost_pkcs8(raw_key, raw_len, algo_nid,
                                     curve_obj, digest_obj, &pkcs8_der);
    }
    if (pkcs8_len < 0)
        goto done;

    /* (vii) Hand the DER back to the caller. */
    if ((size_t)pkcs8_len > outsize) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        goto done;
    }
    memcpy(out, pkcs8_der, (size_t)pkcs8_len);
    *outl = (size_t)pkcs8_len;
    ret = 1;

    (void)is_512;   /* derived from magic, used only for raw_len/algo_nid */

done:
    if (plain != NULL) {
        OPENSSL_cleanse(plain, inl);
        OPENSSL_free(plain);
    }
    OPENSSL_cleanse(Ke, sizeof(Ke));
    OPENSSL_cleanse(raw_key, sizeof(raw_key));
    if (pkcs8_der != NULL) {
        OPENSSL_cleanse(pkcs8_der, (size_t)(pkcs8_len > 0 ? pkcs8_len : 0));
        OPENSSL_free(pkcs8_der);
    }
    CPBlob_free(cpb);
    CPExportBlob_free(eb);
    return ret;
}

static int cryptopro_keybag_unwrap_final(void *vctx,
        unsigned char *out, size_t *outl, size_t outsize)
{
    /* The whole transform happens in update() — final emits no extra
     * bytes. CUSTOM_CIPHER-style: caller is expected to pass the
     * complete bagValue ciphertext in a single Update call. */
    (void)vctx; (void)out; (void)outsize;
    if (outl != NULL)
        *outl = 0;
    return 1;
}

static const OSSL_PARAM cryptopro_keybag_unwrap_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN,      NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN,     NULL),
    OSSL_PARAM_uint  (OSSL_CIPHER_PARAM_MODE,       NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cryptopro_keybag_unwrap_gettable_params(void *provctx)
{
    (void)provctx;
    return cryptopro_keybag_unwrap_known_gettable_params;
}

static int cryptopro_keybag_unwrap_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL
        && !OSSL_PARAM_set_uint(p, EVP_CIPH_CFB_MODE))
        return 0;
    return 1;
}

static const OSSL_PARAM cryptopro_keybag_unwrap_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN,  NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *cryptopro_keybag_unwrap_gettable_ctx_params(
        void *vctx, void *provctx)
{
    (void)vctx; (void)provctx;
    return cryptopro_keybag_unwrap_known_gettable_ctx_params;
}

static int cryptopro_keybag_unwrap_get_ctx_params(void *vctx,
                                                  OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)vctx;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, 32))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, 8))
        return 0;
    return 1;
}

const OSSL_DISPATCH cryptopro_keybag_unwrap_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void))cryptopro_keybag_unwrap_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,
      (void (*)(void))cryptopro_keybag_unwrap_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,
      (void (*)(void))cryptopro_keybag_unwrap_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,
      (void (*)(void))cryptopro_keybag_unwrap_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,
      (void (*)(void))cryptopro_keybag_unwrap_update },
    { OSSL_FUNC_CIPHER_FINAL,
      (void (*)(void))cryptopro_keybag_unwrap_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
      (void (*)(void))cryptopro_keybag_unwrap_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
      (void (*)(void))cryptopro_keybag_unwrap_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))cryptopro_keybag_unwrap_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))cryptopro_keybag_unwrap_gettable_ctx_params },
    { 0, NULL },
};
