/**********************************************************************
 *               gost_cryptopro_keybag_asn1.c                          *
 *                                                                    *
 *  ASN1_SEQUENCE_* + IMPLEMENT_ASN1_FUNCTIONS for the 9 CryptoPro     *
 *  proprietary keybag types declared in `gost_cryptopro_keybag_asn1.h`.*
 *  These schemas are file-local — never exposed on the wire as a      *
 *  public type — and are consumed only by the cipher dispatch         *
 *  pipeline in `gost_cryptopro_keybag.c`.                             *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#include <openssl/asn1t.h>
#include "gost_cryptopro_keybag_asn1.h"

/* CPParamsValue ::= SEQUENCE { salt OCTET STRING, iters INTEGER } */
ASN1_SEQUENCE(CPParamsValue) = {
    ASN1_SIMPLE(CPParamsValue, salt,  ASN1_OCTET_STRING),
    ASN1_SIMPLE(CPParamsValue, iters, ASN1_INTEGER),
} ASN1_SEQUENCE_END(CPParamsValue)
IMPLEMENT_ASN1_FUNCTIONS(CPParamsValue)

/* CPParams ::= SEQUENCE { algo OBJECT IDENTIFIER, params CPParamsValue } */
ASN1_SEQUENCE(CPParams) = {
    ASN1_SIMPLE(CPParams, algo,   ASN1_OBJECT),
    ASN1_SIMPLE(CPParams, params, CPParamsValue),
} ASN1_SEQUENCE_END(CPParams)
IMPLEMENT_ASN1_FUNCTIONS(CPParams)

/* CPBlob ::= SEQUENCE { version, notused ANY, value OCTET STRING,
 *                       notused2 ANY OPTIONAL } */
ASN1_SEQUENCE(CPBlob) = {
    ASN1_SIMPLE(CPBlob, version,  ASN1_INTEGER),
    ASN1_SIMPLE(CPBlob, notused,  ASN1_ANY),
    ASN1_SIMPLE(CPBlob, value,    ASN1_OCTET_STRING),
    ASN1_OPT   (CPBlob, notused2, ASN1_ANY),
} ASN1_SEQUENCE_END(CPBlob)
IMPLEMENT_ASN1_FUNCTIONS(CPBlob)

/* CPExportBlobCek ::= SEQUENCE { enc OCTET STRING, mac OCTET STRING } */
ASN1_SEQUENCE(CPExportBlobCek) = {
    ASN1_SIMPLE(CPExportBlobCek, enc, ASN1_OCTET_STRING),
    ASN1_SIMPLE(CPExportBlobCek, mac, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(CPExportBlobCek)
IMPLEMENT_ASN1_FUNCTIONS(CPExportBlobCek)

/* CPPrivateKeyParameters ::= SEQUENCE { curve OID, digest OID } */
ASN1_SEQUENCE(CPPrivateKeyParameters) = {
    ASN1_SIMPLE(CPPrivateKeyParameters, curve,  ASN1_OBJECT),
    ASN1_SIMPLE(CPPrivateKeyParameters, digest, ASN1_OBJECT),
} ASN1_SEQUENCE_END(CPPrivateKeyParameters)
IMPLEMENT_ASN1_FUNCTIONS(CPPrivateKeyParameters)

/* CPPrivateKeyAlgorithm ::= SEQUENCE { algorithm OID,
 *                                      params CPPrivateKeyParameters } */
ASN1_SEQUENCE(CPPrivateKeyAlgorithm) = {
    ASN1_SIMPLE(CPPrivateKeyAlgorithm, algorithm, ASN1_OBJECT),
    ASN1_SIMPLE(CPPrivateKeyAlgorithm, params,    CPPrivateKeyParameters),
} ASN1_SEQUENCE_END(CPPrivateKeyAlgorithm)
IMPLEMENT_ASN1_FUNCTIONS(CPPrivateKeyAlgorithm)

/* CPPrivateKeyInfo ::= SEQUENCE {
 *     version             BIT STRING,
 *     privateKeyAlgorithm [0] IMPLICIT CPPrivateKeyAlgorithm
 * }
 * Wire-verified against CSP-emitted PFX (14g-final.pfx and
 * test-15a3probe.pfx 2026-05-04): the algorithm sub-structure carries
 * an `A0` (context-specific [0]) tag rather than `30` (universal
 * SEQUENCE). gostpfx.py declares this as a plain Sequence field, but
 * asn1crypto tolerates the actual `A0` because IMPLICIT [0] keeps the
 * primitive/constructed bit and the inner contents unchanged — only
 * the outermost tag differs. We need the IMPLICIT [0] in the C
 * template explicitly so libcrypto's `asn1_check_tlen` accepts the
 * tag at decode time. */
ASN1_SEQUENCE(CPPrivateKeyInfo) = {
    ASN1_SIMPLE(CPPrivateKeyInfo, version,             ASN1_BIT_STRING),
    ASN1_IMP   (CPPrivateKeyInfo, privateKeyAlgorithm, CPPrivateKeyAlgorithm, 0),
} ASN1_SEQUENCE_END(CPPrivateKeyInfo)
IMPLEMENT_ASN1_FUNCTIONS(CPPrivateKeyInfo)

/* CPExportBlob2 ::= SEQUENCE { ukm OCTET STRING, cek CPExportBlobCek,
 *                              oids [0] IMPLICIT CPPrivateKeyInfo } */
ASN1_SEQUENCE(CPExportBlob2) = {
    ASN1_SIMPLE(CPExportBlob2, ukm,  ASN1_OCTET_STRING),
    ASN1_SIMPLE(CPExportBlob2, cek,  CPExportBlobCek),
    ASN1_IMP   (CPExportBlob2, oids, CPPrivateKeyInfo, 0),
} ASN1_SEQUENCE_END(CPExportBlob2)
IMPLEMENT_ASN1_FUNCTIONS(CPExportBlob2)

/* CPExportBlob ::= SEQUENCE { value CPExportBlob2, notused OCTET STRING } */
ASN1_SEQUENCE(CPExportBlob) = {
    ASN1_SIMPLE(CPExportBlob, value,   CPExportBlob2),
    ASN1_SIMPLE(CPExportBlob, notused, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(CPExportBlob)
IMPLEMENT_ASN1_FUNCTIONS(CPExportBlob)
