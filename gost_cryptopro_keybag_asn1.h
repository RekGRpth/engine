/**********************************************************************
 *               gost_cryptopro_keybag_asn1.h                          *
 *                                                                    *
 *  ASN.1 schemas for the CryptoPro proprietary PKCS#12 shrouded-     *
 *  keybag PBE algorithm (OID 1.2.840.113549.1.12.1.80).              *
 *                                                                    *
 *  Schemas are file-local — never appear on the wire as a public     *
 *  type — and are used only inside the cipher dispatch pipeline      *
 *  (`gost_cryptopro_keybag.c`) to walk the PBE params and the inner  *
 *  CPBlob / CPExportBlob* tuple.                                     *
 *                                                                    *
 *  Field names mirror gostpfx.py L213-313 verbatim for cross-        *
 *  reference with the Python reference decoder. Origin in vendor     *
 *  pyderasn schemas (li0ard, Apache-2.0).                            *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#ifndef GOST_CRYPTOPRO_KEYBAG_ASN1_H
#define GOST_CRYPTOPRO_KEYBAG_ASN1_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* CPParamsValue ::= SEQUENCE { salt OCTET STRING, iters INTEGER } */
typedef struct CPParamsValue_st {
    ASN1_OCTET_STRING *salt;
    ASN1_INTEGER      *iters;
} CPParamsValue;

DECLARE_ASN1_FUNCTIONS(CPParamsValue)

/* CPParams ::= SEQUENCE { algo OBJECT IDENTIFIER, params CPParamsValue } —
 * the AlgorithmIdentifier specialised for the CryptoPro keybag PBE. */
typedef struct CPParams_st {
    ASN1_OBJECT   *algo;
    CPParamsValue *params;
} CPParams;

DECLARE_ASN1_FUNCTIONS(CPParams)

/* CPBlob ::= SEQUENCE {
 *     version  INTEGER,
 *     notused  ANY,
 *     value    OCTET STRING,
 *     notused2 ANY OPTIONAL
 * }
 * Plaintext after stage-2 CFB decryption. `value` carries the 16-byte
 * payload header (`46 AA …` for 256-bit, `42 AA …` for 512-bit) plus
 * the DER of CPExportBlob. `notused`/`notused2` are CryptoPro framing
 * the decoder doesn't interpret. */
typedef struct CPBlob_st {
    ASN1_INTEGER      *version;
    ASN1_TYPE         *notused;
    ASN1_OCTET_STRING *value;
    ASN1_TYPE         *notused2;   /* OPTIONAL */
} CPBlob;

DECLARE_ASN1_FUNCTIONS(CPBlob)

/* CPExportBlobCek ::= SEQUENCE { enc OCTET STRING, mac OCTET STRING } —
 * the wrapped CEK. */
typedef struct CPExportBlobCek_st {
    ASN1_OCTET_STRING *enc;
    ASN1_OCTET_STRING *mac;
} CPExportBlobCek;

DECLARE_ASN1_FUNCTIONS(CPExportBlobCek)

/* CPPrivateKeyParameters ::= SEQUENCE {
 *     curve  OBJECT IDENTIFIER,
 *     digest OBJECT IDENTIFIER
 * } — the GOST key's algorithm parameters. */
typedef struct CPPrivateKeyParameters_st {
    ASN1_OBJECT *curve;
    ASN1_OBJECT *digest;
} CPPrivateKeyParameters;

DECLARE_ASN1_FUNCTIONS(CPPrivateKeyParameters)

/* CPPrivateKeyAlgorithm ::= SEQUENCE {
 *     algorithm OBJECT IDENTIFIER,
 *     params    CPPrivateKeyParameters
 * } — the inner private-key algorithm identifier. */
typedef struct CPPrivateKeyAlgorithm_st {
    ASN1_OBJECT            *algorithm;
    CPPrivateKeyParameters *params;
} CPPrivateKeyAlgorithm;

DECLARE_ASN1_FUNCTIONS(CPPrivateKeyAlgorithm)

/* CPPrivateKeyInfo ::= SEQUENCE {
 *     version             BIT STRING,
 *     privateKeyAlgorithm CPPrivateKeyAlgorithm
 * }
 * Note `version` is BIT STRING here (matches pyderasn schemas; pygost's
 * PKCS#8 uses INTEGER). The container is implicitly [0]-tagged inside
 * CPExportBlob2. */
typedef struct CPPrivateKeyInfo_st {
    ASN1_BIT_STRING       *version;
    CPPrivateKeyAlgorithm *privateKeyAlgorithm;
} CPPrivateKeyInfo;

DECLARE_ASN1_FUNCTIONS(CPPrivateKeyInfo)

/* CPExportBlob2 ::= SEQUENCE {
 *     ukm  OCTET STRING,
 *     cek  CPExportBlobCek,
 *     oids [0] IMPLICIT CPPrivateKeyInfo
 * } — the actual CryptoPro export tuple. */
typedef struct CPExportBlob2_st {
    ASN1_OCTET_STRING *ukm;
    CPExportBlobCek   *cek;
    CPPrivateKeyInfo  *oids;
} CPExportBlob2;

DECLARE_ASN1_FUNCTIONS(CPExportBlob2)

/* CPExportBlob ::= SEQUENCE {
 *     value   CPExportBlob2,
 *     notused OCTET STRING
 * } — outer wrapper of the export tuple. */
typedef struct CPExportBlob_st {
    CPExportBlob2     *value;
    ASN1_OCTET_STRING *notused;
} CPExportBlob;

DECLARE_ASN1_FUNCTIONS(CPExportBlob)

#endif /* GOST_CRYPTOPRO_KEYBAG_ASN1_H */
