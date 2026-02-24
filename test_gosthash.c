/**********************************************************************
 *            No OpenSSL libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************/
#include <stdio.h>
#include <string.h>

#include "gost89.h"
#include "gosthash.h"

static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}

int test(const gost_subst_block* subst_block, const byte* data, size_t data_len,
         const byte* expected_digest) {
    int r = 0;
    gost_hash_ctx ctx;
    byte digest[32];

    r = init_gost_hash_ctx(&ctx, subst_block);
    if (r != 1) {
        fprintf(stderr, "init_gost_hash_ctx failed");
        goto exit_return;
    }

    r = start_hash(&ctx);
    if (r != 1) {
        fprintf(stderr, "start_hash failed");
        goto exit_done_gost_hash_ctx;
    }

    r = hash_block(&ctx, data, data_len);
    if (r != 1) {
        fprintf(stderr, "hash_block failed");
        goto exit_done_gost_hash_ctx;
    }

    r = finish_hash(&ctx, digest);
    if (r != 1) {
        fprintf(stderr, "finish_hash failed");
        goto exit_done_gost_hash_ctx;
    }

    if (memcmp(digest, expected_digest, sizeof(digest))) {
        hexdump(stdout, "Data to digest", data, data_len);
        hexdump(stdout, "Calculated digest", digest, sizeof(digest));
        hexdump(stdout, "Expected digest", expected_digest, sizeof(digest));
        fprintf(stderr, "Digest does not match expected value\n");
        r = 0;
    }

exit_done_gost_hash_ctx:
    done_gost_hash_ctx(&ctx);

exit_return:
    return r;
}

void revert(byte* buffer, size_t len) {
    size_t i = 0;
    byte c;
    for (; i < len/2; ++i) {
        c = buffer[i];
        buffer[i] = buffer[len - i - 1];
        buffer[len - i - 1] = c;
    }
}

int main(void)
{
    int ret = 1;
    int r = 0;

    // https://www.rfc-editor.org/rfc/rfc5831.html#section-7.3.1
    byte rfc5831_7_3_1_m[] = {
        0x73, 0x65, 0x74, 0x79, 0x62, 0x20, 0x32, 0x33,
        0x3D, 0x68, 0x74, 0x67, 0x6E, 0x65, 0x6C, 0x20,
        0x2C, 0x65, 0x67, 0x61, 0x73, 0x73, 0x65, 0x6D,
        0x20, 0x73, 0x69, 0x20, 0x73, 0x69, 0x68, 0x54
    };

    byte rfc5831_7_3_1_h[] = {
        0xFA, 0xFF, 0x37, 0xA6, 0x15, 0xA8, 0x16, 0x69,
        0x1C, 0xFF, 0x3E, 0xF8, 0xB6, 0x8C, 0xA2, 0x47,
        0xE0, 0x95, 0x25, 0xF3, 0x9F, 0x81, 0x19, 0x83,
        0x2E, 0xB8, 0x19, 0x75, 0xD3, 0x66, 0xC4, 0xB1
    };

    // https://www.rfc-editor.org/rfc/rfc5831.html#section-7.3.2
    byte rfc5831_7_3_2_m[] = {
        0x73, 0x65, 0x74, 0x79, 0x62, 0x20, 0x30, 0x35,
        0x20, 0x3D, 0x20, 0x68, 0x74, 0x67, 0x6E, 0x65,
        0x6C, 0x20, 0x73, 0x61, 0x68, 0x20, 0x65, 0x67,
        0x61, 0x73, 0x73, 0x65, 0x6D, 0x20, 0x6C, 0x61,
        0x6E, 0x69, 0x67, 0x69, 0x72, 0x6F, 0x20, 0x65,
        0x68, 0x74, 0x20, 0x65, 0x73, 0x6F, 0x70, 0x70,
        0x75, 0x53
    };

    byte rfc5831_7_3_2_h[] = {
        0x08, 0x52, 0xF5, 0x62, 0x3B, 0x89, 0xDD, 0x57,
        0xAE, 0xB4, 0x78, 0x1F, 0xE5, 0x4D, 0xF1, 0x4E,
        0xEA, 0xFB, 0xC1, 0x35, 0x06, 0x13, 0x76, 0x3A,
        0x0D, 0x77, 0x0A, 0xA6, 0x57, 0xBA, 0x1A, 0x47
    };

    revert(rfc5831_7_3_1_m, sizeof(rfc5831_7_3_1_m));
    revert(rfc5831_7_3_1_h, sizeof(rfc5831_7_3_1_h));
    r = test(&GostR3411_94_TestParamSet, rfc5831_7_3_1_m, sizeof(rfc5831_7_3_1_m), rfc5831_7_3_1_h);
    if (r != 1) {
        goto exit_return;
    }

    revert(rfc5831_7_3_2_m, sizeof(rfc5831_7_3_2_m));
    revert(rfc5831_7_3_2_h, sizeof(rfc5831_7_3_2_h));
    r = test(&GostR3411_94_TestParamSet, rfc5831_7_3_2_m, sizeof(rfc5831_7_3_2_m), rfc5831_7_3_2_h);
    if (r != 1) {
        goto exit_return;
    }

    ret = 0;

exit_return:
    return ret;
}
