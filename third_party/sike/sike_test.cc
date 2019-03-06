/* Copyright (c) 2018, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdint.h>

#include <gtest/gtest.h>

#include "../../crypto/test/abi_test.h"
#include "sike.h"
#include "fpx.h"

TEST(SIKE, RoundTrip) {
    uint8_t sk[SIKEp503_PRV_BYTESZ] = {0};
    uint8_t pk[SIKEp503_PUB_BYTESZ] = {0};
    uint8_t ct[SIKEp503_CT_BYTESZ] = {0};
    uint8_t ss_enc[SIKEp503_SS_BYTESZ] = {0};
    uint8_t ss_dec[SIKEp503_SS_BYTESZ] = {0};

    EXPECT_EQ(SIKE_keypair(sk, pk), 1);
    SIKE_encaps(ss_enc, ct, pk);
    SIKE_decaps(ss_dec, ct, pk, sk);

    EXPECT_EQ(memcmp(ss_enc, ss_dec, SIKEp503_SS_BYTESZ), 0);
}

TEST(SIKE, Decapsulation) {
    const uint8_t sk[SIKEp503_PRV_BYTESZ] = {
        0xDB, 0xAF, 0x2C, 0x89, 0xCA, 0x5A, 0xD4, 0x9D, 0x4F, 0x13,
        0x40, 0xDF, 0x2D, 0xB1, 0x5F, 0x4C, 0x91, 0xA7, 0x1F, 0x0B,
        0x29, 0x15, 0x01, 0x59, 0xBC, 0x5F, 0x0B, 0x4A, 0x03, 0x27,
        0x6F, 0x18};

    const uint8_t pk[SIKEp503_PUB_BYTESZ] = {
        0x07, 0xAA, 0x51, 0x45, 0x3E, 0x1F, 0x53, 0x2A, 0x0A, 0x05,
        0x46, 0xF6, 0x54, 0x7F, 0x5D, 0x56, 0xD6, 0x76, 0xD3, 0xEA,
        0x4B, 0x6B, 0x01, 0x9B, 0x11, 0x72, 0x6F, 0x75, 0xEA, 0x34,
        0x3C, 0x28, 0x2C, 0x36, 0xFD, 0x77, 0xDA, 0xBE, 0xB6, 0x20,
        0x18, 0xC1, 0x93, 0x98, 0x18, 0x86, 0x30, 0x2F, 0x2E, 0xD2,
        0x00, 0x61, 0xFF, 0xAE, 0x78, 0xAE, 0xFB, 0x6F, 0x32, 0xAC,
        0x06, 0xBF, 0x35, 0xF6, 0xF7, 0x5B, 0x98, 0x26, 0x95, 0xC2,
        0xD8, 0xD6, 0x1C, 0x0E, 0x47, 0xDA, 0x76, 0xCE, 0xB5, 0xF1,
        0x19, 0xCC, 0x01, 0xE1, 0x17, 0xA9, 0x62, 0xF7, 0x82, 0x6C,
        0x25, 0x51, 0x25, 0xAE, 0xFE, 0xE3, 0xE2, 0xE1, 0x35, 0xAE,
        0x2E, 0x8F, 0x38, 0xE0, 0x7C, 0x74, 0x3C, 0x1D, 0x39, 0x91,
        0x1B, 0xC7, 0x9F, 0x8E, 0x33, 0x4E, 0x84, 0x19, 0xB8, 0xD9,
        0xC2, 0x71, 0x35, 0x02, 0x47, 0x3E, 0x79, 0xEF, 0x47, 0xE1,
        0xD8, 0x21, 0x96, 0x1F, 0x11, 0x59, 0x39, 0x34, 0x76, 0xEF,
        0x3E, 0xB7, 0x4E, 0xFB, 0x7C, 0x55, 0xA1, 0x85, 0xAA, 0xAB,
        0xAD, 0xF0, 0x09, 0xCB, 0xD1, 0xE3, 0x7C, 0x4F, 0x5D, 0x2D,
        0xE1, 0x13, 0xF0, 0x71, 0xD9, 0xE5, 0xF6, 0xAF, 0x7F, 0xC1,
        0x27, 0x95, 0x8D, 0x52, 0xD5, 0x96, 0x42, 0x38, 0x41, 0xF7,
        0x24, 0x3F, 0x3A, 0xB5, 0x7E, 0x11, 0xE4, 0xF9, 0x33, 0xEE,
        0x4D, 0xBE, 0x74, 0x48, 0xF9, 0x98, 0x04, 0x01, 0x16, 0xEB,
        0xA9, 0x0D, 0x61, 0xC6, 0xFD, 0x4C, 0xCF, 0x98, 0x84, 0x4A,
        0x94, 0xAC, 0x69, 0x2C, 0x02, 0x8B, 0xE3, 0xD1, 0x41, 0x0D,
        0xF2, 0x2D, 0x46, 0x1F, 0x57, 0x1C, 0x77, 0x86, 0x18, 0xE3,
        0x63, 0xDE, 0xF3, 0xE3, 0x02, 0x30, 0x54, 0x73, 0xAE, 0xC2,
        0x32, 0xA2, 0xCE, 0xEB, 0xCF, 0x81, 0x46, 0x54, 0x5C, 0xF4,
        0x5D, 0x2A, 0x03, 0x5D, 0x9C, 0xAE, 0xE0, 0x60, 0x03, 0x80,
        0x11, 0x30, 0xA5, 0xAA, 0xD1, 0x75, 0x67, 0xE0, 0x1C, 0x2B,
        0x6B, 0x5D, 0x83, 0xDE, 0x92, 0x9B, 0x0E, 0xD7, 0x11, 0x0F,
        0x00, 0xC4, 0x59, 0xE4, 0x81, 0x04, 0x3B, 0xEE, 0x5C, 0x04,
        0xD1, 0x0E, 0xD0, 0x67, 0xF5, 0xCC, 0xAA, 0x72, 0x73, 0xEA,
        0xC4, 0x76, 0x99, 0x3B, 0x4C, 0x90, 0x2F, 0xCB, 0xD8, 0x0A,
        0x5B, 0xEC, 0x0E, 0x0E, 0x1F, 0x59, 0xEA, 0x14, 0x8D, 0x34,
        0x53, 0x65, 0x4C, 0x1A, 0x59, 0xA8, 0x95, 0x66, 0x60, 0xBB,
        0xC4, 0xCC, 0x32, 0xA9, 0x8D, 0x2A, 0xAA, 0x14, 0x6F, 0x0F,
        0x81, 0x4D, 0x32, 0x02, 0xFD, 0x33, 0x58, 0x42, 0xCF, 0xF3,
        0x67, 0xD0, 0x9F, 0x0B, 0xB1, 0xCC, 0x18, 0xA5, 0xC4, 0x19,
        0xB6, 0x00, 0xED, 0xFA, 0x32, 0x1A, 0x5F, 0x67, 0xC8, 0xC3,
        0xEB, 0x0D, 0xB5, 0x9A, 0x36, 0x47, 0x82, 0x00};

    const uint8_t ct_exp[SIKEp503_CT_BYTESZ] = {
        0xE6, 0xB7, 0xE5, 0x7B, 0xA9, 0x19, 0xD1, 0x2C, 0xB8, 0x5C,
        0x7B, 0x66, 0x74, 0xB0, 0x71, 0xA1, 0xFF, 0x71, 0x7F, 0x4B,
        0xB5, 0xA6, 0xAF, 0x48, 0x32, 0x52, 0xD5, 0x82, 0xEE, 0x8A,
        0xBB, 0x08, 0x1E, 0xF6, 0xAC, 0x91, 0xA2, 0xCB, 0x6B, 0x6A,
        0x09, 0x2B, 0xD9, 0xC6, 0x27, 0xD6, 0x3A, 0x6B, 0x8D, 0xFC,
        0xB8, 0x90, 0x8F, 0x72, 0xB3, 0xFA, 0x7D, 0x34, 0x7A, 0xC4,
        0x7E, 0xE3, 0x30, 0xC5, 0xA0, 0xFE, 0x3D, 0x43, 0x14, 0x4E,
        0x3A, 0x14, 0x76, 0x3E, 0xFB, 0xDF, 0xE3, 0xA8, 0xE3, 0x5E,
        0x38, 0xF2, 0xE0, 0x39, 0x67, 0x60, 0xFD, 0xFB, 0xB4, 0x19,
        0xCD, 0xE1, 0x93, 0xA2, 0x06, 0xCC, 0x65, 0xCD, 0x6E, 0xC8,
        0xB4, 0x5E, 0x41, 0x4B, 0x6C, 0xA5, 0xF4, 0xE4, 0x9D, 0x52,
        0x8C, 0x25, 0x60, 0xDD, 0x3D, 0xA9, 0x7F, 0xF2, 0x88, 0xC1,
        0x0C, 0xEE, 0x97, 0xE0, 0xE7, 0x3B, 0xB7, 0xD3, 0x6F, 0x28,
        0x79, 0x2F, 0x50, 0xB2, 0x4F, 0x74, 0x3A, 0x0C, 0x88, 0x27,
        0x98, 0x3A, 0x27, 0xD3, 0x26, 0x83, 0x59, 0x49, 0x81, 0x5B,
        0x0D, 0xA7, 0x0C, 0x4F, 0xEF, 0xFB, 0x1E, 0xAF, 0xE9, 0xD2,
        0x1C, 0x10, 0x25, 0xEC, 0x9E, 0xFA, 0x57, 0x36, 0xAA, 0x3F,
        0xC1, 0xA3, 0x2C, 0xE9, 0xB5, 0xC9, 0xED, 0x72, 0x51, 0x4C,
        0x02, 0xB4, 0x7B, 0xB3, 0xED, 0x9F, 0x45, 0x03, 0x34, 0xAC,
        0x9A, 0x9E, 0x62, 0x5F, 0x82, 0x7A, 0x77, 0x34, 0xF9, 0x21,
        0x94, 0xD2, 0x38, 0x3D, 0x05, 0xF0, 0x8A, 0x60, 0x1C, 0xB7,
        0x1D, 0xF5, 0xB7, 0x53, 0x77, 0xD3, 0x9D, 0x3D, 0x70, 0x6A,
        0xCB, 0x18, 0x20, 0x6B, 0x29, 0x17, 0x3A, 0x6D, 0xA1, 0xB2,
        0x64, 0xDB, 0x6C, 0xE6, 0x1A, 0x95, 0xA7, 0xF4, 0x1A, 0x78,
        0x1D, 0xA2, 0x40, 0x15, 0x41, 0x59, 0xDD, 0xEE, 0x23, 0x57,
        0xCE, 0x36, 0x0D, 0x55, 0xBD, 0xB8, 0xFD, 0x0F, 0x35, 0xBD,
        0x5B, 0x92, 0xD6, 0x1C, 0x84, 0x8C, 0x32, 0x64, 0xA6, 0x5C,
        0x45, 0x18, 0x07, 0x6B, 0xF9, 0xA9, 0x43, 0x9A, 0x83, 0xCD,
        0xB5, 0xB3, 0xD9, 0x17, 0x99, 0x2C, 0x2A, 0x8B, 0xE0, 0x8E,
        0xAF, 0xA6, 0x4C, 0x95, 0xBB, 0x70, 0x60, 0x1A, 0x3A, 0x97,
        0xAA, 0x2F, 0x3D, 0x22, 0x83, 0xB7, 0x4F, 0x59, 0xED, 0x3F,
        0x4E, 0xF4, 0x19, 0xC6, 0x25, 0x0B, 0x0A, 0x5E, 0x21, 0xB9,
        0x91, 0xB8, 0x19, 0x84, 0x48, 0x78, 0xCE, 0x27, 0xBF, 0x41,
        0x89, 0xF6, 0x30, 0xFD, 0x6B, 0xD9, 0xB8, 0x1D, 0x72, 0x8A,
        0x56, 0xCC, 0x2F, 0x82, 0xE4, 0x46, 0x4D, 0x75, 0xD8, 0x92,
        0xE6, 0x9C, 0xCC, 0xD2, 0xCD, 0x35, 0xE4, 0xFC, 0x2A, 0x85,
        0x6B, 0xA9, 0xB2, 0x27, 0xC9, 0xA1, 0xFF, 0xB3, 0x96, 0x3E,
        0x59, 0xF6, 0x4C, 0x66, 0x56, 0x2E, 0xF5, 0x1B, 0x97, 0x32,
        0xB0, 0x71, 0x5A, 0x9C, 0x50, 0x4B, 0x6F, 0xC4, 0xCA, 0x94,
        0x75, 0x37, 0x46, 0x10, 0x12, 0x2F, 0x4F, 0xA3, 0x82, 0xCD,
        0xBD, 0x7C};

    const uint8_t ss_exp[SIKEp503_SS_BYTESZ] = {
        0x74, 0x3D, 0x25, 0x36, 0x00, 0x24, 0x63, 0x1A, 0x39, 0x1A,
        0xB4, 0xAD, 0x01, 0x17, 0x78, 0xE9};

    uint8_t ss_dec[SIKEp503_SS_BYTESZ] = {0};
    SIKE_decaps(ss_dec, ct_exp, pk, sk);
    EXPECT_EQ(memcmp(ss_dec, ss_exp, sizeof(ss_exp)), 0);
}

// SIKE_encaps and SIKE_keypair doesn't return zeros.
TEST(SIKE, NonZero) {
    uint8_t sk[SIKEp503_PRV_BYTESZ] = {0};
    uint8_t pk[SIKEp503_PUB_BYTESZ] = {0};
    uint8_t ct[SIKEp503_CT_BYTESZ] = {0};
    uint8_t ss[SIKEp503_SS_BYTESZ] = {0};

    // Check secret and public key returned by SIKE_keypair
    EXPECT_EQ(SIKE_keypair(sk, pk), 1);
    uint8_t tmp = 0;
    for (size_t i=0; i<sizeof(sk); i++) tmp|=sk[i];
    EXPECT_NE(tmp, 0);

    tmp = 0;
    for (size_t i=0; i<sizeof(pk); i++) tmp|=pk[i];
    EXPECT_NE(tmp, 0);

    // Check shared secret and ciphertext returned by SIKE_encaps
    SIKE_encaps(ss, ct, pk);
    tmp = 0;
    for (size_t i=0; i<sizeof(ct); i++) tmp|=ct[i];
    EXPECT_NE(tmp, 0);

    tmp = 0;
    for (size_t i=0; i<sizeof(ss); i++) tmp|=ss[i];
    EXPECT_NE(tmp, 0);
}

TEST(SIKE, Negative) {
    uint8_t sk[SIKEp503_PRV_BYTESZ] = {0};
    uint8_t pk[SIKEp503_PUB_BYTESZ] = {0};
    uint8_t ct[SIKEp503_CT_BYTESZ] = {0};
    uint8_t ss_enc[SIKEp503_SS_BYTESZ] = {0};
    uint8_t ss_dec[SIKEp503_SS_BYTESZ] = {0};

    EXPECT_EQ(SIKE_keypair(sk, pk), 1);
    SIKE_encaps(ss_enc, ct, pk);

    // Change cipertext
    uint8_t ct_tmp[SIKEp503_CT_BYTESZ] = {0};
    memcpy(ct_tmp, ct, sizeof(ct));
    ct_tmp[0] = ~ct_tmp[0];
    SIKE_decaps(ss_dec, ct_tmp, pk, sk);
    EXPECT_NE(memcmp(ss_enc, ss_dec, SIKEp503_SS_BYTESZ), 0);

    // Change secret key
    uint8_t sk_tmp[SIKEp503_PRV_BYTESZ] = {0};
    memcpy(sk_tmp, sk, sizeof(sk));
    sk_tmp[0] = ~sk_tmp[0];
    SIKE_decaps(ss_dec, ct, pk, sk_tmp);
    EXPECT_NE(memcmp(ss_enc, ss_dec, SIKEp503_SS_BYTESZ), 0);

    // Change public key
    uint8_t pk_tmp[SIKEp503_PUB_BYTESZ] = {0};
    memcpy(pk_tmp, pk, sizeof(pk));
    pk_tmp[0] = ~pk_tmp[0];
    SIKE_decaps(ss_dec, ct, pk_tmp, sk);
    EXPECT_NE(memcmp(ss_enc, ss_dec, SIKEp503_SS_BYTESZ), 0);
}

#if defined(SUPPORTS_ABI_TEST) && defined(OPENSSL_X86_64)
TEST(SIKE, ABI) {
  felm_t a, b, c;
  dfelm_t d;
  CHECK_ABI(sike_fpadd, a, b, c);
  CHECK_ABI(sike_fpsub, a, b, c);
  CHECK_ABI(sike_mpmul, a, b, d);
  CHECK_ABI(sike_fprdc, d, a);
  CHECK_ABI(sike_mpadd_asm, a, b, c);
  CHECK_ABI(sike_mpsubx2_asm, a, b, c);
}
#endif  // SUPPORTS_ABI_TEST && X86_64
