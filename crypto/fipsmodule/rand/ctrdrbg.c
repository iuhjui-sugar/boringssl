/* Copyright (c) 2017, Google Inc.
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

#include <openssl/rand.h>

#include <openssl/type_check.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../../internal.h"
#include "../cipher/internal.h"


/* Section references in this file refer to SP 800-90Ar1:
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf */

/* See table 3. */
static const uint64_t kMaxReseedCount = UINT64_C(1) << 48;

#if defined(BORINGSSL_FIPS)

static const uint8_t kEntropy[48] =
    "BCM Known Answer Test DBRG Initial Entropy      ";
static const uint8_t kEntropy2[48] =
    "BCM Known Answer Test DBRG Reseed Entropy       ";
static const uint8_t kPersonalization[18] = "BCMPersonalization";
static const uint8_t kAD[16] = "BCM DRBG KAT AD ";
static const uint8_t kOutput[64] = {
    0x1d, 0x63, 0xdf, 0x05, 0x51, 0x49, 0x22, 0x46, 0xcd, 0x9b, 0xc5,
    0xbb, 0xf1, 0x5d, 0x44, 0xae, 0x13, 0x78, 0xb1, 0xe4, 0x7c, 0xf1,
    0x96, 0x33, 0x3d, 0x60, 0xb6, 0x29, 0xd4, 0xbb, 0x6b, 0x44, 0xf9,
    0xef, 0xd9, 0xf4, 0xa2, 0xba, 0x48, 0xea, 0x39, 0x75, 0x59, 0x32,
    0xf7, 0x31, 0x2c, 0x98, 0x14, 0x2b, 0x49, 0xdf, 0x02, 0xb6, 0x5d,
    0x71, 0x09, 0x50, 0xdb, 0x23, 0xdb, 0xe5, 0x22,
#if !defined(BORINGSSL_FIPS_BREAK_DRBG_HEALTH)
    0x95
#else
    0x00
#endif
};
static const uint8_t kReseedOutput[64] = {
    0x60, 0x42, 0xa2, 0x24, 0xe2, 0xa9, 0x49, 0x61, 0xad, 0xc2, 0x2d,
    0x1c, 0xae, 0xc2, 0xff, 0xe4, 0x6f, 0x2b, 0x0e, 0xa6, 0x38, 0x1e,
    0x46, 0xdf, 0x3a, 0x14, 0x02, 0x91, 0x21, 0x76, 0xa1, 0xe3, 0xb2,
    0xa5, 0x76, 0xe3, 0x43, 0x57, 0xe9, 0xfe, 0x09, 0x6e, 0x41, 0x51,
    0xb7, 0x4c, 0x1a, 0x19, 0xc8, 0x30, 0x2f, 0x0c, 0x1c, 0xf9, 0xcd,
    0xdc, 0xca, 0x3b, 0x5b, 0xea, 0x20, 0xd3, 0xd1,
#if !defined(BORINGSSL_FIPS_BREAK_DRBG_HEALTH)
    0xea
#else
    0x00
#endif
};

#endif  /* BORINGSSL_FIPS */

/* ctr_inc adds |n| to the last four bytes of |drbg->counter|, treated as a
 * big-endian number. */
static void ctr32_add(CTR_DRBG_STATE *drbg, uint32_t n) {
  drbg->counter.words[3] =
      CRYPTO_bswap4(CRYPTO_bswap4(drbg->counter.words[3]) + n);
}

static int CTR_DRBG_update(CTR_DRBG_STATE *drbg, const uint8_t *data,
                           size_t data_len) {
  /* Section 10.2.1.2. A value of |data_len| which less than
   * |CTR_DRBG_ENTROPY_LEN| is permitted and acts the same as right-padding
   * with zeros. This can save a copy. */
  if (data_len > CTR_DRBG_ENTROPY_LEN) {
    return 0;
  }

  uint8_t temp[CTR_DRBG_ENTROPY_LEN];
  for (size_t i = 0; i < CTR_DRBG_ENTROPY_LEN; i += AES_BLOCK_SIZE) {
    ctr32_add(drbg, 1);
    drbg->block(drbg->counter.bytes, temp + i, &drbg->ks);
  }

  for (size_t i = 0; i < data_len; i++) {
    temp[i] ^= data[i];
  }

  drbg->ctr = aes_ctr_set_key(&drbg->ks, NULL, &drbg->block, temp, 32);
  OPENSSL_memcpy(drbg->counter.bytes, temp + 32, 16);

  return 1;
}

static int CTR_DRBG_generate_internal(CTR_DRBG_STATE *drbg, uint8_t *out,
                                      size_t out_len,
                                      const uint8_t *additional_data,
                                      size_t additional_data_len) {
  /* See 9.3.1 */
  if (out_len > CTR_DRBG_MAX_GENERATE_LENGTH) {
    return 0;
  }

  /* See 10.2.1.5.1 */
  if (drbg->reseed_counter > kMaxReseedCount) {
    return 0;
  }

  if (additional_data_len != 0 &&
      !CTR_DRBG_update(drbg, additional_data, additional_data_len)) {
    return 0;
  }

  /* kChunkSize is used to interact better with the cache. Since the AES-CTR
   * code assumes that it's encrypting rather than just writing keystream, the
   * buffer has to be zeroed first. Without chunking, large reads would zero
   * the whole buffer, flushing the L1 cache, and then do another pass (missing
   * the cache every time) to “encrypt” it. The code can avoid this by
   * chunking. */
  static const size_t kChunkSize = 8 * 1024;

  while (out_len >= AES_BLOCK_SIZE) {
    size_t todo = kChunkSize;
    if (todo > out_len) {
      todo = out_len;
    }

    todo &= ~(AES_BLOCK_SIZE-1);
    const size_t num_blocks = todo / AES_BLOCK_SIZE;

    if (drbg->ctr) {
      OPENSSL_memset(out, 0, todo);
      ctr32_add(drbg, 1);
      drbg->ctr(out, out, num_blocks, &drbg->ks, drbg->counter.bytes);
      ctr32_add(drbg, num_blocks - 1);
    } else {
      for (size_t i = 0; i < todo; i += AES_BLOCK_SIZE) {
        ctr32_add(drbg, 1);
        drbg->block(drbg->counter.bytes, out + i, &drbg->ks);
      }
    }

    out += todo;
    out_len -= todo;
  }

  if (out_len > 0) {
    uint8_t block[AES_BLOCK_SIZE];
    ctr32_add(drbg, 1);
    drbg->block(drbg->counter.bytes, block, &drbg->ks);

    OPENSSL_memcpy(out, block, out_len);
  }

  if (!CTR_DRBG_update(drbg, additional_data, additional_data_len)) {
    return 0;
  }

  drbg->reseed_counter++;
  return 1;
}

static int CTR_DRBG_init_internal(CTR_DRBG_STATE *drbg,
                                  const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                                  const uint8_t *personalization,
                                  size_t personalization_len) {
  /* Section 10.2.1.3.1 */
  if (personalization_len > CTR_DRBG_ENTROPY_LEN) {
    return 0;
  }

  uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];
  OPENSSL_memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);

  for (size_t i = 0; i < personalization_len; i++) {
    seed_material[i] ^= personalization[i];
  }

  /* Section 10.2.1.2 */

  /* kInitMask is the result of encrypting blocks with big-endian value 1, 2
   * and 3 with the all-zero AES-256 key. */
  static const uint8_t kInitMask[CTR_DRBG_ENTROPY_LEN] = {
      0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
      0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
      0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
      0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
  };

  for (size_t i = 0; i < sizeof(kInitMask); i++) {
    seed_material[i] ^= kInitMask[i];
  }

  drbg->ctr = aes_ctr_set_key(&drbg->ks, NULL, &drbg->block, seed_material, 32);
  OPENSSL_memcpy(drbg->counter.bytes, seed_material + 32, 16);
  drbg->reseed_counter = 1;

  return 1;
}

int CTR_DRBG_init(CTR_DRBG_STATE *drbg,
                  const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                  const uint8_t *personalization, size_t personalization_len) {
#if defined(BORINGSSL_FIPS)
  /* SP 800-90Ar1, section 11.3.2 */
  CTR_DRBG_STATE testing_state;
  uint8_t output[sizeof(kOutput)];
  if (!CTR_DRBG_init_internal(&testing_state, kEntropy, kPersonalization,
                              sizeof(kPersonalization)) ||
      !CTR_DRBG_generate_internal(&testing_state, output, sizeof(kOutput), kAD,
                                  sizeof(kAD)) ||
      OPENSSL_memcmp(kOutput, output, sizeof(kOutput)) != 0) {
    printf("DRBG init health check failed.\n");
    BORINGSSL_FIPS_abort();
  }
#endif

  return CTR_DRBG_init_internal(drbg, entropy, personalization,
                                personalization_len);
}

OPENSSL_COMPILE_ASSERT(CTR_DRBG_ENTROPY_LEN % AES_BLOCK_SIZE == 0,
                       not_a_multiple_of_block_size);

static int CTR_DRBG_reseed_internal(CTR_DRBG_STATE *drbg,
                                    const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                                    const uint8_t *additional_data,
                                    size_t additional_data_len) {
  /* Section 10.2.1.4 */
  uint8_t entropy_copy[CTR_DRBG_ENTROPY_LEN];

  if (additional_data_len > 0) {
    if (additional_data_len > CTR_DRBG_ENTROPY_LEN) {
      return 0;
    }

    OPENSSL_memcpy(entropy_copy, entropy, CTR_DRBG_ENTROPY_LEN);
    for (size_t i = 0; i < additional_data_len; i++) {
      entropy_copy[i] ^= additional_data[i];
    }

    entropy = entropy_copy;
  }

  if (!CTR_DRBG_update(drbg, entropy, CTR_DRBG_ENTROPY_LEN)) {
    return 0;
  }

  drbg->reseed_counter = 1;

  return 1;
}

int CTR_DRBG_reseed(CTR_DRBG_STATE *drbg,
                    const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                    const uint8_t *additional_data,
                    size_t additional_data_len) {
#if defined(BORINGSSL_FIPS)
  /* SP 800-90Ar1, section 11.3.2 */
  CTR_DRBG_STATE testing_state;
  uint8_t output[sizeof(kOutput)];
  if (!CTR_DRBG_init_internal(&testing_state, kEntropy, kPersonalization,
                              sizeof(kPersonalization)) ||
      !CTR_DRBG_reseed_internal(&testing_state, kEntropy2, kAD, sizeof(kAD)) ||
      !CTR_DRBG_generate_internal(&testing_state, output, sizeof(kOutput), kAD,
                                  sizeof(kAD)) ||
      OPENSSL_memcmp(kReseedOutput, output, sizeof(kOutput)) != 0) {
    printf("DRBG reseed health check failed.\n");
    BORINGSSL_FIPS_abort();
  }
#endif

  return CTR_DRBG_reseed_internal(drbg, entropy, additional_data,
                                  additional_data_len);
}

int CTR_DRBG_generate(CTR_DRBG_STATE *drbg, uint8_t *out, size_t out_len,
                      const uint8_t *additional_data,
                      size_t additional_data_len) {
#if defined(BORINGSSL_FIPS)
  if (drbg->reseed_counter != 0 && (drbg->reseed_counter & 0xffff) == 0) {
    /* Perform another KAT to ensure continued health. SP 800-90Ar1,
     * section 11.3.3. */
    CTR_DRBG_STATE testing_state;
    uint8_t output[sizeof(kOutput)];
    if (!CTR_DRBG_init_internal(&testing_state, kEntropy, kPersonalization,
                                sizeof(kPersonalization)) ||
        !CTR_DRBG_generate_internal(&testing_state, output, sizeof(kOutput),
                                    kAD, sizeof(kAD)) ||
        OPENSSL_memcmp(kOutput, output, sizeof(kOutput)) != 0) {
      printf("DRBG generate health check failed.\n");
      BORINGSSL_FIPS_abort();
    }
  }
#endif

  return CTR_DRBG_generate_internal(drbg, out, out_len, additional_data,
                                    additional_data_len);
}

void CTR_DRBG_clear(CTR_DRBG_STATE *drbg) {
  OPENSSL_cleanse(drbg, sizeof(CTR_DRBG_STATE));
}
