/* Copyright (c) 2023, Google Inc.
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

#include <openssl/kyber.h>

#include <assert.h>
#include <stdlib.h>

#include <openssl/rand.h>

#include "../internal.h"
#include "./internal.h"

#define PRIME 3329
#define LOG2PRIME 12
#define HALF_PRIME ((PRIME - 1) / 2)
#define BARRET_MULTIPLIER 5039
#define BARRET_SHIFT 24
#define DEGREE 256
#define RANK 3
#define ETA1 2
#define ETA2 2
#define DU 10
#define DV 4
#define INVERSE_DEGREE 3303
#define ENCODED_SCALAR_SIZE (LOG2PRIME * DEGREE / 8)
#define ENCODED_VECTOR_SIZE (ENCODED_SCALAR_SIZE * RANK)
#define COMPRESSED_SCALAR_SIZE (DV * DEGREE / 8)
#define COMPRESSED_VECTOR_SIZE (DU * RANK * DEGREE / 8)
#define PUBLIC_KEY_RHO_OFFSET ENCODED_VECTOR_SIZE
#define PUBLIC_KEY_OFFSET ENCODED_VECTOR_SIZE
#define PUBLIC_KEY_HASH_OFFSET (2 * ENCODED_VECTOR_SIZE + 32)
#define FO_FAILUE_OFFSET (2 * ENCODED_VECTOR_SIZE + 2 * 32)

typedef struct scalar {
  int32_t c[DEGREE];
} scalar;

typedef struct vector {
  scalar v[RANK];
} vector;

typedef struct matrix {
  scalar v[RANK][RANK];
} matrix;

// ntt_roots[i] = 17 ^ bitreverse(i) mod 3329, i = 0..127
static const int32_t ntt_roots[128] = {
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,
    2786, 3260, 569,  1746, 296,  2447, 1339, 1476, 3046, 56,   2240, 1333,
    1426, 2094, 535,  2882, 2393, 2879, 1974, 821,  289,  331,  3253, 1756,
    1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910,  17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789,
    1847, 952,  1461, 2687, 939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063, 319,  2773, 757,
    2099, 561,  2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885,  2154,
};

// inverse_ntt_roots[i] = 17 ^ -bitinverse(i) mod 3329, i = 0..127
static const int32_t inverse_ntt_roots[128] = {
    1,    1600, 40,   749,  2481, 1432, 2699, 687,  1583, 2760, 69,   543,
    2532, 3136, 1410, 2267, 2508, 1355, 450,  936,  447,  2794, 1235, 1903,
    1996, 1089, 3273, 283,  1853, 1990, 882,  3033, 2419, 2102, 219,  855,
    2681, 1848, 712,  682,  927,  1795, 461,  1891, 2877, 2522, 1894, 1010,
    1414, 2009, 3296, 464,  2697, 816,  1352, 2679, 1274, 1052, 1025, 2132,
    1573, 76,   2998, 3040, 1175, 2444, 394,  1219, 2300, 1455, 2117, 1607,
    2443, 554,  1179, 2186, 2303, 2926, 2237, 525,  735,  863,  2768, 1230,
    2572, 556,  3010, 2266, 1684, 1239, 780,  2954, 109,  1292, 1031, 1745,
    2688, 3061, 992,  2596, 941,  892,  1021, 2390, 642,  1868, 2377, 1482,
    1540, 540,  1678, 1626, 279,  314,  1173, 2573, 3096, 48,   667,  1920,
    2229, 1041, 2606, 1692, 680,  2746, 568,  3312,
};

// mod_roots[i] = 17 ^ (2*bit_inverse(i) + 1) mod 3329, i = 0..127
static const int32_t mod_roots[128] = {
    17,   3312, 2761, 568,  583,  2746, 2649, 680,  1637, 1692, 723,  2606,
    2288, 1041, 1100, 2229, 1409, 1920, 2662, 667,  3281, 48,   233,  3096,
    756,  2573, 2156, 1173, 3015, 314,  3050, 279,  1703, 1626, 1651, 1678,
    2789, 540,  1789, 1540, 1847, 1482, 952,  2377, 1461, 1868, 2687, 642,
    939,  2390, 2308, 1021, 2437, 892,  2388, 941,  733,  2596, 2337, 992,
    268,  3061, 641,  2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
    375,  2954, 2549, 780,  2090, 1239, 1645, 1684, 1063, 2266, 319,  3010,
    2773, 556,  757,  2572, 2099, 1230, 561,  2768, 2466, 863,  2594, 735,
    2804, 525,  1092, 2237, 403,  2926, 1026, 2303, 1143, 2186, 2150, 1179,
    2775, 554,  886,  2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935, 394,  885,  2444, 2154, 1175,
};

// constant time reduce x mod PRIME with x being between 0 and 2*PRIME
static int32_t reduce_simple(int64_t x) {
  assert(x >= 0 && x < 2 * PRIME);
  return constant_time_select_w(constant_time_ge_w(x, PRIME), x - PRIME, x);
}

// constant time reduce x mod PRIME using Barret reduction.
static int32_t reduce(int64_t x) {
  int64_t product = x * BARRET_MULTIPLIER;
  int32_t quotient = product >> BARRET_SHIFT;
  int32_t remainder = x - quotient * PRIME;
  return reduce_simple(remainder);
}

static void zero_scalar(scalar *out) {
  for (int i = 0; i < DEGREE; i++) {
    out->c[i] = 0;
  }
}

static void zero_vector(vector *out) {
  for (int i = 0; i < RANK; i++) {
    zero_scalar(&out->v[i]);
  }
}

// In place number theoretic transform of a given scalar.
// Note that Kyber's prime 3329 does not have a 512th root of unity, so this
// transform leaves of the last iteration of the usual FFT code, with the 128
// relevant roots of unity being stored in |ntt_roots|. This means the output
// should be seen as 128 elements in GF(3329^2), with the coefficients of the
// elements being consecutive entries in s->c.
static void number_theoretic_transform_scalar(scalar *s) {
  int offset = DEGREE;
  for (int step = 1; step < DEGREE / 2; step <<= 1) {
    offset >>= 1;
    int k = 0;
    for (int i = 0; i < step; i++) {
      int32_t step_root = ntt_roots[i + step];
      for (int j = k; j < k + offset; j++) {
        int32_t odd = reduce(step_root * s->c[j + offset]);
        int32_t even = s->c[j];
        s->c[j] = reduce_simple(odd + even);
        s->c[j + offset] = reduce_simple(even - odd + PRIME);
      }
      k += 2 * offset;
    }
  }
}

static void number_theoretic_transform_vector(vector *a) {
  for (int i = 0; i < RANK; i++) {
    number_theoretic_transform_scalar(&a->v[i]);
  }
}

// In place inverse number theoretic transform of a given scalar, with pairs of
// entries of s->v being interpreted as elements of GF(3329^2). Just as with the
// number theoretic transform, this leaves of the first step of the normal iFFT
// to account for the fact that 3329 does not have a 512th root of unity, using
// the precomputed 128 roots of unity stored in |inverse_ntt_roots|.
static void inverse_number_theoretic_transform_scalar(scalar *s) {
  int step = DEGREE / 2;
  for (int offset = 2; offset < DEGREE; offset <<= 1) {
    step >>= 1;
    int k = 0;
    for (int i = 0; i < step; i++) {
      int32_t step_root = inverse_ntt_roots[i + step];
      for (int j = k; j < k + offset; j++) {
        int32_t odd = s->c[j + offset];
        int32_t even = s->c[j];
        s->c[j] = reduce_simple(odd + even);
        s->c[j + offset] = reduce(step_root * (even - odd + PRIME));
      }
      k += 2 * offset;
    }
  }
  for (int i = 0; i < DEGREE; i++) {
    s->c[i] = reduce(s->c[i] * INVERSE_DEGREE);
  }
}

static void inverse_number_theoretic_transform_vector(vector *a) {
  for (int i = 0; i < RANK; i++) {
    inverse_number_theoretic_transform_scalar(&a->v[i]);
  }
}

static void add_accumulate_scalar(scalar *lhs, const scalar *rhs) {
  for (int i = 0; i < DEGREE; i++) {
    lhs->c[i] = reduce_simple(lhs->c[i] + rhs->c[i]);
  }
}

static void subtract_accumulate_scalar(scalar *lhs, const scalar *rhs) {
  for (int i = 0; i < DEGREE; i++) {
    lhs->c[i] = reduce_simple(lhs->c[i] - rhs->c[i] + PRIME);
  }
}

// Multiplying to scalars in the number theoretically transformed state. Since
// 3329 does not have a 512th root of unity, this means we have to interpret
// the 2*ith and (2*i+)1th entries of the scalar as elements of GF(3329)[X]/(X^2
// - 17^(2*bitinverse(i)+1)) The value of 17^(2*bitinverse(i)+1) mod 3329 is
// stored in the precomputed |mod_roots| table. Note that our Barret transform
// only allows us to multipy two reduced numbers together, so we need some
// intermediate reduction steps, even if an int64_t could hold 3 multiplied
// numbers.
static void multiply(const scalar *lhs, const scalar *rhs, scalar *out) {
  for (int i = 0; i < DEGREE / 2; i++) {
    int32_t real_real = reduce(lhs->c[2 * i] * rhs->c[2 * i]);
    int32_t img_img = reduce(rhs->c[2 * i + 1] * lhs->c[2 * i + 1]);
    int32_t real_img = reduce(lhs->c[2 * i] * rhs->c[2 * i + 1]);
    int32_t img_real = reduce(lhs->c[2 * i + 1] * rhs->c[2 * i]);
    out->c[2 * i] = reduce((real_real + img_img * (mod_roots[i])));
    out->c[2 * i + 1] = reduce_simple((img_real + real_img));
  }
}

static void add_accumulate_vector(vector *lhs, const vector *rhs) {
  for (int i = 0; i < RANK; i++) {
    add_accumulate_scalar(&lhs->v[i], &rhs->v[i]);
  }
}

static void matrix_multiply(const matrix *m, const vector *a, vector *out) {
  zero_vector(out);
  for (int i = 0; i < RANK; i++) {
    for (int j = 0; j < RANK; j++) {
      scalar product;
      multiply(&m->v[i][j], &a->v[j], &product);
      add_accumulate_scalar(&out->v[i], &product);
    }
  }
}

static void matrix_multiply_transpose(const matrix *m, const vector *a,
                                      vector *out) {
  zero_vector(out);
  for (int i = 0; i < RANK; i++) {
    for (int j = 0; j < RANK; j++) {
      scalar product;
      multiply(&m->v[j][i], &a->v[j], &product);
      add_accumulate_scalar(&out->v[i], &product);
    }
  }
}

static void inner_product(const vector *lhs, const vector *rhs, scalar *out) {
  zero_scalar(out);
  for (int i = 0; i < RANK; i++) {
    scalar product;
    multiply(&lhs->v[i], &rhs->v[i], &product);
    add_accumulate_scalar(out, &product);
  }
}

// Algorithm 1 of the Kyber spec. Rejection samples a keccak stream to get
// uniformly distributed elements. This is used for matrix expansion.
static void parse(struct BORINGSSL_keccak_st *ctx, scalar *out) {
  int index = 0;
  uint8_t bytes[3];
  while (index < DEGREE) {
    BORINGSSL_keccak_squeeze(ctx, bytes, 3);
    int d1 = bytes[0] + 256 * (bytes[1] % 16);
    int d2 = bytes[1] / 16 + 16 * bytes[2];
    if (d1 < PRIME) {
      out->c[index++] = d1;
    }
    if (d2 < PRIME && index < DEGREE) {
      out->c[index++] = d2;
    }
  }
}

// Algorithm 2 of the Kyber spec. Creates binominally distributed elements by
// sampling 2*|eta| bits, and setting the coefficient to the count of the first
// bits minus the count of the second bits, resulting in a centered binomial
// distribution. In practice, our values for eta are always 2, so this gives
// -2/2 with a probability of 1/16, -1/1 with probability 1/4, and 0 with
// probability 3/8.
static void centered_binomial_distribution(int eta, uint8_t *entropy,
                                           scalar *out) {
  for (int i = 0; i < DEGREE; i++) {
    int32_t value = 0;
    for (int j = 0; j < eta; j++) {
      int plus_index = 2 * i * eta + j;
      int minus_index = (2 * i + 1) * eta + j;
      value = constant_time_select_w(
          constant_time_is_zero_w(entropy[plus_index / 8] &
                                  (1 << (plus_index % 8))),
          value, value + 1);
      value = constant_time_select_w(
          constant_time_is_zero_w(entropy[minus_index / 8] &
                                  (1 << (minus_index % 8))),
          value, value + PRIME - 1);
    }
    out->c[i] = reduce(value);
  }
}

// Generates a secret vector by using |centered_binomial_distribution|, using
// the given seed appending and incrementing |counter| for entry of the vector.
static void generate_secret_vector(int eta, uint8_t *counter, uint8_t *seed,
                                   vector *out) {
  int size = 2 * eta * DEGREE / 8;
  assert(size <= 128);
  uint8_t input[33];
  OPENSSL_memcpy(input, seed, 32);
  for (int i = 0; i < RANK; i++) {
    input[32] = (*counter)++;
    uint8_t entropy[128];
    BORINGSSL_keccak(entropy, size, input, 33, boringssl_shake256);
    centered_binomial_distribution(eta, entropy, &out->v[i]);
  }
}

// Expands the matrix of a seed for key generation and for encaps-CPA.
static void expand_matrix(uint8_t *rho, matrix *out) {
  uint8_t input[34];
  OPENSSL_memcpy(input, rho, 32);
  for (int i = 0; i < RANK; i++) {
    for (int j = 0; j < RANK; j++) {
      struct BORINGSSL_keccak_st ctx;
      input[32] = i;
      input[33] = j;
      BORINGSSL_keccak_init(&ctx, input, 34, boringssl_shake128);
      parse(&ctx, &out->v[i][j]);
    }
  }
}

// Inverse of Algorithm 3 of the Kyber spec. Packs the elements of the scalar
// tightly into the output array, by encoding each scalar coefficient using
// |bits| many bits.
static void encode_scalar(const scalar *s, uint8_t *out, int bits) {
  int written = 0;
  *out = 0;
  for (int i = 0; i < DEGREE; i++) {
    int left = bits;
    uint32_t to_write = s->c[i];
    while (left > 0) {
      if (written == 8) {
        written = 0;
        out++;
        *out = 0;
      }
      int write = (left < (8 - written)) ? left : (8 - written);
      uint8_t mask = (1 << write) - 1;
      *out |= (to_write & mask) << written;
      to_write >>= write;
      written += write;
      left -= write;
    }
  }
}

// Encodes an entire vector. Note that since 256 (DEGREE) is divisible by 8, the
// individual vector entries will always fill a whole number of bytes, so we do
// not need to worry about bit packing here.
static void encode_vector(const vector *a, uint8_t *out, int bits) {
  for (int i = 0; i < RANK; i++) {
    encode_scalar(&a->v[i], out + i * bits * DEGREE / 8, bits);
  }
}

// Algorithm 3 of the Kyber spec.
static void decode_scalar(uint8_t *in, int bits, scalar *out) {
  int remaining = 8;
  for (int i = 0; i < DEGREE; i++) {
    out->c[i] = 0;
    int left = bits;
    uint32_t power = 0;
    while (left > 0) {
      int read = left < remaining ? left : remaining;
      uint8_t mask = ((1 << read) - 1) << (8 - remaining);
      out->c[i] += ((((*in) & mask) >> (8 - remaining)) << power);
      remaining -= read;
      left -= read;
      power += read;
      if (remaining == 0) {
        remaining = 8;
        in++;
      }
    }
  }
}

static void decode_vector(uint8_t *in, int bits, vector *out) {
  for (int i = 0; i < RANK; i++) {
    decode_scalar(in + i * bits * DEGREE / 8, bits, &out->v[i]);
  }
}

// Compresses (lossily) an input |x| mod 3329 into |bits| many bits by grouping
// numbers close to each other together. The formula used is
// round(2^|bits|/PRIME*x) mod 2^|bits|.
// Uses Barret reduction to achieve constant time. Since we need both the
// remainder (for rounding) and the quotient (as the result), we cannot use
// |reduce| here, but need to do the Barret reduction directly.
static int32_t compress(int32_t x, int bits) {
  int64_t product = (x << bits);
  int64_t quotient = (product * BARRET_MULTIPLIER) >> BARRET_SHIFT;
  int32_t remainder = product - quotient * PRIME;
  assert(remainder >= 0 && remainder < 2 * PRIME);
  // Adjusting quotient if necessary.
  quotient = constant_time_select_w(constant_time_ge_w(remainder, PRIME),
                                    quotient + 1, quotient);
  // Recomputing the correct remainder. We could also use |reduce_simple| here,
  // but this avoids calling into constant time libraries for a second time.
  remainder = product - quotient * PRIME;
  // The rounding logic compares the number to (PRIME + 1)/2 and conditionally
  // increments the quotient. The final mod 2^|bits| step is achieves through
  // bitwise operations.
  return constant_time_select_w(constant_time_ge_w(HALF_PRIME, remainder),
                                quotient, quotient + 1) &
         ((1 << bits) - 1);
}

// Decompresses |x| by using an equi-distant representative. The formula is
// round(PRIME/2^|bits|*x). Note that 2^|bits| being the divisor allows us to
// implement this logic using only bit operations.
static int32_t decompress(int32_t x, int bits) {
  int32_t product = x * PRIME;
  int32_t power = 1 << bits;
  // This is |product| % power, since |power| is a power of 2.
  int32_t remainder = product & (power - 1);
  // This is |product| / power, since |power| is a power of 2.
  int32_t lower = product >> bits;
  // The rounding logic works since the first half of numbers mod |power| have a
  // 0 as first bit, and the second half has a 1 as first bit, since |power| is
  // a power of 2. As a 12 bit number, |remainder| is always positive, so we
  // will shift in 0s for a right shift.
  return lower + (remainder >> (bits - 1));
}

static void compress_scalar(scalar *s, int bits) {
  for (int i = 0; i < DEGREE; i++) {
    s->c[i] = compress(s->c[i], bits);
  }
}

static void decompress_scalar(scalar *s, int bits) {
  for (int i = 0; i < DEGREE; i++) {
    s->c[i] = decompress(s->c[i], bits);
  }
}

static void compress_vector(vector *a, int bits) {
  for (int i = 0; i < RANK; i++) {
    compress_scalar(&a->v[i], bits);
  }
}

static void decompress_vector(vector *a, int bits) {
  for (int i = 0; i < RANK; i++) {
    decompress_scalar(&a->v[i], bits);
  }
}

// Algorithm 5 of the Kyber spec. Encrypts a message with given randomness to
// the ciphertext in |out|. Without applying the Fujisaki-Okamoto transform this
// would not result in a CCA secure scheme, since lattice schemes are vulnerable
// to decryption failure oracles.
static void encrypt_cpa(uint8_t *public_key, uint8_t *message,
                        uint8_t *randomness, uint8_t *out) {
  vector rhs;
  decode_vector(public_key, LOG2PRIME, &rhs);
  matrix m;
  expand_matrix(public_key + PUBLIC_KEY_RHO_OFFSET, &m);
  uint8_t counter = 0;
  vector secret;
  generate_secret_vector(ETA1, &counter, randomness, &secret);
  number_theoretic_transform_vector(&secret);
  vector error;
  generate_secret_vector(ETA2, &counter, randomness, &error);
  int size = 2 * ETA2 * DEGREE / 8;
  assert(size <= 128);
  uint8_t input[33];
  OPENSSL_memcpy(input, randomness, 32);
  input[32] = counter;
  uint8_t entropy[128];
  BORINGSSL_keccak(entropy, size, input, 33, boringssl_shake256);
  scalar scalar_error;
  centered_binomial_distribution(ETA2, entropy, &scalar_error);
  vector u;
  matrix_multiply(&m, &secret, &u);
  inverse_number_theoretic_transform_vector(&u);
  add_accumulate_vector(&u, &error);
  scalar v;
  inner_product(&rhs, &secret, &v);
  inverse_number_theoretic_transform_scalar(&v);
  add_accumulate_scalar(&v, &scalar_error);
  scalar expanded_message;
  decode_scalar(message, 1, &expanded_message);
  decompress_scalar(&expanded_message, 1);
  add_accumulate_scalar(&v, &expanded_message);
  compress_vector(&u, DU);
  encode_vector(&u, out, DU);
  compress_scalar(&v, DV);
  encode_scalar(&v, out + COMPRESSED_VECTOR_SIZE, DV);
}

// Algorithm 6 of the Kyber spec.
static void decrypt_cpa(uint8_t *private_key, uint8_t *ciphertext,
                        uint8_t *out) {
  vector u;
  decode_vector(ciphertext, DU, &u);
  decompress_vector(&u, DU);
  number_theoretic_transform_vector(&u);
  scalar v;
  decode_scalar(ciphertext + COMPRESSED_VECTOR_SIZE, DV, &v);
  decompress_scalar(&v, DV);
  vector secret;
  decode_vector(private_key, LOG2PRIME, &secret);
  scalar mask;
  inner_product(&secret, &u, &mask);
  inverse_number_theoretic_transform_scalar(&mask);
  subtract_accumulate_scalar(&v, &mask);
  compress_scalar(&v, 1);
  encode_scalar(&v, out, 1);
}

// Calls |KYBER_generate_key_external_entropy| with random bytes from
// |RAND_bytes|.
void KYBER_generate_key(uint8_t out_public_key[KYBER_PUBLIC_KEY_BYTES],
                        uint8_t out_private_key[KYBER_PRIVATE_KEY_BYTES]) {
  uint8_t entropy[KYBER_GENERATE_KEY_ENTROPY];
  RAND_bytes(entropy, KYBER_GENERATE_KEY_ENTROPY);
  KYBER_generate_key_external_entropy(out_public_key, out_private_key, entropy);
}

// Algorithms 4 and 7 of the Kyber spec. Algorithms are combined since key
// generation is not part of the FO transform, and the spec uses Algorithm 7 to
// specify the actual key format.
void KYBER_generate_key_external_entropy(
    uint8_t out_public_key[KYBER_PUBLIC_KEY_BYTES],
    uint8_t out_private_key[KYBER_PRIVATE_KEY_BYTES],
    uint8_t in_entropy[KYBER_GENERATE_KEY_ENTROPY]) {
  uint8_t hashed[64];
  BORINGSSL_keccak(hashed, 64, in_entropy, 32, boringssl_sha3_512);
  uint8_t *rho = hashed;
  uint8_t *sigma = hashed + 32;
  matrix m;
  expand_matrix(rho, &m);
  uint8_t counter = 0;
  vector secret;
  generate_secret_vector(ETA1, &counter, sigma, &secret);
  number_theoretic_transform_vector(&secret);
  vector error;
  generate_secret_vector(ETA1, &counter, sigma, &error);
  number_theoretic_transform_vector(&error);
  vector rhs;
  matrix_multiply_transpose(&m, &secret, &rhs);
  add_accumulate_vector(&rhs, &error);
  encode_vector(&rhs, out_public_key, LOG2PRIME);
  OPENSSL_memcpy(out_public_key + ENCODED_VECTOR_SIZE, rho, 32);
  uint8_t public_key_hash[32];
  BORINGSSL_keccak(public_key_hash, 32, out_public_key, KYBER_PUBLIC_KEY_BYTES,
                   boringssl_sha3_256);
  encode_vector(&secret, out_private_key, LOG2PRIME);
  OPENSSL_memcpy(out_private_key + PUBLIC_KEY_OFFSET, out_public_key,
                 KYBER_PUBLIC_KEY_BYTES);
  OPENSSL_memcpy(out_private_key + PUBLIC_KEY_HASH_OFFSET, public_key_hash, 32);
  OPENSSL_memcpy(out_private_key + FO_FAILUE_OFFSET, in_entropy + 32, 32);
}

// Calls KYBER_encap_external_entropy| with random bytes from |RAND_bytes|
void KYBER_encap(uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES],
                 uint8_t *out_shared_secret, size_t out_shared_secret_len,
                 uint8_t in_pub[KYBER_PUBLIC_KEY_BYTES]) {
  uint8_t entropy[KYBER_ENCAP_ENTROPY];
  RAND_bytes(entropy, KYBER_ENCAP_ENTROPY);
  KYBER_encap_external_entropy(out_ciphertext, out_shared_secret,
                               out_shared_secret_len, in_pub, entropy);
}

// Algorithm 8 of the Kyber spec, safe for line 2 of the spec. The spec there
// hashes the output of the system's random number generator, since the FO
// transform will reveal it to the decrypting party. There is no reason to do
// this when a secure random number generator is used. When an insecure random
// number generator is used, the caller should switch to a secure one before
// calling this method.
void KYBER_encap_external_entropy(
    uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES], uint8_t *out_shared_secret,
    size_t out_shared_secret_len, uint8_t in_pub[KYBER_PUBLIC_KEY_BYTES],
    uint8_t in_entropy[KYBER_ENCAP_ENTROPY]) {
  uint8_t input[64];
  OPENSSL_memcpy(input, in_entropy, 32);
  BORINGSSL_keccak(input + 32, 32, in_pub, KYBER_PUBLIC_KEY_BYTES,
                   boringssl_sha3_256);
  uint8_t prekey_and_randomness[64];
  BORINGSSL_keccak(prekey_and_randomness, 64, input, 64, boringssl_sha3_512);
  encrypt_cpa(in_pub, input, prekey_and_randomness + 32, out_ciphertext);
  BORINGSSL_keccak(prekey_and_randomness + 32, 32, out_ciphertext,
                   KYBER_CIPHERTEXT_BYTES, boringssl_sha3_256);
  BORINGSSL_keccak(out_shared_secret, out_shared_secret_len,
                   prekey_and_randomness, 64, boringssl_shake256);
}

// Algorithm 9 of the Kyber spec, performing the FO transform by running
// encrypt_cpa on the decrypted message. The spec does not allow the decryption
// failure to be passed on to the caller, and instead returns a result that is
// deterministic but unpredictable to anyone without knowledge of the private
// key.
void KYBER_decap(uint8_t *out_shared_secret, size_t out_shared_secret_len,
                 uint8_t in_ciphertext[KYBER_CIPHERTEXT_BYTES],
                 uint8_t in_priv[KYBER_PRIVATE_KEY_BYTES]) {
  uint8_t decrypted[64];
  decrypt_cpa(in_priv, in_ciphertext, decrypted);
  OPENSSL_memcpy(decrypted + 32, in_priv + PUBLIC_KEY_HASH_OFFSET, 32);
  uint8_t prekey_and_randomness[64];
  BORINGSSL_keccak(prekey_and_randomness, 64, decrypted, 64,
                   boringssl_sha3_512);
  uint8_t expected_ciphertext[KYBER_CIPHERTEXT_BYTES];
  encrypt_cpa(in_priv + PUBLIC_KEY_OFFSET, decrypted,
              prekey_and_randomness + 32, expected_ciphertext);
  uint8_t accumulator = 0;
  for (int i = 0; i < KYBER_CIPHERTEXT_BYTES; i++) {
    accumulator |= in_ciphertext[i] ^ expected_ciphertext[i];
  }
  uint8_t mask = constant_time_is_zero_8(accumulator);
  uint8_t input[64];
  for (int i = 0; i < 32; i++) {
    input[i] = constant_time_select_8(mask, prekey_and_randomness[i],
                                      (in_priv + FO_FAILUE_OFFSET)[i]);
  }
  BORINGSSL_keccak(input + 32, 32, in_ciphertext, KYBER_CIPHERTEXT_BYTES,
                   boringssl_sha3_256);
  BORINGSSL_keccak(out_shared_secret, out_shared_secret_len, input, 64,
                   boringssl_shake256);
}
