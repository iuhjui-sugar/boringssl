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

#include <openssl/sha256x16.h>

#include <openssl/cpu.h>
#include <openssl/digest.h>
#include <openssl/obj.h>
#include <openssl/sha.h>
#include <openssl/type_check.h>

#include "../fipsmodule/digest/internal.h"
#include "../internal.h"

#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(OPENSSL_X86) || defined(OPENSSL_X86_64))
#include <emmintrin.h>
#include <immintrin.h>

#define AVX

// There's no good way to feature detect whether a given compiler will support
// AVX2 instrinsics. Even guarding by compiler version doesn't work because, for
// example, configuring a macOS SDK via -isysroot can seem to control it.
#if defined(__AVX2INTRIN_H) || defined(_AVX2INTRIN_H_INCLUDED)
#define AVX2
#endif

#endif

// SHA-256×16 takes input message, s, and divides it into 4-byte chunks,
// stripped over 16 “lanes”, each of which is hashed with SHA-256. Chunk i,
// starting at byte offset 4×i, is part of lane i%16. Partial chunks are not
// padded.
//
// For example, given len(s) = 137, the lane hashes are:
//
//     h[0] = SHA256(s[0:4] + s[64:68] + s[128:132])
//     h[1] = SHA256(s[4:8] + s[68:72] + s[132:136])
//     h[2] = SHA256(s[8:12] + s[72:76] + s[136])
//     h[3] = SHA256(s[12:16] + s[76:80])
//     …
//     h[15] = SHA256(s[60:64] + s[124:128])
//
// The lane hashes are concatenated with the original length of the input (big-
// endian) and a type suffix to form a summary, which is hashed again. The value
// of SHA256x16(s) is then SHA256(h[0] + h[1] + ... + h[15] + BE64(len(s)) +
// "/J16").

#define BLOCK_SIZE (16 * SHA256_CBLOCK)

// state contains the state of the 16 SHA-256 hashes. In the generic code, the
// representation is obvious: each SHA-256 was eight words of state and that
// structure is repeated 16 times.
//
// With a vector unit in hand, one wants to compute n lanes in an n-word vector.
// The way that the input is assigned to different lanes is designed to be
// compatible with this: just reading the input into a vector register puts
// things in the right place for this design. Thus with a 4-word vector (e.g.
// AVX), the state will contain eight vectors for each group of four lanes. The
// first vector, for example, will contain the first word of the SHA-256 state
// for lanes zero though three.
struct state {
  union {
    uint32_t generic[8*16];
#if defined(AVX)
    __m128i avx[8+8+8+8];
#endif
#if defined(AVX2)
    // With an 8-word vector, only two groups of eight lanes are needed.
    __m256i avx2[8+8];
#endif
  } u;
};

// kInitialValues is the starting state for SHA-256.
static const uint32_t kInitialValues[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                           0xa54ff53a, 0x510e527f, 0x9b05688c,
                                           0x1f83d9ab, 0x5be0cd19};

#if defined(AVX) || defined(AVX2)
// kRoundConstants are magic values for SHA-256.
static const uint32_t kRoundConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
#endif

static void sha256x16_generic_init(struct state *st) {
  for (size_t i = 0; i < 16; i++) {
    uint32_t *state = &st->u.generic[8 * i];
    for (size_t j = 0; j < 8; j++) {
      state[j] = kInitialValues[j];
    }
  }
}

static void sha256x16_generic_update(struct state *st, const uint8_t *in,
                                     size_t num_blocks) {
  for (size_t i = 0; i < num_blocks; i++) {
    for (size_t lane = 0; lane < 16; lane++) {
      uint8_t input_block[64];
      for (size_t k = 0; k < 16; k++) {
        OPENSSL_memcpy(&input_block[k * 4], &in[lane * 4 + k * 64],
                       sizeof(uint32_t));
      }

      uint32_t *state = &st->u.generic[8 * lane];
      SHA256_TransformBlocks(state, input_block, 1);
    }

    in += BLOCK_SIZE;
  }
}

static void sha256x16_generic_final(
    struct state *st, uint8_t out[32 * 16]) {
  for (size_t i = 0; i < 8 * 16; i++) {
    const uint32_t w = CRYPTO_bswap4(st->u.generic[i]);
    OPENSSL_memcpy(&out[4*i], &w, sizeof(w));
  }
}

#if defined(AVX)

__attribute((target("avx")))
static __m128i rotate_avx(__m128i v, uint8_t right_bits) {
  return _mm_slli_epi32(v, 32 - right_bits) ^
         _mm_srli_epi32(v, right_bits);
}

__attribute((target("avx")))
static __m128i from_u32_avx(const uint32_t *v) {
  return (__m128i) _mm_broadcast_ss((const float *) v);
}

__attribute__((target("avx")))
static void sha256x16_avx_init(struct state *st) {
  for (size_t i = 0; i < 8; i++) {
    st->u.avx[i] = from_u32_avx(&kInitialValues[i]);
    st->u.avx[8 + i] = st->u.avx[i];
    st->u.avx[16 + i] = st->u.avx[i];
    st->u.avx[24 + i] = st->u.avx[i];
  }
}

__attribute__((target("avx")))
static void sha256x16_avx_update(
    struct state *st, const uint8_t *data, size_t num_blocks) {
  const __m128i kByteSwapIndexes =
      _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

  const uint8_t *block_start = data;

  for (size_t i = 0; i < num_blocks; i++) {
    for (size_t starting_word = 0; starting_word < 32; starting_word += 8) {
      const uint8_t *half_data = block_start + 2 * starting_word;

      __m128i a = st->u.avx[0 + starting_word];
      __m128i b = st->u.avx[1 + starting_word];
      __m128i c = st->u.avx[2 + starting_word];
      __m128i d = st->u.avx[3 + starting_word];
      __m128i e = st->u.avx[4 + starting_word];
      __m128i f = st->u.avx[5 + starting_word];
      __m128i g = st->u.avx[6 + starting_word];
      __m128i h = st->u.avx[7 + starting_word];
      __m128i window[16];

#if defined(__clang__)
#pragma unroll
#endif
      for (size_t j = 0; j < 64; j++) {
        __m128i w;

        if (j < 16) {
          memcpy(&w, half_data, sizeof(w));
          w = _mm_shuffle_epi8(w, kByteSwapIndexes);
          half_data += 512 / 8;
          window[j] = w;
        } else {
          const __m128i w16 = window[j & 15];
          const __m128i w15 = window[(j - 15) & 15];
          const __m128i w7 = window[(j - 7) & 15];
          const __m128i w2 = window[(j - 2) & 15];

          const __m128i s0 = rotate_avx(w15 ^ rotate_avx(w15, 18 - 7), 7) ^
                             _mm_srli_epi32(w15, 3);
          const __m128i s1 = rotate_avx(w2 ^ rotate_avx(w2, 19 - 17), 17) ^
                             _mm_srli_epi32(w2, 10);

          w = _mm_add_epi32(_mm_add_epi32(w16, s0), _mm_add_epi32(w7, s1));
        }

        const __m128i ch = ((f ^ g) & e) ^ g;
        const __m128i S1 =
            rotate_avx(e ^ rotate_avx(e, 5), 6) ^ rotate_avx(e, 25);

        const __m128i temp1 = _mm_add_epi32(
            _mm_add_epi32(_mm_add_epi32(h, S1),
                          _mm_add_epi32(ch, from_u32_avx(&kRoundConstants[j]))),
            w);

        h = g;
        g = f;
        f = e;
        e = _mm_add_epi32(d, temp1);
        d = c;

        const __m128i S0 =
            rotate_avx(a, 2) ^ rotate_avx(a, 13) ^ rotate_avx(a, 22);
        const __m128i maj = (a & b) ^ (a & c) ^ (b & c);
        const __m128i temp2 = _mm_add_epi32(S0, maj);

        c = b;
        b = a;
        a = _mm_add_epi32(temp1, temp2);

        if (j >= 16) {
          window[j & 15] = w;
        }
      }

      st->u.avx[0 + starting_word] =
          _mm_add_epi32(st->u.avx[0 + starting_word], a);
      st->u.avx[1 + starting_word] =
          _mm_add_epi32(st->u.avx[1 + starting_word], b);
      st->u.avx[2 + starting_word] =
          _mm_add_epi32(st->u.avx[2 + starting_word], c);
      st->u.avx[3 + starting_word] =
          _mm_add_epi32(st->u.avx[3 + starting_word], d);
      st->u.avx[4 + starting_word] =
          _mm_add_epi32(st->u.avx[4 + starting_word], e);
      st->u.avx[5 + starting_word] =
          _mm_add_epi32(st->u.avx[5 + starting_word], f);
      st->u.avx[6 + starting_word] =
          _mm_add_epi32(st->u.avx[6 + starting_word], g);
      st->u.avx[7 + starting_word] =
          _mm_add_epi32(st->u.avx[7 + starting_word], h);
    }

    block_start += 1024;
  }
}

__attribute__((target("avx")))
static void sha256x16_avx_final(
    struct state *st, uint8_t out[32 * 16]) {
  const uint32_t *state_words = (uint32_t *)&st->u.avx[0];

  for (size_t starting_lane = 0; starting_lane < 16; starting_lane += 4) {
    for (size_t sublane = 0; sublane < 4; sublane++) {
      for (size_t i = 0; i < 8; i++) {
        uint32_t w;
        OPENSSL_memcpy(&w, &state_words[4*i + sublane], sizeof(w));
        w = CRYPTO_bswap4(w);
        OPENSSL_memcpy(out, &w, sizeof(w));
        out += sizeof(w);
      }
    }

    state_words += 4*8;
  }
}

static int has_avx(void) {
  return (OPENSSL_ia32cap_P[1] >> 28) & 1;
}

#else

static void sha256x16_avx_init(struct state *st) {}
static void sha256x16_avx_update(struct state *st, const uint8_t *data,
                                 size_t num_blocks) {}
static void sha256x16_avx_final(struct state *st, uint8_t out[32 * 16]) {}

static int has_avx(void) {
  return 0;
}

#endif


#if defined(AVX2)

__attribute((target("avx2")))
static __m256i rotate_avx2(__m256i v, uint8_t right_bits) {
  return _mm256_slli_epi32(v, 32 - right_bits) ^
         _mm256_srli_epi32(v, right_bits);
}

__attribute((target("avx2")))
static __m256i from_u32_avx2(uint32_t v) {
  return _mm256_broadcastd_epi32(_mm_setr_epi32(v, 0, 0, 0));
}

__attribute__((target("avx2")))
static void sha256x16_avx2_init(struct state *st) {
  for (size_t i = 0; i < 8; i++) {
    st->u.avx2[i] = from_u32_avx2(kInitialValues[i]);
    st->u.avx2[8 + i] = st->u.avx2[i];
  }
}

__attribute__((target("avx2")))
static void sha256x16_avx2_update(
    struct state *st, const uint8_t *data, size_t num_blocks) {
  const __m256i kByteSwapIndexes = _mm256_broadcastsi128_si256(
      _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));

  const uint8_t *block_start = data;

  for (size_t i = 0; i < num_blocks; i++) {
    for (size_t left_right = 0; left_right < 16; left_right += 8) {
      const uint8_t *half_data = block_start + 4 * left_right;

      __m256i a = st->u.avx2[0 + left_right];
      __m256i b = st->u.avx2[1 + left_right];
      __m256i c = st->u.avx2[2 + left_right];
      __m256i d = st->u.avx2[3 + left_right];
      __m256i e = st->u.avx2[4 + left_right];
      __m256i f = st->u.avx2[5 + left_right];
      __m256i g = st->u.avx2[6 + left_right];
      __m256i h = st->u.avx2[7 + left_right];
      __m256i window[16];

#if defined(__clang__)
#pragma unroll
#endif
      for (size_t j = 0; j < 64; j++) {
        __m256i w;

        if (j < 16) {
          memcpy(&w, half_data, sizeof(w));
          w = _mm256_shuffle_epi8(w, kByteSwapIndexes);
          half_data += 512 / 8;
          window[j] = w;
        } else {
          const __m256i w16 = window[j & 15];
          const __m256i w15 = window[(j - 15) & 15];
          const __m256i w7 = window[(j - 7) & 15];
          const __m256i w2 = window[(j - 2) & 15];

          const __m256i s0 = rotate_avx2(w15 ^ rotate_avx2(w15, 18 - 7), 7) ^
                             _mm256_srli_epi32(w15, 3);
          const __m256i s1 = rotate_avx2(w2 ^ rotate_avx2(w2, 19 - 17), 17) ^
                             _mm256_srli_epi32(w2, 10);

          w = _mm256_add_epi32(_mm256_add_epi32(w16, s0),
                               _mm256_add_epi32(w7, s1));
        }

        const __m256i ch = ((f ^ g) & e) ^ g;
        const __m256i S1 =
            rotate_avx2(e ^ rotate_avx2(e, 5), 6) ^ rotate_avx2(e, 25);

        const __m256i temp1 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(h, S1),
                _mm256_add_epi32(ch, from_u32_avx2(kRoundConstants[j]))),
            w);

        h = g;
        g = f;
        f = e;
        e = _mm256_add_epi32(d, temp1);
        d = c;

        const __m256i S0 =
            rotate_avx2(a, 2) ^ rotate_avx2(a, 13) ^ rotate_avx2(a, 22);
        const __m256i maj = (a & b) ^ (a & c) ^ (b & c);
        const __m256i temp2 = _mm256_add_epi32(S0, maj);

        c = b;
        b = a;
        a = _mm256_add_epi32(temp1, temp2);

        if (j >= 16) {
          window[j & 15] = w;
        }
      }

      st->u.avx2[0 + left_right] =
          _mm256_add_epi32(st->u.avx2[0 + left_right], a);
      st->u.avx2[1 + left_right] =
          _mm256_add_epi32(st->u.avx2[1 + left_right], b);
      st->u.avx2[2 + left_right] =
          _mm256_add_epi32(st->u.avx2[2 + left_right], c);
      st->u.avx2[3 + left_right] =
          _mm256_add_epi32(st->u.avx2[3 + left_right], d);
      st->u.avx2[4 + left_right] =
          _mm256_add_epi32(st->u.avx2[4 + left_right], e);
      st->u.avx2[5 + left_right] =
          _mm256_add_epi32(st->u.avx2[5 + left_right], f);
      st->u.avx2[6 + left_right] =
          _mm256_add_epi32(st->u.avx2[6 + left_right], g);
      st->u.avx2[7 + left_right] =
          _mm256_add_epi32(st->u.avx2[7 + left_right], h);
    }

    block_start += 1024;
  }
}

__attribute__((target("avx2")))
static void sha256x16_avx2_final(
    struct state *st, uint8_t out[32 * 16]) {
  const uint32_t *state_words = (uint32_t *)&st->u.avx2[0];

  const __m256i kByteSwapIndexes = _mm256_broadcastsi128_si256(
      _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));
  const __m256i kSeq = _mm256_setr_epi32(0, 8, 8*2, 8*3, 8*4, 8*5, 8*6, 8*7);

  for (size_t left_right = 0; left_right < 2; left_right++) {
    for (size_t sublane = 0; sublane < 8; sublane++) {
      const __m256i result = _mm256_shuffle_epi8(
          _mm256_i32gather_epi32((const int *)state_words, kSeq, 4),
          kByteSwapIndexes);
      OPENSSL_memcpy(out, &result, sizeof(result));
      out += sizeof(result);
      state_words++;
    }

    state_words += 7*8;
  }
}

static int has_avx2(void) {
  return (OPENSSL_ia32cap_P[2] >> 5) & 1;
}

#else

static void sha256x16_avx2_init(struct state *st) {}
static void sha256x16_avx2_update(struct state *st, const uint8_t *data,
                                  size_t num_blocks) {}
static void sha256x16_avx2_final(struct state *st, uint8_t out[32 * 16]) {}

static int has_avx2(void) {
  return 0;
}

#endif


// state_aligned returns an interior pointer to |ctx| with the correct alignment
// for a |state| structure.
static struct state *state_aligned(SHA256x16_CTX *ctx) {
  uintptr_t x = (uintptr_t) &ctx->state[3];
  x &= ~31;
  return (struct state *) x;
}

void SHA256x16_Init(SHA256x16_CTX *ctx) {
  struct state *state = state_aligned(ctx);

  if (has_avx2()) {
    sha256x16_avx2_init(state);
  } else if (has_avx()) {
    sha256x16_avx_init(state);
  } else {
    sha256x16_generic_init(state);
  }
  ctx->num_blocks = 0;
  ctx->buf_used = 0;
}

void SHA256x16_Update(SHA256x16_CTX *ctx, const uint8_t *in, size_t in_len) {
  struct state *state = state_aligned(ctx);

  if (ctx->buf_used > 0) {
    const size_t remaining = sizeof(ctx->buf) - ctx->buf_used;
    size_t todo = in_len;
    if (todo > remaining) {
      todo = remaining;
    }
    OPENSSL_memcpy(&ctx->buf[ctx->buf_used], in, todo);

    ctx->buf_used += todo;
    in += todo;
    in_len -= todo;

    if (ctx->buf_used == sizeof(ctx->buf)) {
      if (has_avx2()) {
        sha256x16_avx2_update(state, ctx->buf, 1);
      } else if (has_avx()) {
        sha256x16_avx_update(state, ctx->buf, 1);
      } else {
        sha256x16_generic_update(state, ctx->buf, 1);
      }
      ctx->buf_used = 0;
      ctx->num_blocks++;
    }
  }

  if (in_len >= BLOCK_SIZE) {
    const size_t num_blocks = in_len / BLOCK_SIZE;
    const size_t num_bytes = num_blocks * BLOCK_SIZE;
    if (has_avx2()) {
      sha256x16_avx2_update(state, in, num_blocks);
    } else if (has_avx()) {
      sha256x16_avx_update(state, in, num_blocks);
    } else {
      sha256x16_generic_update(state, in, num_blocks);
    }
    ctx->num_blocks += num_blocks;
    in += num_bytes;
    in_len -= num_bytes;
  }

  if (in_len > 0) {
    OPENSSL_memcpy(ctx->buf, in, in_len);
    ctx->buf_used = in_len;
  }
}

// write_lane_lengths writes |num_bytes| as a big-endian value into lanes
// [|start_lane|..|end_lane_plus_one|) in the correct position for a SHA-256
// hash.
static void write_lane_lengths(uint8_t buf[1024], size_t start_lane,
                              size_t end_plus_one_lane, uint64_t num_bytes) {
  uint8_t bitlen_bytes[8];
  const uint64_t num_bits_be = CRYPTO_bswap8(num_bytes * 8);
  memcpy(bitlen_bytes, &num_bits_be, sizeof(num_bits_be));

  for (size_t word = 0; word < 2; word++) {
    for (size_t lane = start_lane; lane < end_plus_one_lane; lane++) {
      OPENSSL_memcpy(&buf[64 * (word + 14) + 4 * lane], &bitlen_bytes[4 * word],
                     sizeof(uint32_t));
    }
  }
}

void SHA256x16_Final(uint8_t out[32], SHA256x16_CTX *ctx) {
  // The “final” operation is complex. Consider a 1024-byte block like this:
  //
  //        Word -->
  //    +----+----+----+...
  // L  |    |    |    |
  // a  +----+----+----+...
  // n  |    |    |    |
  // e  +----+----+----+...
  // |  |    |    |    |
  // V  +----+----+----+...
  //    .    .    .    .
  //
  // Each box is four bytes. The grid is 16 (lanes) high and 16 (words) across.
  // The final block is probably a partial block and it fills up top-to-bottom,
  // left-to-right.
  //
  // We call the column where the next byte would be written the |filling_word|.
  const size_t n = ctx->buf_used;
  const size_t filling_word = n / 64;

  // In the filling word there are zero or more lanes which have been filled
  // (i.e. they have the full four bytes supplied for this word). These lanes
  // are the prefix:
  const size_t num_prefix_lanes = (n % 64) / 4;
  // There may be a partial lane: a lane after the prefix which has one, two, or
  // three bytes written to it:
  const size_t num_partial_lanes = (n % 4) != 0;
  // Then there are zero or more suffix lanes: lanes with no bytes for this
  // word:
  const size_t num_suffix_lanes = 16 - (num_prefix_lanes + num_partial_lanes);
  const size_t first_suffix_lane = 16 - num_suffix_lanes;

  // Each lane is a separate SHA-256 and SHA-256 needs to be finished by hashing
  // in the length of the message. The prefix, partial, and suffix lanes will
  // have hashed different number of bytes:
  const uint64_t suffix_lane_bytes =
      ctx->num_blocks * 64 + filling_word * 4;
  const uint64_t prefix_lane_bytes = suffix_lane_bytes + 4;
  const uint64_t partial_lane_bytes = suffix_lane_bytes + (n % 4);

  // Each lane will need to be finished by writing an 0x80 byte and then the
  // big-endian, 64-bit bit-length. The bit-length is always written at the end
  // of a SHA-256 block and the gap between the terminating 0x80 and it is zero
  // padded. To start, zero out the unused part of the final block:

  OPENSSL_memset(&ctx->buf[n], 0, 1024 - n);

  // Is there isn't enough space in the final block to include both the
  // terminator and the bit-length then we may have to add another block to some
  // lanes. We can split this into four cases:

  int lane_case;
  if (n <= 13 * 64) {
    // All lanes can be completed in this block.
    lane_case = 0;
  } else if (n < 14 * 64) {
    // Prefix lanes can be capped with the 0x80 byte, but not completed.
    lane_case = 1;
  } else if (n < 15 * 64 + 4) {
    // All lanes can be capped, but not completed.
    lane_case = 2;
  } else {
    // Prefix lanes cannot be capped and no lanes can be completed.
    assert(filling_word == 15 && num_prefix_lanes > 0);
    lane_case = 3;
  }

  if (lane_case < 3) {
    // The prefix lanes can be capped.
    for (size_t lane = 0; lane < num_prefix_lanes; lane++) {
      ctx->buf[64 * (filling_word + 1) + 4 * lane] = 0x80;
    }
  }

  if (num_partial_lanes) {
    ctx->buf[64 * filling_word + 4 * num_prefix_lanes + (n % 4)] = 0x80;
  }

  for (size_t lane = first_suffix_lane; lane < 16; lane++) {
    ctx->buf[64 * filling_word + 4 * lane] = 0x80;
  }

  if (lane_case == 0) {
    // There's enough space to append the bit length of the prefix lanes.
    write_lane_lengths(ctx->buf, 0, num_prefix_lanes, prefix_lane_bytes);
  }

  if (lane_case < 2) {
    // There's enough space to append the bit length of the partial lane (if
    // any) and the suffix lanes.

    if (num_partial_lanes) {
      write_lane_lengths(ctx->buf, num_prefix_lanes, num_prefix_lanes + 1,
                         partial_lane_bytes);
    }

    write_lane_lengths(ctx->buf, first_suffix_lane, 16, suffix_lane_bytes);
  }

  struct state *const state = state_aligned(ctx);
  if (has_avx2()) {
    sha256x16_avx2_update(state, ctx->buf, 1);
  } else if (has_avx()) {
    sha256x16_avx_update(state, ctx->buf, 1);
  } else {
    sha256x16_generic_update(state, ctx->buf, 1);
  }

  uint8_t lane_digests[32 * 16];
  if (lane_case < 2) {
    // Some lanes were completed. Store the current state of all lanes in |out|.
    // Any incomplete lanes will be overwritten shortly.
    if (has_avx2()) {
      sha256x16_avx2_final(state, lane_digests);
    } else if (has_avx()) {
      sha256x16_avx_final(state, lane_digests);
    } else {
      sha256x16_generic_final(state, lane_digests);
    }
  }

  if (lane_case > 0) {
    // Some lanes were not completed.
    OPENSSL_memset(ctx->buf, 0, sizeof(ctx->buf));

    if (lane_case == 3) {
      // prefix lanes still need to be capped.
      for (size_t lane = 0; lane < num_prefix_lanes; lane++) {
        ctx->buf[4 * lane] = 0x80;
      }
    }

    write_lane_lengths(ctx->buf, 0, num_prefix_lanes, prefix_lane_bytes);

    if (lane_case >= 2) {
      if (num_partial_lanes) {
        write_lane_lengths(ctx->buf, num_prefix_lanes, num_prefix_lanes + 1,
                           partial_lane_bytes);
      }

      write_lane_lengths(ctx->buf, first_suffix_lane, 16, suffix_lane_bytes);
    }

    if (has_avx2()) {
      sha256x16_avx2_update(state, ctx->buf, 1);
    } else if (has_avx()) {
      sha256x16_avx_update(state, ctx->buf, 1);
    } else {
      sha256x16_generic_update(state, ctx->buf, 1);
    }

    if (lane_case == 1) {
      uint8_t remainder_out[32 * 16];
      if (has_avx2()) {
        sha256x16_avx2_final(state, remainder_out);
      } else if (has_avx()) {
        sha256x16_avx_final(state, remainder_out);
      } else {
        sha256x16_generic_final(state, remainder_out);
      }
      OPENSSL_memcpy(lane_digests, remainder_out, 32 * num_prefix_lanes);
    } else {
      assert(lane_case == 2 || lane_case == 3);
      if (has_avx2()) {
        sha256x16_avx2_final(state, lane_digests);
      } else if (has_avx()) {
        sha256x16_avx_final(state, lane_digests);
      } else {
        sha256x16_generic_final(state, lane_digests);
      }
    }
  }

  // |lane_digests| contains 16 digests. The final step is to hash them down.
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, lane_digests, sizeof(lane_digests));

  uint8_t trailer[8 + 4];
  const uint64_t total_length = BLOCK_SIZE * ctx->num_blocks + n;
  const uint64_t total_length_be = CRYPTO_bswap8(total_length);
  OPENSSL_memcpy(trailer, &total_length_be, sizeof(total_length_be));
  OPENSSL_memcpy(&trailer[sizeof(total_length_be)], "/J16", 4);

  SHA256_Update(&sha256, trailer, sizeof(trailer));
  SHA256_Final(out, &sha256);
}

uint8_t *SHA256x16(const uint8_t *data, size_t len, uint8_t *out) {
  SHA256x16_CTX ctx;
  SHA256x16_Init(&ctx);
  SHA256x16_Update(&ctx, data, len);
  SHA256x16_Final(out, &ctx);
  return out;
}

static void evp_sha256x16_init(EVP_MD_CTX *ctx) {
  SHA256x16_Init((SHA256x16_CTX *) ctx->md_data);
}

static void evp_sha256x16_update(EVP_MD_CTX *ctx, const void *data,
                                 size_t len) {
  SHA256x16_Update((SHA256x16_CTX *)ctx->md_data, (const uint8_t *)data, len);
}

static void evp_sha256x16_final(EVP_MD_CTX *ctx, uint8_t *out) {
  SHA256x16_Final(out, (SHA256x16_CTX *)ctx->md_data);
}

static const EVP_MD EVP_sha256x16_digest = {
  NID_undef,
  32,
  0,
  evp_sha256x16_init,
  evp_sha256x16_update,
  evp_sha256x16_final,
  BLOCK_SIZE,
  sizeof(SHA256x16_CTX),
};

const EVP_MD *EVP_sha256x16(void) {
  return &EVP_sha256x16_digest;
}
