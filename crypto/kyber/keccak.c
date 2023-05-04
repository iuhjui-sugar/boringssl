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

#include <openssl/base.h>

#include <assert.h>
#include <stdlib.h>

#include "../internal.h"
#include "./internal.h"


// keccak_f implements the Keccak-1600 permutation as described at
// https://keccak.team/keccak_specs_summary.html. Each lane is represented as a
// 64-bit value and the 5×5 lanes are stored as an array in row-major order.
static void keccak_f(uint64_t state[25], const int rounds) {
  static const int kMaxRounds = 24;
  assert(rounds <= kMaxRounds);

  for (int round = kMaxRounds - rounds; round < kMaxRounds; round++) {
    // θ step
    uint64_t c[5];
    for (int x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
             state[x + 20];
    }

    for (int x = 0; x < 5; x++) {
      const uint64_t d = c[(x + 4) % 5] ^ CRYPTO_rotl_u64(c[(x + 1) % 5], 1);
      for (int y = 0; y < 5; y++) {
        state[y * 5 + x] ^= d;
      }
    }

    // ρ and π steps.
    //
    // These steps involve a mapping of the state matrix. Each input point,
    // (x,y), is rotated and written to the point (y, 2x + 3y). In the Keccak
    // pseudo-code a separate array is used because an in-place operation would
    // overwrite some values that are subsequently needed. However, the mapping
    // forms a trail through 24 of the 25 values so we can do it in place with
    // only a single temporary variable.
    //
    // Start with (1, 0). The value here will be mapped and end up at (0, 2).
    // That value will end up at (2, 1), then (1, 2), and so on. After 24
    // steps, 24 of the 25 values have been hit (as this mapping is injective)
    // and the sequence will repeat. All that remains is to handle the element
    // at (0, 0), but the rotation for that element is zero, and it goes to (0,
    // 0), so we can ignore it.
    static const uint8_t kIndexes[24] = {10, 7,  11, 17, 18, 3,  5,  16,
                                         8,  21, 24, 4,  15, 23, 19, 13,
                                         12, 2,  20, 14, 22, 9,  6,  1};
    static const uint8_t kRotations[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                           45, 55, 2,  14, 27, 41, 56, 8,
                                           25, 43, 62, 18, 39, 61, 20, 44};
    uint64_t prev_value = state[1];
    for (int i = 0; i < 24; i++) {
      const uint64_t value = CRYPTO_rotl_u64(prev_value, kRotations[i]);
      const size_t index = kIndexes[i];
      prev_value = state[index];
      state[index] = value;
    }

    // χ step
    for (int y = 0; y < 5; y++) {
      const int row_index = 5 * y;
      const uint64_t orig_x0 = state[row_index];
      const uint64_t orig_x1 = state[row_index + 1];
      state[row_index] ^= ~orig_x1 & state[row_index + 2];
      state[row_index + 1] ^= ~state[row_index + 2] & state[row_index + 3];
      state[row_index + 2] ^= ~state[row_index + 3] & state[row_index + 4];
      state[row_index + 3] ^= ~state[row_index + 4] & orig_x0;
      state[row_index + 4] ^= ~orig_x0 & orig_x1;
    }

    // ι step
    //
    // From https://keccak.team/files/Keccak-reference-3.0.pdf, section
    // 1.2, the round constants are based on the output of a LFSR. Thus, as
    // suggested in the appendix of of
    // https://keccak.team/keccak_specs_summary.html, the values are
    // simply encoded here.
    static const uint64_t kRoundConstants[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    state[0] ^= kRoundConstants[round];
  }
}

OPENSSL_EXPORT void BORINGSSL_keccak_init(
    struct BORINGSSL_keccak_st *ctx, enum boringssl_keccak_config_t config) {
  OPENSSL_memset(ctx, 0, sizeof(*ctx));

  size_t capacity_bytes;
  ctx->rounds = 24;
  switch (config) {
    case boringssl_sha3_256:
      capacity_bytes = 512 / 8;
      ctx->required_out_len = 32;
      ctx->terminator = 0x06;
      break;
    case boringssl_sha3_512:
      capacity_bytes = 1024 / 8;
      ctx->required_out_len = 64;
      ctx->terminator = 0x06;
      break;
    case boringssl_shake128:
      capacity_bytes = 256 / 8;
      ctx->terminator = 0x1f;
      break;
    case boringssl_shake256:
      capacity_bytes = 512 / 8;
      ctx->terminator = 0x1f;
      break;
    case boringssl_turboshake128:
      capacity_bytes = 256 / 8;
      ctx->terminator = 0x1f;
      ctx->rounds = 12;
      break;
    case boringssl_turboshake256:
      capacity_bytes = 512 / 8;
      ctx->terminator = 0x1f;
      ctx->rounds = 12;
      break;
    default:
      abort();
  }

  ctx->rate_bytes = 200 - capacity_bytes;
  assert(ctx->rate_bytes % 8 == 0);
}

// absorb_left_encode implements the |left_encode| function from SP 800-185,
// section 2.3.1. Note that the examples at the end of that section write
// bits backwards.
static void absorb_left_encode(struct BORINGSSL_keccak_st *ctx,
                               uint64_t value) {
  uint8_t buf[sizeof(uint64_t)];
  CRYPTO_store_u64_be(buf, value);

  size_t i;
  for (i = 0; i < sizeof(buf) - 1 && buf[i] == 0; i++) {
  }
  const uint8_t len = sizeof(buf) - i;
  BORINGSSL_keccak_absorb(ctx, &len, sizeof(len));
  BORINGSSL_keccak_absorb(ctx, &buf[i], len);
}

OPENSSL_EXPORT void BORINGSSL_keccak_init_with_customization(
    struct BORINGSSL_keccak_st *ctx,
    enum boringssl_keccak_customization_config_t config,
    const uint8_t *customization, size_t customization_len) {
  // This is a sanity bound to avoid worrying about bounds later on.
  if (customization_len > 1024 * 1024 * 1024) {
    abort();
  }

  OPENSSL_memset(ctx, 0, sizeof(*ctx));
  size_t capacity_bytes;
  ctx->rounds = 24;
  switch (config) {
    case boringssl_cshake128:
      if (customization_len == 0) {
        return BORINGSSL_keccak_init(ctx, boringssl_shake128);
      }
      capacity_bytes = 256 / 8;
      ctx->terminator = 0x04;
      break;
    case boringssl_cshake256:
      if (customization_len == 0) {
        return BORINGSSL_keccak_init(ctx, boringssl_shake256);
      }
      capacity_bytes = 512 / 8;
      ctx->terminator = 0x04;
      break;
    default:
      abort();
  }

  ctx->rate_bytes = 200 - capacity_bytes;
  assert(ctx->rate_bytes % 8 == 0);

  absorb_left_encode(ctx, ctx->rate_bytes);
  BORINGSSL_keccak_absorb(ctx, (const uint8_t *)"\x01", 2);  // left_encode(0)
  absorb_left_encode(ctx, ((uint64_t)customization_len) * 8);
  BORINGSSL_keccak_absorb(ctx, customization, customization_len);

  if (ctx->next_word || ctx->word_offset) {
    keccak_f(ctx->state, ctx->rounds);
    ctx->next_word = ctx->word_offset = 0;
  }
}

void BORINGSSL_keccak_absorb(struct BORINGSSL_keccak_st *ctx, const uint8_t *in,
                             size_t in_len) {
  assert(ctx->terminator);

  // Accessing |ctx->state| as a |uint8_t*| is allowed by strict aliasing
  // because we require |uint8_t| to be a character type.
  uint8_t *const state_bytes = (uint8_t *)ctx->state;
  const size_t rate_words = ctx->rate_bytes / 8;

  if (ctx->word_offset) {
    while (ctx->word_offset < 8 && in_len) {
      state_bytes[sizeof(uint64_t) * ctx->next_word + ctx->word_offset] ^= *in;
      ctx->word_offset++;
      in++;
      in_len--;
    }

    if (ctx->word_offset == 8) {
      ctx->next_word++;
      ctx->word_offset = 0;

      if (ctx->next_word == rate_words) {
        keccak_f(ctx->state, ctx->rounds);
        ctx->next_word = 0;
      }
    }
  }

  if (ctx->next_word != 0) {
    while (in_len >= 8) {
      assert(ctx->word_offset == 0);
      ctx->state[ctx->next_word++] ^= CRYPTO_load_u64_le(in);
      in += 8;
      in_len -= 8;

      if (ctx->next_word == rate_words) {
        keccak_f(ctx->state, ctx->rounds);
        ctx->next_word = 0;
        break;
      }
    }
  }

  while (in_len >= ctx->rate_bytes) {
    assert(ctx->next_word == 0);
    for (size_t i = 0; i < rate_words; i++) {
      ctx->state[i] ^= CRYPTO_load_u64_le(in + 8 * i);
    }
    keccak_f(ctx->state, ctx->rounds);
    in += ctx->rate_bytes;
    in_len -= ctx->rate_bytes;
  }

  while (in_len >= 8) {
    assert(ctx->word_offset == 0);
    ctx->state[ctx->next_word++] ^= CRYPTO_load_u64_le(in);
    in += 8;
    in_len -= 8;

    if (ctx->next_word == rate_words) {
      keccak_f(ctx->state, ctx->rounds);
      ctx->next_word = 0;
    }
  }

  assert(in_len < 8);
  while (in_len) {
    state_bytes[sizeof(uint64_t) * ctx->next_word + ctx->word_offset] ^= *in;
    ctx->word_offset++;
    in++;
    in_len--;
  }
}

static void keccak_final(struct BORINGSSL_keccak_st *ctx) {
  assert(ctx->terminator);
  // Accessing |ctx->state| as a |uint8_t*| is allowed by strict aliasing
  // because we require |uint8_t| to be a character type.
  uint8_t *state_bytes = (uint8_t *)ctx->state;
  state_bytes[sizeof(uint64_t) * ctx->next_word + ctx->word_offset++] ^=
      ctx->terminator;
  state_bytes[ctx->rate_bytes - 1] ^= 0x80;
  keccak_f(ctx->state, ctx->rounds);
  ctx->terminator = 0;
}

void BORINGSSL_keccak(uint8_t *out, size_t out_len, const uint8_t *in,
                      size_t in_len, enum boringssl_keccak_config_t config) {
  struct BORINGSSL_keccak_st ctx;
  BORINGSSL_keccak_init(&ctx, config);
  BORINGSSL_keccak_absorb(&ctx, in, in_len);
  BORINGSSL_keccak_squeeze(&ctx, out, out_len);
}

void BORINGSSL_keccak_squeeze(struct BORINGSSL_keccak_st *ctx, uint8_t *out,
                              size_t out_len) {
  if (ctx->terminator) {
    keccak_final(ctx);
  }

  if (ctx->required_out_len &&
      (out_len != ctx->required_out_len || ctx->offset != 0)) {
    abort();
  }

  // Accessing |ctx->state| as a |uint8_t*| is allowed by strict aliasing
  // because we require |uint8_t| to be a character type.
  const uint8_t *state_bytes = (const uint8_t *)ctx->state;
  while (out_len) {
    size_t remaining = ctx->rate_bytes - ctx->offset;
    size_t todo = out_len;
    if (todo > remaining) {
      todo = remaining;
    }
    OPENSSL_memcpy(out, &state_bytes[ctx->offset], todo);
    out += todo;
    out_len -= todo;
    ctx->offset += todo;
    if (ctx->offset == ctx->rate_bytes) {
      keccak_f(ctx->state, ctx->rounds);
      ctx->offset = 0;
    }
  }
}
