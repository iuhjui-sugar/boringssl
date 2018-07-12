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

#include "../fipsmodule/digest/internal.h"
#include "../internal.h"
#include "internal.h"


void sha256x16_avx_init(struct state *st);
void sha256x16_avx_update(struct state *st, const uint8_t *data,
                          size_t num_blocks);
void sha256x16_avx_final(struct state *st, uint8_t out[32 * 16]);

void sha256x16_avx2_init(struct state *st);
void sha256x16_avx2_update(struct state *st, const uint8_t *data,
                           size_t num_blocks);
void sha256x16_avx2_final(struct state *st, uint8_t out[32 * 16]);

#if defined(OPENSSL_X86_64) && defined(OS_LINUX)

static int has_avx(void) {
  return (OPENSSL_ia32cap_P[1] >> 28) & 1;
}

static int has_avx2(void) {
  return (OPENSSL_ia32cap_P[2] >> 5) & 1;
}

#else

static int has_avx(void) { return 0; }
static int has_avx2(void) { return 0; }

void sha256x16_avx_init(struct state *st) {}
void sha256x16_avx_update(struct state *st, const uint8_t *data,
                          size_t num_blocks) {}
void sha256x16_avx_final(struct state *st, uint8_t out[32 * 16]) {}

void sha256x16_avx2_init(struct state *st) {}
void sha256x16_avx2_update(struct state *st, const uint8_t *data,
                           size_t num_blocks) {}
void sha256x16_avx2_final(struct state *st, uint8_t out[32 * 16]) {}

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

    in += SHA256x16_CBLOCK;
  }
}

static void sha256x16_generic_final(
    struct state *st, uint8_t out[32 * 16]) {
  for (size_t i = 0; i < 8 * 16; i++) {
    const uint32_t w = CRYPTO_bswap4(st->u.generic[i]);
    OPENSSL_memcpy(&out[4*i], &w, sizeof(w));
  }
}

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

  if (in_len >= SHA256x16_CBLOCK) {
    const size_t num_blocks = in_len / SHA256x16_CBLOCK;
    const size_t num_bytes = num_blocks * SHA256x16_CBLOCK;
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
  // have hashed different numbers of bytes:
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
    // Some lanes were completed. Store the current state of all lanes in
    // |lane_digests|. Any incomplete lanes will be overwritten shortly.
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
  const uint64_t total_length = SHA256x16_CBLOCK * ctx->num_blocks + n;
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
  SHA256x16_CBLOCK,
  sizeof(SHA256x16_CTX),
};

const EVP_MD *EVP_sha256x16(void) {
  return &EVP_sha256x16_digest;
}
