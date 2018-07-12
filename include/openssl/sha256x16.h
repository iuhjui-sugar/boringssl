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

#ifndef OPENSSL_HEADER_SHA256x16_H
#define OPENSSL_HEADER_SHA256x16_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// SHA-256×16


// SHA256x16_DIGEST_LENGTH is the length of a SHA-256×16 digest.
#define SHA256x16_DIGEST_LENGTH 32

// SHA256x16_CBLOCK is the block size of SHA-256×16. (I.e. 16 times the block
// size of SHA-256.)
#define SHA256x16_CBLOCK (16 * 64)

// SHA256x16_Init initialises |ctx|.
OPENSSL_EXPORT void SHA256x16_Init(SHA256x16_CTX *ctx);

// SHA256x16_Update adds |len| bytes from |data| to |sha|.
OPENSSL_EXPORT void SHA256x16_Update(SHA256x16_CTX *sha, const uint8_t *data,
                                     size_t len);

// SHA256x16_Final adds the final padding to |sha| and writes the resulting
// digest to |md|, which must have at least |SHA256x16_DIGEST_LENGTH| bytes of
// space.
OPENSSL_EXPORT void SHA256x16_Final(uint8_t *md, SHA256x16_CTX *sha);

// SHA256x16 writes the digest of |len| bytes from |data| to |out| and returns
// |out|. There must be at least |SHA256x16_DIGEST_LENGTH| bytes of space in
// |out|.
OPENSSL_EXPORT uint8_t *SHA256x16(const uint8_t *data, size_t len,
                                  uint8_t *out);

struct sha256x16_state_st {
  uint64_t state[3 + 64];
  uint64_t num_blocks;
  uint8_t buf[1024];
  // buf_used is the size, in bytes, of the prefix of |buf| that contains
  // unprocessed data. It is always less than 1024.
  unsigned buf_used;
};


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SHA256x16_H
