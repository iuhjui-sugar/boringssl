/* Copyright (c) 2015, Google Inc.
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

#ifndef OPENSSL_HEADER_BLAKE2B_H
#define OPENSSL_HEADER_BLAKE2B_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* BLAKE2b hash function, as defined in RFC 7693. */

/* BLAKE2B_256_DIGEST_LENGTH is the length of a BLAKE2b-256 digest. */
#define BLAKE2B_256_DIGEST_LENGTH 32
#define BLAKE2B_512_DIGEST_LENGTH 64

/* BLAKE2B_BLOCK_SIZE is the number of bytes in a BLAKE2b block. */
#define BLAKE2B_BLOCK_SIZE 128

OPENSSL_EXPORT int BLAKE2b_256_Init(BLAKE2B_CTX *blake2b);

OPENSSL_EXPORT int BLAKE2b_256_Update(BLAKE2B_CTX *blake2b, const void *data,
                                      size_t len);

OPENSSL_EXPORT int BLAKE2b_256_Final(uint8_t *md, BLAKE2B_CTX *blake2b);

OPENSSL_EXPORT int BLAKE2b_512_Init(BLAKE2B_CTX *blake2b);

OPENSSL_EXPORT int BLAKE2b_512_Update(BLAKE2B_CTX *blake2b, const void *data,
                                      size_t len);

OPENSSL_EXPORT int BLAKE2b_512_Final(uint8_t *md, BLAKE2B_CTX *blake2b);

struct blake2b_state_st {
  union {
    uint64_t m[16];
    uint8_t p[128];
  } u;
  uint64_t h[8];
  uint64_t v[16];
  unsigned num_bytes, md_len;
};

#if defined(__cplusplus)
}
#endif

#endif /* OPENSSL_HEADER_BLAKE2B_H */
