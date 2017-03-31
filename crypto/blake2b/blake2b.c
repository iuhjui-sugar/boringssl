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

#include <openssl/blake2b.h>

#include "../internal.h"

static uint64_t iv[8] = {
  UINT64_C(0x6a09e667f3bcc908),
  UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b),
  UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1),
  UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b),
  UINT64_C(0x5be0cd19137e2179),
};

static unsigned sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
};

#define R1 32
#define R2 24
#define R3 16
#define R4 63

/* Mixing Function G from Section 3.1 of RFC 7693 */
static void blake2_g(uint64_t *v, unsigned a, unsigned b, unsigned c, unsigned d, uint64_t x, uint64_t y) {
  v[a] += v[b] + x;
  uint64_t vd = v[d] ^ v[a];
  v[d] = (vd >> R1) ^ (vd << (64 - R1));
  v[c] += + v[d];
  uint64_t vb = v[b] ^ v[c];
  v[b] = (vb >> R2) ^ (vb << (64 - R2));
  v[a] += v[b] + y;
  vd = v[d] ^ v[a];
  v[d] = (vd >> R3) ^ (vd << (64 - R3));
  v[c] += v[d];
  vb = v[b] ^ v[c];
  v[b] = (vb >> R4) ^ (vb << (64 - R4));
}

/* Compression Function F from Section 3.2 of RFC 7693 */
static void blake2_f(BLAKE2B_CTX *b, unsigned f) {
  OPENSSL_memcpy(b->v, b->h, sizeof(b->h));
  OPENSSL_memcpy(b->v + 8, iv, sizeof(iv));

  b->v[12] ^= b->num_bytes;

  if (f) {
    b->v[14] ^= UINT64_C(0xffffffffffffffff);
  }

  for (int i = 0; i < 12; i++) {
		unsigned *s = sigma[i];
		blake2_g(b->v, 0, 4,  8, 12, b->u.m[s[0]], b->u.m[s[1]]);
		blake2_g(b->v, 1, 5,  9, 13, b->u.m[s[2]], b->u.m[s[3]]);
		blake2_g(b->v, 2, 6, 10, 14, b->u.m[s[4]], b->u.m[s[5]]);
		blake2_g(b->v, 3, 7, 11, 15, b->u.m[s[6]], b->u.m[s[7]]);
		blake2_g(b->v, 0, 5, 10, 15, b->u.m[s[8]], b->u.m[s[9]]);
		blake2_g(b->v, 1, 6, 11, 12, b->u.m[s[10]], b->u.m[s[11]]);
		blake2_g(b->v, 2, 7,  8, 13, b->u.m[s[12]], b->u.m[s[13]]);
		blake2_g(b->v, 3, 4,  9, 14, b->u.m[s[14]], b->u.m[s[15]]);
  }

	for (int i = 0; i < 8; i++) {
		b->h[i] ^= b->v[i] ^ b->v[i + 8];
	}
}

static int BLAKE2b_Init(BLAKE2B_CTX *b) {
  OPENSSL_memcpy(b->h, iv, sizeof(iv));
	// TODO: explain this line.
  b->h[0] ^= 0x01010000 ^ b->md_len;
  return 1;
}


static int BLAKE2b_Update(BLAKE2B_CTX *b, const void *data, size_t len) {
	while (1) {
		size_t partial_block_size = b->num_bytes % BLAKE2B_BLOCK_SIZE;
		if (len == 0) {
			return 1;
		}

		if (partial_block_size + len > BLAKE2B_BLOCK_SIZE) {
			// Finish the current block and start the next.
			size_t remaining_bytes = BLAKE2B_BLOCK_SIZE - partial_block_size;
			OPENSSL_memcpy(b->u.p + partial_block_size, data, remaining_bytes);
			b->num_bytes += remaining_bytes;
			data += remaining_bytes;
			len -= remaining_bytes;
			blake2_f(b, 0);
		} else {
			OPENSSL_memcpy(b->u.p + partial_block_size, data, len);
			b->num_bytes += len;
			return 1;
		}
	}
  return 1;
}

static int BLAKE2b_Final(uint8_t *md, BLAKE2B_CTX *b) {
	size_t partial_block_size = b->num_bytes % BLAKE2B_BLOCK_SIZE;
	OPENSSL_memset(b->u.p + partial_block_size, 0, BLAKE2B_BLOCK_SIZE - partial_block_size);
	blake2_f(b, 1);

  for (size_t i = 0; i < b->md_len / 8; i++) {
    uint64_t h = b->h[i];
    *(md++) = (uint8_t)(h);
    *(md++) = (uint8_t)(h >> 8);
    *(md++) = (uint8_t)(h >> 16);
    *(md++) = (uint8_t)(h >> 24);
    *(md++) = (uint8_t)(h >> 32);
    *(md++) = (uint8_t)(h >> 40);
    *(md++) = (uint8_t)(h >> 48);
    *(md++) = (uint8_t)(h >> 56);
  }
  return 1;
}

int BLAKE2b_256_Init(BLAKE2B_CTX *b) {
  OPENSSL_memset(b, 0, sizeof(BLAKE2B_CTX));
	b->md_len = BLAKE2B_256_DIGEST_LENGTH;
	return BLAKE2b_Init(b);
}

int BLAKE2b_256_Update(BLAKE2B_CTX *b, const void *data, size_t len) {
	return BLAKE2b_Update(b, data, len);
}

int BLAKE2b_256_Final(uint8_t *md, BLAKE2B_CTX *b) {
	return BLAKE2b_Final(md, b);
}

int BLAKE2b_512_Init(BLAKE2B_CTX *b) {
  OPENSSL_memset(b, 0, sizeof(BLAKE2B_CTX));
	b->md_len = BLAKE2B_512_DIGEST_LENGTH;
	return BLAKE2b_Init(b);
}

int BLAKE2b_512_Update(BLAKE2B_CTX *b, const void *data, size_t len) {
	return BLAKE2b_Update(b, data, len);
}

int BLAKE2b_512_Final(uint8_t *md, BLAKE2B_CTX *b) {
	return BLAKE2b_Final(md, b);
}
