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

#ifndef OPENSSL_HEADER_HRSS_INTERNAL_H
#define OPENSSL_HEADER_HRSS_INTERNAL_H

#include <openssl/base.h>
#include "../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


#define N 701
#define BITS_PER_WORD (sizeof(word_t) * 8)
#define WORDS_PER_POLY ((N + BITS_PER_WORD - 1) / BITS_PER_WORD)
#define BITS_IN_LAST_WORD (N % BITS_PER_WORD)

typedef crypto_word_t word_t;

struct poly2 {
  word_t v[WORDS_PER_POLY];
};

OPENSSL_EXPORT void HRSS_poly2_rotr_consttime(struct poly2 *p, size_t bits);


#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // !OPENSSL_HEADER_HRSS_INTERNAL_H
