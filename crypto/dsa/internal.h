/* Copyright (c) 2016, Google Inc.
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

#ifndef OPENSSL_HEADER_DSA_INTERNAL_H
#define OPENSSL_HEADER_DSA_INTERNAL_H

#include <openssl/base.h>

#include <openssl/dsa.h>
#include <openssl/thread.h>
#include <openssl/type_check.h>

#if defined(__cplusplus)
extern "C" {
#endif


typedef struct {
  DSA dsa;
  CRYPTO_MUTEX lock;
  CRYPTO_refcount_t references;
} DSA_IMPL;

#define TO_DSA_IMPL(dsa) CHECKED_CAST(DSA_IMPL *, DSA *, dsa)


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_DSA_INTERNAL_H */
