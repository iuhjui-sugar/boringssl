/* Copyright (c) 2023, Google LLC
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
#ifndef OPENSSL_HEADER_CRYPTO_SPX_UTIL_H
#define OPENSSL_HEADER_CRYPTO_SPX_UTIL_H

#include <openssl/base.h>

// Encodes the integer value of input to out_len bytes in big-endian order.
// Note that input < 2^(8*out_len), as otherwise this function will truncate
// the least significant bytes of the integer representation.
void uint64_to_bytes(uint8_t *output, size_t out_len, uint64_t input);

uint32_t to_uint32(const uint8_t *input);
uint64_t to_uint64(const uint8_t *input, size_t input_len);

void uint32_to_bytes(uint8_t *output, const uint32_t input);

// Compute the base b representation of X.
//
// The base b must be a power of 2.
// As some of the parameter sets in https://eprint.iacr.org/2022/1725.pdf use
// a FORS height > 16 we use a uint32_t to store the output.
void base_b(uint32_t *output, size_t out_len, const uint8_t *input,
            unsigned int b);

#endif  // OPENSSL_HEADER_CRYPTO_SPX_UTIL_H
