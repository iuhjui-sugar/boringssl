/* Copyright (c) 2017, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_BASE64_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_BASE64_INTERNAL_H

#include "../internal.h"


/* constant_time_lt_args_8 behaves like |constant_time_lt_8| but takes |uint8_t|
 * arguments for a slightly simpler implementation. */
static inline uint8_t constant_time_lt_args_8(uint8_t a, uint8_t b) {
  crypto_word_t aw = a;
  crypto_word_t bw = b;
  /* |crypto_word_t| is larger than |uint8_t|, so |aw| and |bw| have the same
   * MSB. |aw| < |bw| iff MSB(|aw| - |bw|) is 1. */
  return constant_time_msb_w(aw - bw);
}

/* constant_time_in_range_8 returns |CONSTTIME_TRUE_8| if |min| <= |a| <= |max|
 * and |CONSTTIME_FALSE_8| otherwise. */
static inline uint8_t constant_time_in_range_8(uint8_t a, uint8_t min,
                                               uint8_t max) {
  a -= min;
  return constant_time_lt_args_8(a, max - min + 1);
}

static uint8_t conv_bin2ascii(uint8_t a) {
  /* Since PEM is sometimes used to carry private keys, we encode base64 data
   * itself in constant-time. */
  a &= 0x3f;
  uint8_t ret = constant_time_select_8(constant_time_eq_8(a, 62), '+', '/');
  ret =
      constant_time_select_8(constant_time_lt_args_8(a, 62), a - 52 + '0', ret);
  ret =
      constant_time_select_8(constant_time_lt_args_8(a, 52), a - 26 + 'a', ret);
  ret = constant_time_select_8(constant_time_lt_args_8(a, 26), a + 'A', ret);
  return ret;
}

static uint8_t base64_ascii_to_bin(uint8_t a) {
  /* Since PEM is sometimes used to carry private keys, we decode base64 data
   * itself in constant-time. */
  const uint8_t is_upper = constant_time_in_range_8(a, 'A', 'Z');
  const uint8_t is_lower = constant_time_in_range_8(a, 'a', 'z');
  const uint8_t is_digit = constant_time_in_range_8(a, '0', '9');
  const uint8_t is_plus = constant_time_eq_8(a, '+');
  const uint8_t is_slash = constant_time_eq_8(a, '/');
  const uint8_t is_equals = constant_time_eq_8(a, '=');

  uint8_t ret = 0xff; /* 0xff signals invalid. */
  ret = constant_time_select_8(is_upper, a - 'A', ret);      /* [0,26) */
  ret = constant_time_select_8(is_lower, a - 'a' + 26, ret); /* [26,52) */
  ret = constant_time_select_8(is_digit, a - '0' + 52, ret); /* [52,62) */
  ret = constant_time_select_8(is_plus, 62, ret);
  ret = constant_time_select_8(is_slash, 63, ret);
  /* Padding maps to zero, to be further handled by the caller. */
  ret = constant_time_select_8(is_equals, 0, ret);
  return ret;
}

/* base64_decode_quad decodes a single “quad” (i.e. four characters) of base64
 * data and writes up to three bytes to |out|. It sets |*out_num_bytes| to the
 * number of bytes written, which will be less than three if the quad ended
 * with padding.  It returns one on success or zero on error. */
static int base64_decode_quad(uint8_t *out, size_t *out_num_bytes,
                              const uint8_t *in) {
  const uint8_t a = base64_ascii_to_bin(in[0]);
  const uint8_t b = base64_ascii_to_bin(in[1]);
  const uint8_t c = base64_ascii_to_bin(in[2]);
  const uint8_t d = base64_ascii_to_bin(in[3]);
  if (a == 0xff || b == 0xff || c == 0xff || d == 0xff) {
    return 0;
  }

  const uint32_t v = ((uint32_t)a) << 18 | ((uint32_t)b) << 12 |
                     ((uint32_t)c) << 6 | (uint32_t)d;

  const unsigned padding_pattern = (in[0] == '=') << 3 |
                                   (in[1] == '=') << 2 |
                                   (in[2] == '=') << 1 |
                                   (in[3] == '=');

  switch (padding_pattern) {
    case 0:
      /* The common case of no padding. */
      *out_num_bytes = 3;
      out[0] = v >> 16;
      out[1] = v >> 8;
      out[2] = v;
      break;

    case 1: /* xxx= */
      *out_num_bytes = 2;
      out[0] = v >> 16;
      out[1] = v >> 8;
      break;

    case 3: /* xx== */
      *out_num_bytes = 1;
      out[0] = v >> 16;
      break;

    default:
      return 0;
  }

  return 1;
}


#endif  /* !OPENSSL_HEADER_CRYPTO_BASE64_INTERNAL_H */
