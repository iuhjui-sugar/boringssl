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

#include "./spx_util.h"

#include <stdio.h>

void spx_uint64_to_len_bytes(uint8_t *output, size_t out_len, uint64_t input) {
  for (size_t i = out_len; i > 0; --i) {
    output[i - 1] = input & 0xff;
    input = input >> 8;
  }
}

uint32_t spx_to_uint32(const uint8_t *input) {
  uint32_t tmp = 0;
  for (size_t i = 0; i < 4; ++i) {
    tmp = 256 * tmp + input[i];
  }
  return tmp;
}

uint64_t spx_to_uint64(const uint8_t *input, size_t input_len) {
  uint64_t tmp = 0;
  for (size_t i = 0; i < input_len; ++i) {
    tmp = 256 * tmp + input[i];
  }
  return tmp;
}

void spx_uint32_to_bytes(uint8_t *output, const uint32_t input) {
  output[0] = (uint8_t)(input >> 24);
  output[1] = (uint8_t)(input >> 16);
  output[2] = (uint8_t)(input >> 8);
  output[3] = (uint8_t)(input);
}

// Compute the log2 of a power of 2.
static unsigned int log2_p2(unsigned int x) {
  // TODO: Replace with lookup for the limited values we need
  for (int b = 0; x != 0; x >>= 1) {
    if (x & 0x1) {
      return b;
    }
    b++;
  }
  return 0;
}

void spx_base_b(uint32_t *output, size_t out_len, const uint8_t *input,
                unsigned int base) {
  int in = 0;
  unsigned int out = 0;
  unsigned int bits = 0;
  unsigned int total = 0;

  for (out = 0; out < out_len; ++out) {
    while (bits < log2_p2(base)) {
      total = (total << 8) + input[in];
      in++;
      bits = bits + 8;
    }
    bits -= log2_p2(base);
    output[out] = (total >> bits) % base;
  }
}
