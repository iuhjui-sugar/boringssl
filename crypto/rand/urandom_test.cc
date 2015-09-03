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

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>

extern "C" {
extern void CRYPTO_sysrand(uint8_t *out, size_t requested);
}

static bool TestBuffering() {
  RAND_I_promise_not_to_fork();
  uint8_t buf[4096];

  memset(buf, 0, sizeof(buf));
  CRYPTO_sysrand(buf, 0);
  CRYPTO_sysrand(buf, 2048);  /* fills the buffer */
  CRYPTO_sysrand(buf, 4096);  /* triggers a second fill */
  CRYPTO_sysrand(buf, 2048);  /* consumes the remainder */
  CRYPTO_sysrand(buf, 4096);  /* consumes an entire new buffer */

  /* Lame, but might as well sanity check that something happened. */
  uint8_t cmp[4096];
  memset(cmp, 0, sizeof(cmp));
  return memcmp(buf, cmp, 4096) != 0;
}

int main() {
  CRYPTO_library_init();
  if (!TestBuffering()) {
    return false;
  }

  printf("PASS\n");
  return 0;
}
