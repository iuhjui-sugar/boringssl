/* Copyright (c) 2023, Google Inc.
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

#if !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE  // needed for getentropy() on Linux.
#endif

#include <openssl/rand.h>

#include "internal.h"

#if defined(OPENSSL_RAND_GETENTROPY)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(OPENSSL_MACOS)
#include <sys/random.h>
#endif

#include "../delocate.h"

// fill_with_entropy writes |len| bytes of entropy into |out| using
// getentropy(). On some platforms it may block until the system entropy pool
// is ready, after which it will not block. It will abort if getentropy() fails.
static void fill_with_entropy(uint8_t *out, size_t len) {
  if (len == 0) {
    return;
  }

  while (len > 0) {
    ssize_t r;
    // |getentropy| can only request 256 bytes at a time.
    size_t todo = len <= 256 ? len : 256;
    r = getentropy(out, todo) != 0 ? -1 : (ssize_t)todo;

    if (r <= 0) {
      perror("getentropy() failed");
      abort();
    }
    out += r;
    len -= r;
  }

}

DEFINE_STATIC_ONCE(wait_for_entropy_once)

// Some platforms may have getentropy() block when the system is first booted
// until the entropy pool is ready. After that point it will not block.
static void wait_for_entropy(void) {
  uint8_t buf[256];
  fill_with_entropy(buf, sizeof(buf));
}

void CRYPTO_init_sysrand(void) {
  CRYPTO_once(wait_for_entropy_once_bss_get(), wait_for_entropy);
}

// CRYPTO_sysrand puts |requested| random bytes into |out|.
void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  fill_with_entropy(out, requested);
}

void CRYPTO_sysrand_for_seed(uint8_t *out, size_t requested) {
  CRYPTO_sysrand(out, requested);
}

#endif  // OPENSSL_RAND_GETENTROPY
