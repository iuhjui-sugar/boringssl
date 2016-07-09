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

#define _GNU_SOURCE

#include <openssl/rand.h>

#ifdef OPENSSL_LINUX
#include <sys/syscall.h>
#endif

#if defined(SYS_getrandom) && !defined(OPENSSL_WINDOWS) && \
    !defined(BORINGSSL_UNSAFE_FUZZER_MODE)

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "internal.h"

void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  long orig_errno, r;

  orig_errno = errno;

  while (requested > 0) {
    do {
      r = syscall(SYS_getrandom, out, requested, 0);
    } while (r == -1 && errno == EINTR);

    if (r <= 0) {
      abort();
    }

    out += r;
    requested -= r;
  }

  errno = orig_errno;
}

void RAND_cleanup(void) {}

#endif  /* SYS_getrandom && !OPENSSL_WINDOWS && !BORINGSSL_UNSAFE_FUZZER_MODE */
