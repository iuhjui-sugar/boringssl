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

#include <openssl/crypto.h>

#include "../internal.h"
#include "delocate.h"


int FIPS_mode(void) {
#if defined(BORINGSSL_FIPS) && !defined(OPENSSL_ASAN)
  return 1;
#else
  return 0;
#endif
}

int FIPS_mode_set(int on) { return on == FIPS_mode(); }

typedef CRYPTO_refcount_t counters_array_t[fips_counter_max + 1];
DEFINE_BSS_GET(counters_array_t, counters_array);

size_t FIPS_read_counter(enum fips_counter_t counter) {
  if (0 <= counter && counter <= fips_counter_max) {
    return (*counters_array_bss_get())[counter];
  }

  abort();
}

void boringssl_fips_inc_counter(enum fips_counter_t counter) {
  if (0 <= counter && counter <= fips_counter_max) {
    CRYPTO_refcount_inc(&(*counters_array_bss_get())[counter]);
    return;
  }

  abort();
}
