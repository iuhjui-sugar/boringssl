/* Copyright (c) 2020, Google Inc.
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

#include <openssl/ctrdrbg.h>

#include "../fipsmodule/rand/internal.h"

#if defined(BORINGSSL_FIPS)

#define ENTROPY_READ_LEN \
  (/* last_block size */ 16 + CTR_DRBG_ENTROPY_LEN * BORINGSSL_FIPS_OVERREAD)

#if defined(OPENSSL_ANDROID)

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

static int get_seed_from_daemon(uint8_t *out_entropy, size_t out_entropy_len) {
  uint8_t buffer[ENTROPY_READ_LEN];
  if (out_entropy_len > sizeof(buffer)) {
    return 0;
  }

  const int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    return 0;
  }

  int ret = 0;
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  static const char kSocketPath[] = "/dev/socket/prng_seeder";
  OPENSSL_memcpy(sun.sun_path, kSocketPath, sizeof(kSocketPath));

  if (connect(sock, (struct sockaddr *)&sun, sizeof(sun))) {
    goto out;
  }

  ssize_t n;
  do {
    n = read(sock, buffer, sizeof(buffer));
  } while (n == -1 && errno == EINTR);

  if (n < out_entropy_len) {
    goto out;
  }

  assert(out_entropy_len <= sizeof(buffer));
  OPENSSL_memcpy(out_entropy, buffer, out_entropy_len);
  ret = 1;

out:
  close(sock);
  return ret;
}

#else

static int get_seed_from_daemon(uint8_t *out_entropy, size_t out_entropy_len) {
  return 0;
}

#endif  // OPENSSL_ANDROID

// RAND_need_entropy is called by the FIPS module when it has blocked because of
// a lack of entropy. This signal is used as an indication to feed it more.
void RAND_need_entropy(size_t bytes_needed) {
  uint8_t buf[ENTROPY_READ_LEN];
  size_t todo = sizeof(buf);
  if (todo > bytes_needed) {
    todo = bytes_needed;
  }

  int want_additional_input;
  if (get_seed_from_daemon(buf, todo)) {
    want_additional_input = 1;
  } else {
    CRYPTO_get_seed_entropy(buf, todo, &want_additional_input);
  }

  if (boringssl_fips_break_test("CRNG")) {
    // This breaks the "continuous random number generator test" defined in FIPS
    // 140-2, section 4.9.2, and implemented in |rand_get_seed|.
    OPENSSL_memset(buf, 0, todo);
  }

  RAND_load_entropy(buf, todo, want_additional_input);
}

#endif  // FIPS
