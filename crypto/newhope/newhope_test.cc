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

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "../test/scoped_types.h"
#include "internal.h"

/* Set to 1 for quick execution.  Tested up to 1,000,000. */
#define NTESTS 1

static bool test_keys(void) {
  ScopedNEWHOPE_POLY sk(NEWHOPE_POLY_new());
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];

  /* Alice generates a public key */
  NEWHOPE_offer(offermsg, sk.get());

  /* Bob derives a secret key and creates a response */
  if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
    fprintf(stderr, "ERROR accept key exchange failed\n");
    return false;
  }

  /* Alice uses Bob's response to get her secret key */
  if (!NEWHOPE_finish(offer_key, sk.get(), acceptmsg, sizeof(acceptmsg))) {
    fprintf(stderr, "ERROR finish key exchange failed\n");
    return false;
  }

  if (memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "ERROR keys did not agree\n");
    return false;
  }

  return true;
}

static bool test_invalid_sk(void) {
  ScopedNEWHOPE_POLY sk(NEWHOPE_POLY_new());
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];

  /* Alice generates a public key */
  NEWHOPE_offer(offermsg, sk.get());

  /* Bob derives a secret key and creates a response */
  if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
    fprintf(stderr, "ERROR accept key exchange failed\n");
    return false;
  }

  /* Corrupt the secret key.  It turns out that you need to corrupt a lot of
   * bits to ensure that the key exchange always fails! */
  sk->coeffs[PARAM_N - 1] = 0;
  sk->coeffs[PARAM_N - 2] = 0;
  sk->coeffs[PARAM_N - 3] = 0;
  sk->coeffs[PARAM_N - 4] = 0;

  /* Alice uses Bob's response to get her secret key */
  if (!NEWHOPE_finish(offer_key, sk.get(), acceptmsg, sizeof(acceptmsg))) {
    fprintf(stderr, "ERROR finish key exchange failed\n");
    return false;
  }

  if (memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH) == 0) {
    fprintf(stderr, "ERROR keys agreed despite corrupt sk\n");
    return false;
  }

  return true;
}

static bool test_invalid_acceptmsg(void) {
  ScopedNEWHOPE_POLY sk(NEWHOPE_POLY_new());
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];

  /* Alice generates a public key */
  NEWHOPE_offer(offermsg, sk.get());

  /* Bob derives a secret key and creates a response */
  if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
    fprintf(stderr, "ERROR accept key exchange failed\n");
    return false;
  }

  /* Corrupt the (polynomial part of the) accept message.  It turns out that you
   * need to corrupt a lot of bits to ensure that the key exchange always
   * fails! */
  acceptmsg[PARAM_N - 1] = 0;
  acceptmsg[PARAM_N - 2] = 0;
  acceptmsg[PARAM_N - 3] = 0;
  acceptmsg[PARAM_N - 4] = 0;

  /* Alice uses Bob's response to get her secret key */
  if (!NEWHOPE_finish(offer_key, sk.get(), acceptmsg, sizeof(acceptmsg))) {
    fprintf(stderr, "ERROR finish key exchange failed\n");
    return false;
  }

  if (!memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH)) {
    fprintf(stderr, "ERROR keys agreed despite corrupt accept message\n");
    return false;
  }

  return true;
}

int main(void) {
  int i;
  // Make it easy to run a zillion iterations.
  for (i = 0; i < NTESTS; i++) {
    if (!test_keys() ||
        !test_invalid_sk() ||
        !test_invalid_acceptmsg()) {
      return 1;
    }
  }
  printf("PASS\n");
  return 0;
}
