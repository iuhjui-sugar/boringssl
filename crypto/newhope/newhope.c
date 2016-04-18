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

#include <string.h>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"

NEWHOPE_POLY* NEWHOPE_POLY_new(void) {
  return (NEWHOPE_POLY*)OPENSSL_malloc(sizeof(NEWHOPE_POLY));
}

void NEWHOPE_POLY_free(NEWHOPE_POLY* p) { OPENSSL_free(p); }

/* Encodes reconciliation data from |c| into |r|. */
static void encode_rec(const NEWHOPE_POLY* c, uint8_t* r) {
  int i;
  for (i = 0; i < PARAM_N / 4; i++) {
    r[i] = c->coeffs[4 * i] | (c->coeffs[4 * i + 1] << 2) |
           (c->coeffs[4 * i + 2] << 4) | (c->coeffs[4 * i + 3] << 6);
  }
}

/* Decodes reconciliation data from |r| into |c|. */
static void decode_rec(const uint8_t* r, NEWHOPE_POLY* c) {
  int i;
  for (i = 0; i < PARAM_N / 4; i++) {
    c->coeffs[4 * i + 0] = r[i] & 0x03;
    c->coeffs[4 * i + 1] = (r[i] >> 2) & 0x03;
    c->coeffs[4 * i + 2] = (r[i] >> 4) & 0x03;
    c->coeffs[4 * i + 3] = (r[i] >> 6);
  }
}

void NEWHOPE_keygen(uint8_t* servermsg, NEWHOPE_POLY* sk) {
  poly_getnoise(sk);
  poly_ntt(sk);

  // The first part of the server's message is the seed, which compactly encodes
  // a.
  NEWHOPE_POLY a;
  uint8_t* seed = &servermsg[POLY_BYTES];
  RAND_bytes(seed, SEED_LENGTH);
  poly_uniform(&a, seed);

  NEWHOPE_POLY e;
  poly_getnoise(&e);
  poly_ntt(&e);

  // The second part of the server's message is the polynomial pk = a * sk + e
  NEWHOPE_POLY r, pk;
  poly_pointwise(&r, sk, &a);
  poly_add(&pk, &e, &r);
  poly_tobytes(servermsg, &pk);
}

void NEWHOPE_client_compute_key(uint8_t* key, uint8_t* clientmsg,
                                const uint8_t* servermsg) {
  // Generate the same |a| as the server, from the server's seed.
  NEWHOPE_POLY a;
  const uint8_t* seed = &servermsg[POLY_BYTES];
  poly_uniform(&a, seed);

  NEWHOPE_POLY pk;
  poly_frombytes(&pk, servermsg);

  NEWHOPE_POLY sp;
  poly_getnoise(&sp);
  poly_ntt(&sp);

  NEWHOPE_POLY ep;
  poly_getnoise(&ep);
  poly_ntt(&ep);

  NEWHOPE_POLY epp;
  poly_getnoise(&epp);

  // The first part of the client's message is the polynomial bp = e' + a * s'
  NEWHOPE_POLY bp;
  poly_pointwise(&bp, &a, &sp);
  poly_add(&bp, &bp, &ep);
  poly_tobytes(clientmsg, &bp);

  // v = pk * s' + e''
  NEWHOPE_POLY v;
  poly_pointwise(&v, &pk, &sp);
  poly_invntt(&v);
  poly_add(&v, &v, &epp);

  // The second part of the client's message is the reconciliation data derived
  // from v.
  NEWHOPE_POLY c;
  uint8_t* reconciliation = &clientmsg[POLY_BYTES];
  helprec(&c, &v);
  encode_rec(&c, reconciliation);

  uint8_t k[KEY_LENGTH];
  reconcile(k, &v, &c);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, k, KEY_LENGTH);
  SHA256_Final(key, &ctx);
}

void NEWHOPE_server_compute_key(uint8_t* key, const NEWHOPE_POLY* sk,
                                const uint8_t* clientmsg) {
  NEWHOPE_POLY bp;
  poly_frombytes(&bp, clientmsg);

  NEWHOPE_POLY v;
  poly_pointwise(&v, sk, &bp);
  poly_invntt(&v);

  NEWHOPE_POLY c;
  const uint8_t* reconciliation = &clientmsg[POLY_BYTES];
  decode_rec(reconciliation, &c);

  uint8_t k[KEY_LENGTH];
  reconcile(k, &v, &c);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, k, KEY_LENGTH);
  SHA256_Final(key, &ctx);
}
