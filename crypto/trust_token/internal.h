/* Copyright (c) 2019, Google Inc.
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

#ifndef OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
#define OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>

#include "../fipsmodule/ec/internal.h"

#include <openssl/trust_token.h>

#define PMBTOKEN_NONCE_SIZE 64

typedef struct pmb_pretoken_st {
  uint8_t t[PMBTOKEN_NONCE_SIZE];
  EC_SCALAR r;
  EC_RAW_POINT T;
  EC_RAW_POINT Tp;
} PMBTOKEN_PRETOKEN;

DEFINE_STACK_OF(PMBTOKEN_PRETOKEN)

void PMBTOKEN_PRETOKEN_free(PMBTOKEN_PRETOKEN *token);

typedef struct pmb_token_st {
  uint8_t t[PMBTOKEN_NONCE_SIZE];
  EC_RAW_POINT S;
  EC_RAW_POINT W;
  EC_RAW_POINT Ws;
} PMBTOKEN_TOKEN;

void PMBTOKEN_TOKEN_free(PMBTOKEN_TOKEN *token);

int pmbtoken_blind(TRUST_TOKEN_CLIENT *ctx, PMBTOKEN_PRETOKEN **out_pretoken);
int pmbtoken_sign(TRUST_TOKEN_ISSUER *ctx, uint8_t out_s[PMBTOKEN_NONCE_SIZE],
                  EC_RAW_POINT *out_Wp, EC_RAW_POINT *out_Wsp, EC_RAW_POINT Tp);
int pmbtoken_unblind(TRUST_TOKEN_CLIENT *ctx, PMBTOKEN_TOKEN **out_token,
                     uint8_t s[PMBTOKEN_NONCE_SIZE], EC_RAW_POINT Wp,
                     EC_RAW_POINT Wsp, PMBTOKEN_PRETOKEN *pretoken);
int pmbtoken_read(TRUST_TOKEN_ISSUER *ctx, uint8_t *out_result,
                  uint8_t *out_private_metadata, PMBTOKEN_TOKEN *token,
                  uint8_t public_metadata);

struct trust_token_client_key_st {
  uint32_t id;
  EC_POINT *pub0;
  EC_POINT *pub1;
  EC_POINT *pubs;
};

struct trust_token_issuer_key_st {
  uint32_t id;
  EC_SCALAR x0;
  EC_SCALAR y0;
  EC_SCALAR x1;
  EC_SCALAR y1;
  EC_SCALAR xs;
  EC_SCALAR ys;
};

struct trust_token_client_st {
  EC_GROUP *group;
  uint16_t max_batchsize;
  struct trust_token_client_key_st keys[3];
  uint8_t key_index;
  uint32_t a;

  STACK_OF(PMBTOKEN_PRETOKEN) * pretokens;

  EVP_PKEY *srr_key;
};


struct trust_token_issuer_st {
  EC_GROUP *group;
  uint16_t max_batchsize;
  struct trust_token_issuer_key_st keys[3];
  uint8_t key_index;
  uint32_t a;

  uint8_t public_metadata;
  uint8_t private_metadata;

  EVP_PKEY *srr_key;
  const uint8_t *metadata_key;
  size_t metadata_key_len;
};

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
