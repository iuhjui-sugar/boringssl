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


int privacy_pass_client_new(TRUST_TOKEN_CLIENT *ctx, uint16_t max_batchsize);
int privacy_pass_client_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                       size_t *out_len, size_t count);
STACK_OF(TRUST_TOKEN) *
    privacy_pass_client_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                        uint32_t *out_id,
                                        const uint8_t *response,
                                        size_t response_len);
int privacy_pass_client_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                         size_t *out_len,
                                         const TRUST_TOKEN *token);

int privacy_pass_issuer_new(TRUST_TOKEN_ISSUER *ctx, uint16_t max_batchsize);
int privacy_pass_issuer_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                     uint8_t public_metadata,
                                     uint8_t private_metadata);
int privacy_pass_issuer_get_public(TRUST_TOKEN_ISSUER *ctx, uint32_t *out,
                                   uint8_t public_metadata);
int privacy_pass_issuer_issue(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, uint8_t *out_tokens_issued,
                              const uint8_t *request, size_t request_len,
                              size_t max_issuance);
int privacy_pass_issuer_redeem(TRUST_TOKEN_ISSUER *ctx, int *result,
                               TRUST_TOKEN **out_token,
                               uint8_t *out_public_metadata,
                               int *out_private_metadata,
                               const uint8_t *request, size_t request_len);

struct privacy_pass_client_key_st {
  uint32_t id;
  EC_POINT *pub0;
  EC_POINT *pub1;
  EC_POINT *pubs;
};

struct privacy_pass_issuer_key_st {
  uint32_t id;
  EC_SCALAR x0;
  EC_SCALAR y0;
  EC_SCALAR x1;
  EC_SCALAR y1;
  EC_SCALAR xs;
  EC_SCALAR ys;
};

typedef struct privacy_pass_pretoken_st {
  uint8_t t[8];
  EC_SCALAR r;
  EC_RAW_POINT T;
  EC_RAW_POINT Tp;
  uint32_t value;
} PRIVACY_PASS_PRETOKEN;

DEFINE_STACK_OF(PRIVACY_PASS_PRETOKEN)

struct trust_token_client_st {
  EC_GROUP *group;
  uint16_t max_batchsize;
  struct privacy_pass_client_key_st keys[3];
  uint8_t key_index;
  uint32_t a;

  STACK_OF(PRIVACY_PASS_PRETOKEN) *pretokens;

  EVP_PKEY *srr_key;
};


struct trust_token_issuer_st {
  EC_GROUP *group;
  uint16_t max_batchsize;
  struct privacy_pass_issuer_key_st keys[3];
  uint8_t key_index;
  uint32_t a;
  uint8_t public_metadata;
  uint8_t private_metadata;

  EVP_PKEY *srr_key;
  const uint8_t *metadata_key;
  size_t metadata_key_len;
};

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
