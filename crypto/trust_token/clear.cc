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

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/trust_token.h>

#include "internal.h"

struct clear_ctx_st {
  uint32_t a;
};

typedef clear_ctx_st CLEAR_CTX;

static int clear_init_client(TRUST_TOKEN_CLIENT *ctx) {
  ctx->protocol = (CLEAR_CTX *)OPENSSL_malloc(sizeof(CLEAR_CTX));
  return 1;
}

static int clear_init_issuer(TRUST_TOKEN_ISSUER *ctx) {
  ctx->protocol = (CLEAR_CTX *)OPENSSL_malloc(sizeof(CLEAR_CTX));
  return 1;
}

static void clear_free_client(TRUST_TOKEN_CLIENT *ctx) {
  OPENSSL_free(ctx->protocol);
}

static void clear_free_issuer(TRUST_TOKEN_ISSUER *ctx) {
  OPENSSL_free(ctx->protocol);
}

static int clear_client_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                       size_t *out_len, size_t count) {
  CLEAR_CTX *cctx = (CLEAR_CTX *)ctx->protocol;

  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  for (size_t i = 0; i < count; i++) {
    if (!CBB_add_u32(&request, i * cctx->a)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }

  return CBB_finish(&request, out, out_len);
}

static int clear_issuer_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                     uint8_t public_metadata,
                                     int private_metadata) {
  return 0;
}

static int clear_issuer_issue(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, const CBS request) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(request);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return 0;
  }

  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u16(&response, count)) {
    return 0;
  }
  for (size_t i = 0; i < count; i++) {
    uint32_t btoken;
    if (!CBS_get_u32(&in, &btoken) ||
        !CBB_add_u32(&response, btoken * cctx->a)) {
      return 0;
    }
  }

  if (CBS_len(&in) != 0) {
    return 0;
  }
  return CBB_finish(&response, out, out_len);
}

static STACK_OF(TRUST_TOKEN) *
    clear_client_finish_issuance(TRUST_TOKEN_CLIENT *ctx, const CBS response) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(response);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return NULL;
  }

  STACK_OF(TRUST_TOKEN) *tokens = sk_TRUST_TOKEN_new_null();
  for (size_t i = 0; i < count; i++) {
    uint32_t bstoken;
    if (!CBS_get_u32(&in, &bstoken)) {
     return NULL;
    }
    uint32_t token = bstoken / cctx->a;
    TRUST_TOKEN *atoken = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
    atoken->data = (uint8_t *)OPENSSL_malloc(2);
    atoken->data[0] = token>>8;
    atoken->data[1] = token;
    atoken->len = 2;
    if (!sk_TRUST_TOKEN_push(tokens, atoken)) {
      return NULL;
    }
  }

  return tokens;
}

static int clear_client_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                         size_t *out_len,
                                         const TRUST_TOKEN *token) {
  if (token->len != 2) {
    return 0;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u32(&request, token->data[0]<<8|token->data[1])) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  return CBB_finish(&request, out, out_len);
}

static int clear_issuer_redeem(TRUST_TOKEN_ISSUER *ctx, int *result,
                               const CBS request) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(request);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return 0;
  }

  *result = (token % cctx->a == 0);
  return 1;
}

static const TRUST_TOKEN_CLIENT_METHOD kClearTrustTokenClientMethod = {
    clear_init_client,
    clear_free_client,
    clear_client_begin_issuance,
    clear_client_finish_issuance,
    clear_client_begin_redemption,
};

static const TRUST_TOKEN_ISSUER_METHOD kClearTrustTokenIssuerMethod = {
    clear_init_issuer,
    clear_free_issuer,
    clear_issuer_set_metadata,
    clear_issuer_issue,
    clear_issuer_redeem
};

TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new_clear(uint32_t public_key) {
  TRUST_TOKEN_CLIENT *ret = (TRUST_TOKEN_CLIENT *)OPENSSL_malloc(sizeof(TRUST_TOKEN_CLIENT));
  ret->method = &kClearTrustTokenClientMethod;
  if (!ret->method->init(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = public_key;
  return ret;
}

TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new_clear(uint32_t private_key) {
  TRUST_TOKEN_ISSUER *ret = (TRUST_TOKEN_ISSUER *)OPENSSL_malloc(sizeof(TRUST_TOKEN_ISSUER));
  ret->method = &kClearTrustTokenIssuerMethod;
  if (!ret->method->init(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = private_key;
  return ret;
}
