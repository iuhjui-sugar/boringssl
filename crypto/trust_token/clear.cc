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

static bool clear_new_client(TT_CTX *ctx) {
  ctx->protocol = (CLEAR_CTX *)OPENSSL_malloc(sizeof(CLEAR_CTX));
  return true;
}

static bool clear_new_issuer(TT_CTX *ctx) {
  ctx->protocol = (CLEAR_CTX *)OPENSSL_malloc(sizeof(CLEAR_CTX));
  return true;
}

static void clear_free(TT_CTX *ctx) {
  OPENSSL_free(ctx->protocol);
}

static bool clear_client_begin_issuance(TT_CTX *ctx, uint8_t **out,
                                        size_t *out_len, size_t count) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    if (!CBB_add_u32(&request, i * cctx->a)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return false;
    }
  }

  return CBB_finish(&request, out, out_len);
}

static bool clear_issuer_do_issuance(TT_CTX *ctx, uint8_t **out,
                                     size_t *out_len, const CBS request) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(request);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return false;
  }

  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u16(&response, count)) {
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    uint32_t btoken;
    if (!CBS_get_u32(&in, &btoken) ||
        !CBB_add_u32(&response, btoken * cctx->a)) {
      return false;
    }
  }

  if (CBS_len(&in) != 0) {
    return false;
  }
  return CBB_finish(&response, out, out_len);
}

static bool clear_client_finish_issuance(TT_CTX *ctx,
                                         STACK_OF(TRUST_TOKEN) **out_tokens,
                                         const CBS response) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(response);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return false;
  }

  STACK_OF(TRUST_TOKEN) *tokens = sk_TRUST_TOKEN_new_null();
  for (size_t i = 0; i < count; i++) {
    uint32_t bstoken;
    if (!CBS_get_u32(&in, &bstoken)) {
     return false;
    }
    uint32_t token = bstoken / cctx->a;
    TRUST_TOKEN *atoken = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
    atoken->data = (uint8_t *)OPENSSL_malloc(2);
    atoken->data[0] = token>>8;
    atoken->data[1] = token;
    atoken->len = 2;
    if (!sk_TRUST_TOKEN_push(tokens, atoken)) {
      return false;
    }
  }

  *out_tokens = tokens;
  return true;
}

static bool clear_client_begin_redemption(TT_CTX *ctx, uint8_t **out,
                                          size_t *out_len,
                                          const TRUST_TOKEN *token) {
  if (token->len != 2) {
    return false;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u32(&request, token->data[0]<<8|token->data[1])) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }

  return CBB_finish(&request, out, out_len);
}

static bool clear_issuer_set_metadata(TT_CTX *ctx, uint8_t public_metadata,
                                      bool private_metadata) {
  return false;
}

static bool clear_issuer_do_redemption(TT_CTX *ctx, bool *result,
                                       const CBS request) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(request);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return false;
  }

  *result = (token % cctx->a == 0);
  return true;
}

static const TRUST_TOKEN_METHOD kClearTrustTokenMethod = {
    clear_new_client,
    clear_new_issuer,
    clear_free,
    clear_client_begin_issuance,
    clear_issuer_do_issuance,
    clear_client_finish_issuance,
    clear_client_begin_redemption,
    clear_issuer_set_metadata,
    clear_issuer_do_redemption,
};

static const TRUST_TOKEN_METHOD *TRUST_TOKEN_ClearProtocol(void) {
  return &kClearTrustTokenMethod;
}

TT_CTX *TRUST_TOKEN_clear_init_client(uint32_t public_key) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_ClearProtocol();
  if (!ret->method->tt_new_client(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = public_key;
  return ret;
}

TT_CTX *TRUST_TOKEN_clear_init_issuer(uint32_t private_key) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_ClearProtocol();
  if (!ret->method->tt_new_issuer(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = private_key;
  return ret;
}
