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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

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

static bool clear_client_begin_issuance(TT_CTX *ctx, std::vector<uint8_t> *out, size_t count) {
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
  printf("Clear issuance begin.\n");

  uint8_t *der;
  size_t der_len;
  if (!CBB_finish(&request, &der, &der_len)) {
    return false;
  }
  out->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

static bool clear_issuer_do_issuance(TT_CTX *ctx, std::vector<uint8_t> *out, const std::vector<uint8_t> request) {
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
    printf("Saw blinded token %d and signed to %d.\n", btoken, btoken * cctx->a);
  }
  printf("Clear issuance do for %d tokens.\n", count);

  uint8_t *der;
  size_t der_len;
  if (CBS_len(&in) != 0 ||
      !CBB_finish(&response, &der, &der_len)) {
    return false;
  }
  OPENSSL_free(der);
  out->assign(der, der + der_len);
  return true;
}
static bool clear_client_finish_issuance(TT_CTX *ctx, std::vector<TRUST_TOKEN *> *tokens, const std::vector<uint8_t> response) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(response);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return false;
  }

  for (size_t i = 0; i < count; i++) {
    uint32_t bstoken;
    if (!CBS_get_u32(&in, &bstoken)) {
      return false;
    }
    uint32_t token = bstoken / cctx->a;
    printf("Signed Token: %d\n", token);
    TRUST_TOKEN *atoken = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
    atoken->data = token;
    tokens->push_back(atoken);
  }
  printf("Clear issuance finish.\n");
  return true;
}

static bool clear_client_begin_redemption(TT_CTX *ctx, std::vector<uint8_t> *out, const TRUST_TOKEN *token) {
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u32(&request, token->data)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }
  printf("Clear redemption begin.\n");
  uint8_t *der;
  size_t der_len;
  if (!CBB_finish(&request, &der, &der_len)) {
    return false;
  }
  OPENSSL_free(der);
  out->assign(der, der + der_len);
  return true;
}

static bool clear_issuer_do_redemption(TT_CTX *ctx, bool *result, const std::vector<uint8_t> request) {
  CLEAR_CTX *cctx = (CLEAR_CTX*)ctx->protocol;

  CBS in(request);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return false;
  }

  *result = (token % cctx->a == 0);
  printf("Clear redemption do.\n");
  return CBS_len(&in) == 0;
}

static const TRUST_TOKEN_METHOD kClearTrustTokenMethod = {
  clear_new_client,
  clear_new_issuer,
  clear_free,
  clear_client_begin_issuance,
  clear_issuer_do_issuance,
  clear_client_finish_issuance,
  clear_client_begin_redemption,
  clear_issuer_do_redemption,
};

static const TRUST_TOKEN_METHOD *TRUST_TOKEN_ClearProtocol(void) {
  return &kClearTrustTokenMethod;
}

TT_CTX *TRUST_TOKEN_Clear_InitClient(uint32_t public_key) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_ClearProtocol();
  if (!ret->method->tt_new_client(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = public_key;
  return ret;
}

TT_CTX *TRUST_TOKEN_Clear_InitIssuer(uint32_t private_key) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_ClearProtocol();
  if (!ret->method->tt_new_issuer(ret)) {
    return nullptr;
  }
  CLEAR_CTX *cctx = (CLEAR_CTX*)ret->protocol;
  cctx->a = private_key;
  return ret;
}
