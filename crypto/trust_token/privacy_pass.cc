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

struct privacy_pass_key_st {
  uint32_t id;
};

struct privacy_pass_ctx_st {
  // aux
  uint16_t ciphersuite;
  uint16_t max_batchsize;
  privacy_pass_key_st keys[3];
  uint32_t a;
};

typedef privacy_pass_ctx_st PRIVACY_PASS_CTX;

static int privacy_pass_client_new(TRUST_TOKEN_CLIENT *ctx) {
  ctx->protocol = (PRIVACY_PASS_CTX *)OPENSSL_malloc(sizeof(PRIVACY_PASS_CTX));
  // TODO: Make public_keys map.
  return 1;
}

static int privacy_pass_issuer_new(TRUST_TOKEN_ISSUER *ctx) {
  ctx->protocol = (PRIVACY_PASS_CTX *)OPENSSL_malloc(sizeof(PRIVACY_PASS_CTX));
  return 1;
}

static void privacy_pass_client_free(TRUST_TOKEN_CLIENT *ctx) {
  OPENSSL_free(ctx->protocol);
}

static void privacy_pass_issuer_free(TRUST_TOKEN_ISSUER *ctx) {
  OPENSSL_free(ctx->protocol);
}

static int privacy_pass_client_begin_issuance(TRUST_TOKEN_CLIENT *ctx,
                                              uint8_t **out, size_t *out_len,
                                              size_t count) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX *)ctx->protocol;

  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u8(&request, 1) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  for (size_t i = 0; i < count; i++) {

    // Random point
    // VOPRF_Blind(x)
    // Add to CBB.

    if (!CBB_add_u32(&request, i * cctx->a)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }

  return CBB_finish(&request, out, out_len);
}

static int privacy_pass_issuer_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                            uint8_t public_metadata,
                                            int private_metadata) {
  if (public_metadata > 3) {
    return 0;
  }
  return 1;
}

static int privacy_pass_issuer_get_public(TRUST_TOKEN_ISSUER *ctx, uint8_t **out, size_t *out_len, uint8_t public_metadata) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;

  uint8_t *ret = (uint8_t *)OPENSSL_malloc(4);
  if (ret == NULL) {
    return 0;
  }
  ret[0] = cctx->keys[public_metadata].id>>24;
  ret[1] = cctx->keys[public_metadata].id>>16;
  ret[2] = cctx->keys[public_metadata].id>>8;
  ret[3] = cctx->keys[public_metadata].id;
  *out = ret;
  *out_len = 4;
  return 1;
}

static int privacy_pass_issuer_issue(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                                     size_t *out_len, const uint8_t *request,
                                     size_t request_len) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;

  CBS in;
  CBS_init(&in, request, request_len);
  uint8_t type;
  if (!CBS_get_u8(&in, &type)) {
    return 0;
  }

  CBB response;
  if (!CBB_init(&response, 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  uint16_t count = 8;
  if (type == 0) {
    count = 1;

    // VOPRF_Eval
  } else if (type == 1) {
    if (!CBS_get_u16(&in, &count) ||
        !CBB_add_u16(&response, count)) {
      return 0;
    }

    // Batch Eval
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
    privacy_pass_client_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                        uint32_t *out_id,
                                        const uint8_t *response,
                                        size_t response_len) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;

  CBS in;
  CBS_init(&in, response, response_len);
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    return NULL;
  }
  *out_id = 1;
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

static int privacy_pass_client_begin_redemption(TRUST_TOKEN_CLIENT *ctx,
                                                uint8_t **out, size_t *out_len,
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

static int privacy_pass_issuer_redeem(TRUST_TOKEN_ISSUER *ctx, int *result,
                                      TRUST_TOKEN **out_token,
                                      uint8_t *out_public_metadata,
                                      int *out_private_metadata,
                                      const uint8_t *request,
                                      size_t request_len) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;

  CBS in;
  CBS_init(&in, request, request_len);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return 0;
  }

  TRUST_TOKEN *ret_token = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
  if (ret_token == NULL) {
    return 0;
  }
  ret_token->data = (uint8_t *)OPENSSL_malloc(4);
  if (ret_token->data == NULL) {
    return 0;
  }
  ret_token->data[0] = token >> 24;
  ret_token->data[1] = token >> 16;
  ret_token->data[2] = token >> 8;
  ret_token->data[3] = token >> 0;
  ret_token->len = 4;
  *out_token = ret_token;
  *result = (token % cctx->a == 0);
  return CBS_len(&in) == 0;
}

int TRUST_TOKEN_generate_key(uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  EC_KEY *key = VOPRF_Setup(0x4242);
  CBB cbb;
  if (!CBB_init_fixed(&cbb, out_priv_key, max_priv_key_len) ||
      !EC_KEY_marshal_private_key(&cbb, key, EC_KEY_get_enc_flags(key)) ||
      !CBB_finish(&cbb, NULL, out_priv_key_len)) {
    return false;
  }

  uint8_t *pub = nullptr;
  size_t pub_len =
      EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &pub, nullptr);

  if (!CBB_init_fixed(&cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&cbb, id) ||
      !CBB_add_u16(&cbb, pub_len) ||
      !CBB_add_bytes(&cbb, pub, pub_len) ||
      !CBB_finish(&cbb, NULL, out_pub_key_len)) {
    return false;
  }
  OPENSSL_free(pub);
  return true;
}

static const TRUST_TOKEN_CLIENT_METHOD kPrivacy_PassTrustTokenClientMethod = {
    privacy_pass_client_new,
    privacy_pass_client_free,
    privacy_pass_client_begin_issuance,
    privacy_pass_client_finish_issuance,
    privacy_pass_client_begin_redemption,
};

static const TRUST_TOKEN_ISSUER_METHOD kPrivacy_PassTrustTokenIssuerMethod = {
    privacy_pass_issuer_new,
    privacy_pass_issuer_free,
    privacy_pass_issuer_set_metadata,
    privacy_pass_issuer_get_public,
    privacy_pass_issuer_issue,
    privacy_pass_issuer_redeem
};

TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(uint16_t max_batchsize) {
  TRUST_TOKEN_CLIENT *ret =
      (TRUST_TOKEN_CLIENT *)OPENSSL_malloc(sizeof(TRUST_TOKEN_CLIENT));
  ret->method = &kPrivacy_PassTrustTokenClientMethod;
  if (!ret->method->new_client(ret)) {
    return nullptr;
  }
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX *)ret->protocol;
  cctx->max_batchsize = max_batchsize;
  return ret;
}

int TRUST_TOKEN_CLIENT_add_key(TRUST_TOKEN_CLIENT *ctx, uint32_t id,
                               const uint8_t *key, size_t key_len) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;

  CBS cbs;
  CBS_init(&cbs, key, key_len);
  uint16_t kid, y_len;
  if (!CBS_get_u16(&cbs, &kid) ||
      !CBS_get_u16(&cbs, &y_len)) {
    return 0;
  }
  // TODO: Add key to TT_CTX->P_CTX
  cctx->a = 17;
  return 1;
}

TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(uint16_t max_batchsize) {
  TRUST_TOKEN_ISSUER *ret =
      (TRUST_TOKEN_ISSUER *)OPENSSL_malloc(sizeof(TRUST_TOKEN_ISSUER));
  ret->method = &kPrivacy_PassTrustTokenIssuerMethod;
  if (!ret->method->new_issuer(ret)) {
    return nullptr;
  }
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ret->protocol;
  cctx->max_batchsize = max_batchsize;
  return ret;
}

int TRUST_TOKEN_ISSUER_add_key(TRUST_TOKEN_ISSUER *ctx, uint32_t id,
                               const uint8_t *key, size_t key_len) {
  PRIVACY_PASS_CTX *cctx = (PRIVACY_PASS_CTX*)ctx->protocol;
  // TODO: Add key to TT_CTX->P_CTX
  cctx->a = 17;
  return 1;
}
