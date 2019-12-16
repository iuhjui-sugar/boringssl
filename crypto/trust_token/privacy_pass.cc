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

struct pp_ctx_st {
  // aux
  uint16_t ciphersuite;
  uint16_t max_batchsize;
  // keys
  uint32_t a;
};

typedef pp_ctx_st PP_CTX;

static bool privacy_pass_new_client(TT_CTX *ctx) {
  ctx->protocol = (PP_CTX *)OPENSSL_malloc(sizeof(PP_CTX));
  //PP_CTX *cctx = (PP_CTX*)ctx->protocol;
  // TODO: Make public_keys map.
  return true;
}

static bool privacy_pass_new_issuer(TT_CTX *ctx) {
  ctx->protocol = (PP_CTX *)OPENSSL_malloc(sizeof(PP_CTX));
  return true;
}

static void privacy_pass_free(TT_CTX *ctx) {
  OPENSSL_free(ctx->protocol);
}

static bool privacy_pass_client_begin_issuance(TT_CTX *ctx, uint8_t **out,
                                               size_t *out_len, size_t count) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u8(&request, 1) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }
  for (size_t i = 0; i < count; i++) {

    // Random point
    // VOPRF_Blind(x)
    // Add to CBB.

    if (!CBB_add_u32(&request, i * cctx->a)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return false;
    }
  }

  return CBB_finish(&request, out, out_len);
}

static bool privacy_pass_issuer_set_metadata(TT_CTX *ctx,
                                             uint8_t public_metadata,
                                             bool private_metadata) {
  if (public_metadata > 3) {
    return false;
  }
  return true;
}

static bool privacy_pass_issuer_do_issuance(TT_CTX *ctx, uint8_t **out,
                                            size_t *out_len,
                                            const CBS request) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

  CBS in(request);
  uint8_t type;
  if (!CBS_get_u8(&in, &type)) {
    return false;
  }

  CBB response;
  if (!CBB_init(&response, 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }

  uint16_t count = 8;
  if (type == 0) {
    count = 1;

    // VOPRF_Eval
  } else if (type == 1) {
    if (!CBS_get_u16(&in, &count) ||
        !CBB_add_u16(&response, count)) {
      return false;
    }

    // Batch Eval
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

static bool privacy_pass_client_finish_issuance(
    TT_CTX *ctx, STACK_OF(TRUST_TOKEN) * *out_tokens, const CBS response) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

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

static bool privacy_pass_client_begin_redemption(TT_CTX *ctx, uint8_t **out,
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

static bool privacy_pass_issuer_do_redemption(TT_CTX *ctx, bool *result,
                                              const CBS request) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

  CBS in(request);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return false;
  }

  *result = (token % cctx->a == 0);
  return CBS_len(&in) == 0;
}

static const TRUST_TOKEN_METHOD kPrivacyPassTrustTokenMethod = {
    privacy_pass_new_client,
    privacy_pass_new_issuer,
    privacy_pass_free,
    privacy_pass_client_begin_issuance,
    privacy_pass_issuer_do_issuance,
    privacy_pass_client_finish_issuance,
    privacy_pass_client_begin_redemption,
    privacy_pass_issuer_set_metadata,
    privacy_pass_issuer_do_redemption,
};

static const TRUST_TOKEN_METHOD *TRUST_TOKEN_PrivacyPassProtocol(void) {
  return &kPrivacyPassTrustTokenMethod;
}

bool TRUST_TOKEN_privacy_pass_init_key(
    uint8_t **out_priv_key, size_t *out_priv_key_len,
    uint8_t **out_pub_key, size_t *out_pub_key_len,
    uint16_t version) {
  EC_KEY *key = VOPRF_Setup(0x4242);
  CBB cbb;
  if (!CBB_init(&cbb, 0) ||
      !EC_KEY_marshal_private_key(&cbb, key, EC_KEY_get_enc_flags(key)) ||
      !CBB_finish(&cbb, out_priv_key, out_priv_key_len)) {
    return false;
  }

  uint8_t *pub = nullptr;
  size_t pub_len =
      EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &pub, nullptr);

  // TODO: Add expiry and signature.
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_u16(&cbb, version) ||
      !CBB_add_u16(&cbb, pub_len) ||
      !CBB_add_bytes(&cbb, pub, pub_len) ||
      !CBB_finish(&cbb, out_pub_key, out_pub_key_len)) {
    return false;
  }
  OPENSSL_free(pub);
  return true;
}

// bool TRUST_TOKEN_privacy_pass_init_private_metadata_key(
//     uint8_t **out_priv_key, size_t *out_priv_key_len,
//     uint8_t **out_pub_key, size_t *out_pub_key_len,
//     uint16_t version);


TT_CTX *TRUST_TOKEN_privacy_pass_init_client(uint16_t max_batchsize) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_PrivacyPassProtocol();
  if (!ret->method->tt_new_client(ret)) {
    return nullptr;
  }
  PP_CTX *cctx = (PP_CTX*)ret->protocol;
  cctx->max_batchsize = max_batchsize;
  return ret;
}

bool TRUST_TOKEN_privacy_pass_client_add_key(TT_CTX *ctx, const CBS key) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

  CBS cbs(key);
  uint16_t version, y_len;
  if (!CBS_get_u16(&cbs, &version) ||
      !CBS_get_u16(&cbs, &y_len)) {
    return false;
  }
  // TODO: Add key to TT_CTX->P_CTX
  cctx->a = 17;
  return true;
}

TT_CTX *TRUST_TOKEN_privacy_pass_init_issuer(uint16_t max_batchsize) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_PrivacyPassProtocol();
  if (!ret->method->tt_new_issuer(ret)) {
    return nullptr;
  }
  PP_CTX *cctx = (PP_CTX*)ret->protocol;
  cctx->max_batchsize = max_batchsize;
  return ret;
}

bool TRUST_TOKEN_privacy_pass_issuer_add_key(TT_CTX *ctx, const CBS key) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;
  // TODO: Add key to TT_CTX->P_CTX
  cctx->a = 17;
  return true;
}
