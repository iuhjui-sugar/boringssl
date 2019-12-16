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

#include <map>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/trust_token.h>

#include "internal.h"

struct pp_ctx_st {
  // aux
  uint16_t ciphersuite;
  uint16_t max_batchsize;
  std::map<uint16_t, std::vector<uint8_t>*> *public_keys;
  // keys
  uint32_t a;
};

typedef pp_ctx_st PP_CTX;

static bool privacy_pass_new_client(TT_CTX *ctx) {
  ctx->protocol = (PP_CTX *)OPENSSL_malloc(sizeof(PP_CTX));
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;
  cctx->public_keys = (std::map<uint16_t, std::vector<uint8_t>*> *)OPENSSL_malloc(sizeof(std::map<uint16_t, std::vector<uint8_t>*>));
  return true;
}

static bool privacy_pass_new_issuer(TT_CTX *ctx) {
  ctx->protocol = (PP_CTX *)OPENSSL_malloc(sizeof(PP_CTX));
  return true;
}

static void privacy_pass_free(TT_CTX *ctx) {
  OPENSSL_free(ctx->protocol);
}

static bool privacy_pass_client_begin_issuance(TT_CTX *ctx, std::vector<uint8_t> *out, size_t count) {
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

  uint8_t *der;
  size_t der_len;
  if (!CBB_finish(&request, &der, &der_len)) {
    return false;
  }
  out->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

static bool privacy_pass_issuer_do_issuance(TT_CTX *ctx, std::vector<uint8_t> *out, const std::vector<uint8_t> request) {
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
    printf("Saw blinded token %d and signed to %d.\n", btoken, btoken * cctx->a);
  }
  printf("Privacy_Pass issuance do for %d tokens.\n", count);
  uint8_t *der;
  size_t der_len;
  if (CBS_len(&in) != 0 ||
      !CBB_finish(&response, &der, &der_len)) {
    return false;
  }
  out->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

static bool privacy_pass_client_finish_issuance(TT_CTX *ctx, std::vector<TRUST_TOKEN *> *tokens, const std::vector<uint8_t> response) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

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
  printf("Privacy Pass issuance finish.\n");
  return true;
}

static bool privacy_pass_client_begin_redemption(TT_CTX *ctx, std::vector<uint8_t> *out, const TRUST_TOKEN *token) {
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u32(&request, token->data)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return false;
  }
  printf("Privacy Pass redemption begin.\n");
  uint8_t *der;
  size_t der_len;
  if (!CBB_finish(&request, &der, &der_len)) {
    return false;
  }
  out->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

static bool privacy_pass_issuer_do_redemption(TT_CTX *ctx, bool *result, const std::vector<uint8_t> request) {
  PP_CTX *cctx = (PP_CTX*)ctx->protocol;

  CBS in(request);
  uint32_t token;
  if (!CBS_get_u32(&in, &token)) {
    return false;
  }

  *result = (token % cctx->a == 0);
  printf("Privacy Pass redemption do.\n");
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
  privacy_pass_issuer_do_redemption,
};

static const TRUST_TOKEN_METHOD *TRUST_TOKEN_PrivacyPassProtocol(void) {
  return &kPrivacyPassTrustTokenMethod;
}

bool TRUST_TOKEN_PrivacyPass_InitKey(uint16_t ciphersuite,
                                     uint16_t version,
                                     std::vector<uint8_t> *priv_key,
                                     std::vector<uint8_t> *pub_key) {
  bssl::UniquePtr<EC_KEY> key = VOPRF_Setup(ciphersuite);
  bssl::ScopedCBB cbb;
  uint8_t *der;
  size_t der_len;
  if (!CBB_init(cbb.get(), 0) ||
      !EC_KEY_marshal_private_key(cbb.get(), key.get(), EC_KEY_get_enc_flags(key.get())) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  priv_key->assign(der, der + der_len);
  OPENSSL_free(der);

  uint8_t *pub = nullptr;
  size_t pub_len =
      EC_KEY_key2buf(key.get(), POINT_CONVERSION_UNCOMPRESSED, &pub, nullptr);

  // TODO: Add expiry and signature.
  if (!CBB_init(cbb.get(), 0) ||
      !CBB_add_u16(cbb.get(), version) ||
      !CBB_add_u16(cbb.get(), pub_len) ||
      !CBB_add_bytes(cbb.get(), pub, pub_len) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  OPENSSL_free(pub);
  pub_key->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

TT_CTX *TRUST_TOKEN_PrivacyPass_InitClient(
    uint16_t ciphersuite, uint16_t max_batchsize,
    std::vector<std::vector<uint8_t>> public_keys) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_PrivacyPassProtocol();
  if (!ret->method->tt_new_client(ret)) {
    return nullptr;
  }
  PP_CTX *cctx = (PP_CTX*)ret->protocol;
  cctx->ciphersuite = ciphersuite;
  cctx->max_batchsize = max_batchsize;

  for (std::vector<uint8_t> public_key : public_keys) {
    CBS key(public_key);
    uint16_t version, y_len;
    if (!CBS_get_u16(&key, &version) ||
        !CBS_get_u16(&key, &y_len)) {
      return nullptr;
    }
    //std::vector<uint8_t> *y = (std::vector<uint8_t> *)OPENSSL_malloc(sizeof(std::vector<uint8_t>));
    //*y = std::vector<uint8_t>();
    //y->assign(CBS_data(&key), CBS_data(&key) + y_len);
    (*(cctx->public_keys))[version] = nullptr;
    // TODO: Check the expiry and signature.
  }
  cctx->a = 17;
  return ret;
}

TT_CTX *TRUST_TOKEN_PrivacyPass_InitIssuer(uint16_t ciphersuite,
                                           uint16_t max_batchsize,
                                           std::vector<uint8_t> key) {
  TT_CTX *ret = (TT_CTX *)OPENSSL_malloc(sizeof(TT_CTX));
  ret->method = TRUST_TOKEN_PrivacyPassProtocol();
  if (!ret->method->tt_new_issuer(ret)) {
    return nullptr;
  }
  PP_CTX *cctx = (PP_CTX*)ret->protocol;
  cctx->ciphersuite = ciphersuite;
  cctx->max_batchsize = max_batchsize;

  // Store the key to cctx->private_key.
  cctx->a = 42;
  return ret;
}
