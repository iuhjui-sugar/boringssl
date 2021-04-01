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
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/trust_token.h>

#include "internal.h"


// The Trust Token API is described in
// https://github.com/WICG/trust-token-api/blob/master/README.md and provides a
// protocol for issuing and redeeming tokens built on top of the PMBTokens
// construction.

const TRUST_TOKEN_METHOD *TRUST_TOKEN_experiment_v2_voprf(void) {
  static const TRUST_TOKEN_METHOD kMethod = {
      voprf_exp2_generate_key,
      voprf_exp2_client_key_from_bytes,
      voprf_exp2_issuer_key_from_bytes,
      voprf_exp2_blind,
      voprf_exp2_sign,
      voprf_exp2_unblind,
      voprf_exp2_read,
      0, /* has_private_metadata */
      6, /* max_keys */
  };
  return &kMethod;
}

const TRUST_TOKEN_METHOD *TRUST_TOKEN_experiment_v2_pmb(void) {
  static const TRUST_TOKEN_METHOD kMethod = {
      pmbtoken_exp2_generate_key,
      pmbtoken_exp2_client_key_from_bytes,
      pmbtoken_exp2_issuer_key_from_bytes,
      pmbtoken_exp2_blind,
      pmbtoken_exp2_sign,
      pmbtoken_exp2_unblind,
      pmbtoken_exp2_read,
      1, /* has_private_metadata */
      3, /* max_keys */
  };
  return &kMethod;
}

void TRUST_TOKEN_PRETOKEN_free(TRUST_TOKEN_PRETOKEN *pretoken) {
  OPENSSL_free(pretoken);
}

TRUST_TOKEN *TRUST_TOKEN_new(const uint8_t *data, size_t len) {
  TRUST_TOKEN *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN));
  ret->data = OPENSSL_memdup(data, len);
  if (len != 0 && ret->data == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
  }
  ret->len = len;
  return ret;
}

void TRUST_TOKEN_free(TRUST_TOKEN *token) {
  if (token == NULL) {
    return;
  }
  OPENSSL_free(token->data);
  OPENSSL_free(token);
}

int TRUST_TOKEN_generate_key(const TRUST_TOKEN_METHOD *method,
                             uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  // Prepend the key ID in front of the PMBTokens format.
  int ret = 0;
  CBB priv_cbb, pub_cbb;
  CBB_zero(&priv_cbb);
  CBB_zero(&pub_cbb);
  if (!CBB_init_fixed(&priv_cbb, out_priv_key, max_priv_key_len) ||
      !CBB_init_fixed(&pub_cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&priv_cbb, id) ||
      !CBB_add_u32(&pub_cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  if (!method->generate_key(&priv_cbb, &pub_cbb)) {
    goto err;
  }

  if (!CBB_finish(&priv_cbb, NULL, out_priv_key_len) ||
      !CBB_finish(&pub_cbb, NULL, out_pub_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  ret = 1;

err:
  CBB_cleanup(&priv_cbb);
  CBB_cleanup(&pub_cbb);
  return ret;
}

TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(const TRUST_TOKEN_METHOD *method,
                                           size_t max_batchsize) {
  if (max_batchsize > 0xffff) {
    // The protocol supports only two-byte token counts.
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_OVERFLOW);
    return NULL;
  }

  TRUST_TOKEN_CLIENT *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN_CLIENT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN_CLIENT));
  ret->method = method;
  ret->max_batchsize = (uint16_t)max_batchsize;
  return ret;
}

void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx) {
  if (ctx == NULL) {
    return;
  }
  sk_TRUST_TOKEN_PRETOKEN_pop_free(ctx->pretokens, TRUST_TOKEN_PRETOKEN_free);
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_CLIENT_add_key(TRUST_TOKEN_CLIENT *ctx, size_t *out_key_index,
                               const uint8_t *key, size_t key_len) {
  if (ctx->num_keys == OPENSSL_ARRAY_SIZE(ctx->keys) ||
      ctx->num_keys >= ctx->method->max_keys) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_TOO_MANY_KEYS);
    return 0;
  }

  struct trust_token_client_key_st *key_s = &ctx->keys[ctx->num_keys];
  CBS cbs;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id) ||
      !ctx->method->client_key_from_bytes(&key_s->key, CBS_data(&cbs),
                                          CBS_len(&cbs))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }
  key_s->id = key_id;
  *out_key_index = ctx->num_keys;
  ctx->num_keys += 1;
  return 1;
}

int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                      size_t *out_len, size_t count) {
  if (count > ctx->max_batchsize) {
    count = ctx->max_batchsize;
  }

  int ret = 0;
  CBB request;
  STACK_OF(TRUST_TOKEN_PRETOKEN) *pretokens = NULL;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  pretokens = ctx->method->blind(&request, count);
  if (pretokens == NULL) {
    goto err;
  }

  if (!CBB_finish(&request, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  sk_TRUST_TOKEN_PRETOKEN_pop_free(ctx->pretokens, TRUST_TOKEN_PRETOKEN_free);
  ctx->pretokens = pretokens;
  pretokens = NULL;
  ret = 1;

err:
  CBB_cleanup(&request);
  sk_TRUST_TOKEN_PRETOKEN_pop_free(pretokens, TRUST_TOKEN_PRETOKEN_free);
  return ret;
}

STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       size_t *out_key_index,
                                       const uint8_t *response,
                                       size_t response_len) {
  CBS in;
  CBS_init(&in, response, response_len);
  uint16_t count;
  uint32_t key_id;
  if (!CBS_get_u16(&in, &count) ||
      !CBS_get_u32(&in, &key_id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  size_t key_index = 0;
  const struct trust_token_client_key_st *key = NULL;
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == key_id) {
      key_index = i;
      key = &ctx->keys[i];
      break;
    }
  }

  if (key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_KEY_ID);
    return NULL;
  }

  if (count > sk_TRUST_TOKEN_PRETOKEN_num(ctx->pretokens)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  STACK_OF(TRUST_TOKEN) *tokens =
      ctx->method->unblind(&key->key, ctx->pretokens, &in, count, key_id);
  if (tokens == NULL) {
    return NULL;
  }

  if (CBS_len(&in) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    sk_TRUST_TOKEN_pop_free(tokens, TRUST_TOKEN_free);
    return NULL;
  }

  sk_TRUST_TOKEN_PRETOKEN_pop_free(ctx->pretokens, TRUST_TOKEN_PRETOKEN_free);
  ctx->pretokens = NULL;

  *out_key_index = key_index;
  return tokens;
}

int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                        size_t *out_len,
                                        const TRUST_TOKEN *token,
                                        const uint8_t *data, size_t data_len,
                                        uint64_t time) {
  CBB request, token_inner, inner;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16_length_prefixed(&request, &token_inner) ||
      !CBB_add_bytes(&token_inner, token->data, token->len) ||
      !CBB_add_u16_length_prefixed(&request, &inner) ||
      !CBB_add_bytes(&inner, data, data_len) ||
      !CBB_finish(&request, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    CBB_cleanup(&request);
    return 0;
  }
  return 1;
}

TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(const TRUST_TOKEN_METHOD *method,
                                           size_t max_batchsize) {
  if (max_batchsize > 0xffff) {
    // The protocol supports only two-byte token counts.
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_OVERFLOW);
    return NULL;
  }

  TRUST_TOKEN_ISSUER *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN_ISSUER));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN_ISSUER));
  ret->method = method;
  ret->max_batchsize = (uint16_t)max_batchsize;
  return ret;
}

void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx) {
  if (ctx == NULL) {
    return;
  }
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_ISSUER_add_key(TRUST_TOKEN_ISSUER *ctx, const uint8_t *key,
                               size_t key_len) {
  if (ctx->num_keys == OPENSSL_ARRAY_SIZE(ctx->keys) ||
      ctx->num_keys >= ctx->method->max_keys) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_TOO_MANY_KEYS);
    return 0;
  }

  struct trust_token_issuer_key_st *key_s = &ctx->keys[ctx->num_keys];
  CBS cbs;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id) ||
      !ctx->method->issuer_key_from_bytes(&key_s->key, CBS_data(&cbs),
                                          CBS_len(&cbs))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  key_s->id = key_id;
  ctx->num_keys += 1;
  return 1;
}

static const struct trust_token_issuer_key_st *trust_token_issuer_get_key(
    const TRUST_TOKEN_ISSUER *ctx, uint32_t key_id) {
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == key_id) {
      return &ctx->keys[i];
    }
  }
  return NULL;
}

int TRUST_TOKEN_ISSUER_issue(const TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                             size_t *out_len, size_t *out_tokens_issued,
                             const uint8_t *request, size_t request_len,
                             uint32_t public_metadata, uint8_t private_metadata,
                             size_t max_issuance) {
  if (max_issuance > ctx->max_batchsize) {
    max_issuance = ctx->max_batchsize;
  }

  const struct trust_token_issuer_key_st *key =
      trust_token_issuer_get_key(ctx, public_metadata);
  if (key == NULL || private_metadata > 1 ||
      (!ctx->method->has_private_metadata && private_metadata != 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA);
    return 0;
  }

  CBS in;
  uint16_t num_requested;
  CBS_init(&in, request, request_len);
  if (!CBS_get_u16(&in, &num_requested)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  size_t num_to_issue = num_requested;
  if (num_to_issue > max_issuance) {
    num_to_issue = max_issuance;
  }

  int ret = 0;
  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u16(&response, num_to_issue) ||
      !CBB_add_u32(&response, public_metadata)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!ctx->method->sign(&key->key, &response, &in, num_requested, num_to_issue,
                         private_metadata)) {
    goto err;
  }

  if (CBS_len(&in) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    goto err;
  }

  if (!CBB_finish(&response, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  *out_tokens_issued = num_to_issue;
  ret = 1;

err:
  CBB_cleanup(&response);
  return ret;
}


int TRUST_TOKEN_ISSUER_redeem_raw(const TRUST_TOKEN_ISSUER *ctx,
                                  uint32_t *out_public, uint8_t *out_private,
                                  TRUST_TOKEN **out_token,
                                  uint8_t **out_client_data,
                                  size_t *out_client_data_len,
                                  const uint8_t *request, size_t request_len) {
  CBS request_cbs, token_cbs;
  CBS_init(&request_cbs, request, request_len);
  if (!CBS_get_u16_length_prefixed(&request_cbs, &token_cbs)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    return 0;
  }

  uint32_t public_metadata = 0;
  uint8_t private_metadata = 0;

  // Parse the token. If there is an error, treat it as an invalid token.
  if (!CBS_get_u32(&token_cbs, &public_metadata)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }

  const struct trust_token_issuer_key_st *key =
      trust_token_issuer_get_key(ctx, public_metadata);
  uint8_t nonce[TRUST_TOKEN_NONCE_SIZE];
  if (key == NULL ||
      !ctx->method->read(&key->key, nonce, &private_metadata,
                         CBS_data(&token_cbs), CBS_len(&token_cbs))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }

  CBS client_data;
  if (!CBS_get_u16_length_prefixed(&request_cbs, &client_data) ||
      CBS_len(&request_cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    return 0;
  }

  uint8_t *client_data_buf = NULL;
  size_t client_data_len = 0;
  if (!CBS_stow(&client_data, &client_data_buf, &client_data_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  TRUST_TOKEN *token = TRUST_TOKEN_new(nonce, TRUST_TOKEN_NONCE_SIZE);
  if (token == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  *out_public = public_metadata;
  *out_private = private_metadata;
  *out_token = token;
  *out_client_data = client_data_buf;
  *out_client_data_len = client_data_len;

  return 1;

err:
  OPENSSL_free(client_data_buf);
  return 0;
}
