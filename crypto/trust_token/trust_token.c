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

TRUST_TOKEN *TRUST_TOKEN_new(uint8_t *data, size_t len) {
  TRUST_TOKEN *ret = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
  ret->data = (uint8_t *)OPENSSL_malloc(len);
  if (ret->data == NULL) {
    return NULL;
  }
  OPENSSL_memcpy(ret->data, data, len);
  ret->len = len;
  return ret;
}

void TRUST_TOKEN_free(TRUST_TOKEN *token) {
  OPENSSL_free(token->data);
}

TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(uint16_t max_batchsize) {
  TRUST_TOKEN_CLIENT *ret =
      (TRUST_TOKEN_CLIENT *)OPENSSL_malloc(sizeof(TRUST_TOKEN_CLIENT));
  ret->group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (ret->group == NULL) {
    return 0;
  }
  ret->max_batchsize = max_batchsize;
  ret->key_index = 0;
  ret->pretokens = sk_PMBTOKEN_PRETOKEN_new_null();
  return ret;
}

void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx) {
  while (sk_PMBTOKEN_PRETOKEN_num(ctx->pretokens)) {
    PMBTOKEN_PRETOKEN_free(sk_PMBTOKEN_PRETOKEN_pop(ctx->pretokens));
  }
  OPENSSL_free(ctx);
}

TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(uint16_t max_batchsize) {
  TRUST_TOKEN_ISSUER *ret =
      (TRUST_TOKEN_ISSUER *)OPENSSL_malloc(sizeof(TRUST_TOKEN_ISSUER));
  ret->group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (ret->group == NULL) {
    return 0;
  }
  ret->max_batchsize = max_batchsize;
  ret->key_index = 0;
  return ret;
}

void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx) {
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_CLIENT_add_key(TRUST_TOKEN_CLIENT *ctx, uint32_t id,
                               const uint8_t *key, size_t key_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->key_index == 3) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_TOO_MANY_KEYS);
    return 0;
  }

  struct trust_token_client_key_st key_s = ctx->keys[ctx->key_index];

  key_s.pub0 = EC_POINT_new(group);
  key_s.pub1 = EC_POINT_new(group);
  key_s.pubs = EC_POINT_new(group);
  if (key_s.pub0 == NULL || key_s.pub1 == NULL || key_s.pubs == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  CBS cbs, tmp;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id) ||
      !CBS_get_u16_length_prefixed(&cbs, &tmp) ||
      !EC_POINT_oct2point(group, key_s.pub0, CBS_data(&tmp), CBS_len(&tmp), NULL) ||
      !CBS_get_u16_length_prefixed(&cbs, &tmp) ||
      !EC_POINT_oct2point(group, key_s.pub1, CBS_data(&tmp), CBS_len(&tmp), NULL) ||
      !CBS_get_u16_length_prefixed(&cbs, &tmp) ||
      !EC_POINT_oct2point(group, key_s.pubs, CBS_data(&tmp), CBS_len(&tmp), NULL) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  ctx->key_index += 1;
  return 1;
}

int TRUST_TOKEN_ISSUER_add_key(TRUST_TOKEN_ISSUER *ctx, uint32_t id,
                               const uint8_t *key, size_t key_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->key_index == 3) {
    return 0;
  }

  size_t scalar_len = BN_num_bytes(&group->order);

  CBS cbs, tmp;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  struct trust_token_issuer_key_st *key_s = &(ctx->keys[ctx->key_index]);
  EC_SCALAR *scalars[] = {&key_s->x0, &key_s->y0, &key_s->x1,
                          &key_s->y1, &key_s->xs, &key_s->ys};
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(scalars); i++) {
    if (!CBS_get_bytes(&cbs, &tmp, scalar_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return 0;
    }

    ec_scalar_from_bytes(group, scalars[i], CBS_data(&tmp), CBS_len(&tmp));
  }
  ctx->key_index += 1;
  return 1;
}

int TRUST_TOKEN_CLIENT_set_srr_key(TRUST_TOKEN_CLIENT *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_ISSUER_set_srr_key(TRUST_TOKEN_ISSUER *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_ISSUER_set_metadata_key(TRUST_TOKEN_ISSUER *ctx,
                                        const uint8_t *key, size_t len) {
  ctx->metadata_key = key;
  ctx->metadata_key_len = len;
  return 1;
}

static int cbb_add_raw_point(CBB *cbb, EC_GROUP *group, EC_RAW_POINT point) {
  EC_POINT *tmp = EC_POINT_new(group);
  if (tmp == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  int ok = 1;
  tmp->raw = point;
  CBB tmp_cbb;
  if (!CBB_add_u16_length_prefixed(cbb, &tmp_cbb) ||
      !EC_POINT_point2cbb(&tmp_cbb, group, tmp, POINT_CONVERSION_UNCOMPRESSED,
                          NULL) ||
      !CBB_flush(cbb)) {
    ok = 0;
  }
  EC_POINT_free(tmp);
  return ok;
}

static int cbs_get_raw_point(CBS *cbs, EC_RAW_POINT *out, EC_GROUP *group) {
  EC_POINT *tmp_point = EC_POINT_new(group);
  if (tmp_point == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  int ok = 1;
  CBS tmp_cbs;
  if (!CBS_get_u16_length_prefixed(cbs, &tmp_cbs) ||
      !EC_POINT_oct2point(group, tmp_point, CBS_data(&tmp_cbs),
                          CBS_len(&tmp_cbs), NULL)) {
    ok = 0;
  }
  *out = tmp_point->raw;
  EC_POINT_free(tmp_point);
  return ok;
}


int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                      size_t *out_len, size_t count) {
  if (count > ctx->max_batchsize) {
    count = ctx->max_batchsize;
  }

  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  for (size_t i = 0; i < count; i++) {
    PMBTOKEN_PRETOKEN *pretoken;
    if (!pmbtoken_blind(ctx, &pretoken)) {
      return 0;
    }
    sk_PMBTOKEN_PRETOKEN_push(ctx->pretokens, pretoken);
    if (!cbb_add_raw_point(&request, ctx->group, pretoken->Tp)) {
      return 0;
    }
  }

  return CBB_finish(&request, out, out_len);
}

int TRUST_TOKEN_ISSUER_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                    uint8_t public_metadata,
                                    uint8_t private_metadata) {
  if (public_metadata >= ctx->key_index || private_metadata > 1) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA);
    return 0;
  }
  ctx->public_metadata = public_metadata;
  ctx->private_metadata = private_metadata;
  return 1;
}

int TRUST_TOKEN_ISSUER_issue(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                             size_t *out_len, uint8_t *out_tokens_issued,
                             const uint8_t *request, size_t request_len,
                             size_t max_issuance) {
  if (max_issuance > ctx->max_batchsize) {
    max_issuance = ctx->max_batchsize;
  }

  CBS in;
  CBS_init(&in, request, request_len);

  CBB response;
  if (!CBB_init(&response, 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  if (count > max_issuance) {
    count = max_issuance;
  }

  if (!CBB_add_u16(&response, count) ||
      !CBB_add_u32(&response, ctx->keys[ctx->public_metadata].id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  for (size_t i = 0; i < count; i++) {
    EC_RAW_POINT Tp;
    if (!cbs_get_raw_point(&in, &Tp, ctx->group)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return 0;
    }

    uint8_t s[PMBTOKEN_NONCE_SIZE];
    EC_RAW_POINT Wp, Wsp;
    if (!pmbtoken_sign(ctx, s, &Wp, &Wsp, Tp)) {
      return 0;
    }

    if (!CBB_add_bytes(&response, s, PMBTOKEN_NONCE_SIZE) ||
        !cbb_add_raw_point(&response, ctx->group, Wp) ||
        !cbb_add_raw_point(&response, ctx->group, Wsp)) {
      return 0;
    }
  }

  *out_tokens_issued = count;

  if (CBS_len(&in) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }
  return CBB_finish(&response, out, out_len);
}

STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       uint32_t *out_id,
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
  if (count > sk_PMBTOKEN_PRETOKEN_num(ctx->pretokens)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  STACK_OF(TRUST_TOKEN) *tokens = sk_TRUST_TOKEN_new_null();
  for (size_t i = 0; i < count; i++) {
    uint8_t s[PMBTOKEN_NONCE_SIZE];
    EC_RAW_POINT Wp, Wsp;
    if (!CBS_copy_bytes(&in, s, PMBTOKEN_NONCE_SIZE) ||
        !cbs_get_raw_point(&in, &Wp, ctx->group) ||
        !cbs_get_raw_point(&in, &Wsp, ctx->group)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return NULL;
    }

    PMBTOKEN_PRETOKEN *ptoken = sk_PMBTOKEN_PRETOKEN_shift(ctx->pretokens);
    PMBTOKEN_TOKEN *token;
    if (!pmbtoken_unblind(ctx, &token, s, Wp, Wsp, ptoken)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      return NULL;
    }

    TRUST_TOKEN *atoken = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
    atoken->key_id = key_id;
    CBB token_cbb;
    if (!CBB_init(&token_cbb, 0) ||
        !CBB_add_bytes(&token_cbb, token->t, PMBTOKEN_NONCE_SIZE) ||
        !cbb_add_raw_point(&token_cbb, ctx->group, token->S) ||
        !cbb_add_raw_point(&token_cbb, ctx->group, token->W) ||
        !cbb_add_raw_point(&token_cbb, ctx->group, token->Ws) ||
        !CBB_finish(&token_cbb, &atoken->data, &atoken->len) ||
        !sk_TRUST_TOKEN_push(tokens, atoken)) {
      PMBTOKEN_PRETOKEN_free(ptoken);
      PMBTOKEN_TOKEN_free(token);
      OPENSSL_free(atoken);
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return NULL;
    }
    PMBTOKEN_PRETOKEN_free(ptoken);
    PMBTOKEN_TOKEN_free(token);
  }

  while (sk_PMBTOKEN_PRETOKEN_num(ctx->pretokens)) {
    PMBTOKEN_PRETOKEN_free(sk_PMBTOKEN_PRETOKEN_pop(ctx->pretokens));
  }

  *out_id = key_id;
  return tokens;
}

int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                        size_t *out_len,
                                        const TRUST_TOKEN *token,
                                        const uint8_t *data, size_t data_len,
                                        uint64_t time) {
  CBB request, inner;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16_length_prefixed(&request, &inner) ||
      !CBB_add_u32(&inner, token->key_id) ||
      !CBB_add_u16(&inner, token->len) ||
      !CBB_add_bytes(&inner, token->data, token->len) ||
      !CBB_add_u16(&request, data_len) ||
      !CBB_add_bytes(&request, data, data_len) ||
      !CBB_add_u64(&request, time)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  return CBB_finish(&request, out, out_len);
}

static int add_cbor_int(CBB *cbb, uint64_t value) {
  if (value <= 23) {
    return CBB_add_u8(cbb, value);
  }
  if (value <= 0xff) {
    return CBB_add_u8(cbb, 0x18) && CBB_add_u8(cbb, value);
  }
  if (value <= 0xffff) {
    return CBB_add_u8(cbb, 0x19) && CBB_add_u16(cbb, value);
  }
  if (value <= 0xffffffff) {
    return CBB_add_u8(cbb, 0x1a) && CBB_add_u32(cbb, value);
  }
  if (value <= 0xffffffffffffffff) {
    return CBB_add_u8(cbb, 0x1b) && CBB_add_u64(cbb, value);
  }
}

static int add_cbor_text(CBB *cbb, const uint8_t *data, size_t len) {
  return CBB_add_u8(cbb, 0x60 | len) && CBB_add_bytes(cbb, data, len);
}

static int add_cbor_map(CBB *cbb, uint8_t size) {
  return CBB_add_u8(cbb, 0xA0 | size);
}

int TRUST_TOKEN_ISSUER_redeem(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, TRUST_TOKEN **out_token,
                              uint8_t **out_client_data,
                              size_t *out_client_data_len,
                              const uint8_t *request, size_t request_len,
                              uint64_t lifetime) {
  CBS outer;
  CBS_init(&outer, request, request_len);
  CBS inner;
  if (!CBS_get_u16_length_prefixed(&outer, &inner)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    return 0;
  }

  uint32_t key_id;
  uint16_t token_len;
  if (!CBS_get_u32(&inner, &key_id) ||
      !CBS_get_u16(&inner, &token_len)) {
    return 0;
  }

  TRUST_TOKEN *ret_token = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
  if (ret_token == NULL) {
    return 0;
  }
  ret_token->data = (uint8_t *)OPENSSL_malloc(token_len);
  if (ret_token->data == NULL) {
    return 0;
  }
  ret_token->len = token_len;

  if (!CBS_copy_bytes(&inner, ret_token->data, token_len) ||
      CBS_len(&inner) != 0) {
    return 0;
  }

  int valid_token = 0;
  uint8_t public_metadata, private_metadata;

  // Parse the token. If there is an error, treat it as an invalid token.
  CBS token_cbs;
  CBS_init(&token_cbs, ret_token->data, ret_token->len);
  PMBTOKEN_TOKEN pmbtoken;
  if (CBS_copy_bytes(&token_cbs, pmbtoken.t, PMBTOKEN_NONCE_SIZE) &&
      cbs_get_raw_point(&token_cbs, &pmbtoken.S, ctx->group) &&
      cbs_get_raw_point(&token_cbs, &pmbtoken.W, ctx->group) &&
      cbs_get_raw_point(&token_cbs, &pmbtoken.Ws, ctx->group) &&
      CBS_len(&token_cbs) == 0) {
    for (size_t index = 0; index < ctx->key_index; index++) {
      if (ctx->keys[index].id == key_id) {
        public_metadata = index;
      }
    }

    valid_token =
        pmbtoken_read(ctx, &private_metadata, &pmbtoken, public_metadata);
  }

  // Treat invalid private metadata as a '0'.
  // TODO: Surface this to the caller.
  if (private_metadata == 2) {
    private_metadata = 0;
  }

  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u8(&response, valid_token)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (valid_token) {
    CBS client_data;
    uint64_t redemption_time;
    if (!CBS_get_u16_length_prefixed(&outer, &client_data) ||
        !CBS_get_u64(&outer, &redemption_time)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
      return 0;
    }

    CBS client_data_copy = client_data;

    uint32_t public_id = ctx->keys[public_metadata].id;

    CBB obfuscator_key;
    uint8_t *obfuscator_key_buf;
    size_t obfuscator_key_len;
    if (!CBB_init(&obfuscator_key, 0) ||
        !CBB_add_bytes(&obfuscator_key, ctx->metadata_key,
                       ctx->metadata_key_len) ||
        !CBB_add_bytes(&obfuscator_key, CBS_data(&client_data),
                       CBS_len(&client_data)) ||
        !CBB_finish(&obfuscator_key, &obfuscator_key_buf,
                    &obfuscator_key_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    uint8_t metadata_obfuscator[SHA256_DIGEST_LENGTH];
    SHA256(obfuscator_key_buf, obfuscator_key_len, metadata_obfuscator);
    OPENSSL_free(obfuscator_key_buf);

    static const uint8_t kClientDataLabel[] = "client-data";
    static const uint8_t kExpiryTimestampLabel[] = "expiry-timestamp";
    static const uint8_t kMetadataLabel[] = "metadata";
    static const uint8_t kPrivateLabel[] = "private";
    static const uint8_t kPublicLabel[] = "public";
    CBB srr;
    if (!CBB_init(&srr, 0) ||
        !add_cbor_map(&srr, 3) ||  // SRR map
        !add_cbor_text(&srr, kClientDataLabel, sizeof(kClientDataLabel) - 1) ||
        !CBB_add_bytes(&srr, CBS_data(&client_data), CBS_len(&client_data)) ||
        !add_cbor_text(&srr, kExpiryTimestampLabel,
                       sizeof(kExpiryTimestampLabel) - 1) ||
        !add_cbor_int(&srr, redemption_time + lifetime) ||
        !add_cbor_text(&srr, kMetadataLabel, sizeof(kMetadataLabel) - 1) ||
        !add_cbor_map(&srr, 2) ||  // Metadata map
        !add_cbor_text(&srr, kPrivateLabel, sizeof(kPrivateLabel) - 1) ||
        !add_cbor_int(&srr, private_metadata ^ (metadata_obfuscator[0] >> 7)) ||
        !add_cbor_text(&srr, kPublicLabel, sizeof(kPublicLabel) - 1) ||
        !add_cbor_int(&srr, public_id)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    uint8_t *srr_buf;
    size_t srr_len;
    if (!CBB_finish(&srr, &srr_buf, &srr_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }

    size_t sig_len = 0;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);
    if (!EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
        !EVP_DigestSign(&md_ctx, NULL, &sig_len, srr_buf, srr_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_SRR_SIGNATURE_ERROR);
      return 0;
    }
    uint8_t *sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!EVP_DigestSign(&md_ctx, sig, &sig_len, srr_buf, srr_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_SRR_SIGNATURE_ERROR);
      return 0;
    }
    if (!CBB_add_u16(&response, srr_len) ||
        !CBB_add_bytes(&response, srr_buf, srr_len) ||
        !CBB_add_u16(&response, sig_len) ||
        !CBB_add_bytes(&response, sig, sig_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    OPENSSL_free(srr_buf);

    *out_client_data = NULL;
    if (!CBS_stow(&client_data_copy, out_client_data, out_client_data_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }
  *out_token = ret_token;
  return CBB_finish(&response, out, out_len);
}

int TRUST_TOKEN_CLIENT_finish_redemption(TRUST_TOKEN_CLIENT *ctx, int *result,
                                         uint8_t **out_srr, size_t *out_srr_len,
                                         uint8_t **out_sig, size_t *out_sig_len,
                                         const uint8_t *response,
                                         size_t response_len) {
  CBS in;
  CBS_init(&in, response, response_len);
  uint8_t res;
  if (!CBS_get_u8(&in, &res)) {
    return 0;
  }
  *result = (res == 1);
  if (*result) {
    CBS srr, sig;
    if (!CBS_get_u16_length_prefixed(&in, &srr) ||
        !CBS_get_u16_length_prefixed(&in, &sig)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
      return 0;
    }
    size_t srr_len = CBS_len(&srr);
    uint8_t *srr_buf = (uint8_t *)OPENSSL_malloc(srr_len);
    size_t sig_len = CBS_len(&sig);
    uint8_t *sig_buf = (uint8_t *)OPENSSL_malloc(sig_len);
    CBS srr_copy = srr;
    CBS sig_copy = sig;
    if (srr_buf == NULL || sig_buf == NULL ||
        !CBS_copy_bytes(&srr_copy, srr_buf, srr_len) ||
        !CBS_copy_bytes(&sig_copy, sig_buf, sig_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    if (ctx->srr_key != NULL) {
      EVP_MD_CTX md_ctx;
      EVP_MD_CTX_init(&md_ctx);
      if (!EVP_DigestVerifyInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
          !EVP_DigestVerify(&md_ctx, CBS_data(&sig), CBS_len(&sig),
                            CBS_data(&srr), CBS_len(&srr))) {
        OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_SRR_SIGNATURE_ERROR);
        return 0;
      }
    }
    *out_srr = srr_buf;
    *out_srr_len = srr_len;
    *out_sig = sig_buf;
    *out_sig_len = sig_len;
  }
  return 1;
}

int TRUST_TOKEN_decode_private_metadata(uint8_t *out_value, const uint8_t *key,
                                        size_t key_len,
                                        const uint8_t *client_data,
                                        size_t client_data_len,
                                        uint8_t encrypted_bit) {
  CBB obfuscator_key;
  uint8_t *obfuscator_key_buf;
  size_t obfuscator_key_len;
  if (!CBB_init(&obfuscator_key, 0) ||
      !CBB_add_bytes(&obfuscator_key, key, key_len) ||
      !CBB_add_bytes(&obfuscator_key, client_data, client_data_len) ||
      !CBB_finish(&obfuscator_key, &obfuscator_key_buf, &obfuscator_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  uint8_t metadata_obfuscator[SHA256_DIGEST_LENGTH];
  SHA256(obfuscator_key_buf, obfuscator_key_len, metadata_obfuscator);
  OPENSSL_free(obfuscator_key_buf);
  *out_value = encrypted_bit ^ (metadata_obfuscator[0] >> 7);
  return 1;
}
