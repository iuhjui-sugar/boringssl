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
#include <openssl/trust_token.h>

#include "internal.h"

TRUST_TOKEN *TRUST_TOKEN_new(uint8_t *data, size_t len) {
  TRUST_TOKEN *ret = (TRUST_TOKEN *)OPENSSL_malloc(sizeof(TRUST_TOKEN));
  ret->data = data;
  ret->len = len;
  return ret;
}

void TRUST_TOKEN_free(TRUST_TOKEN *token) {
  OPENSSL_free(token->data);
}

void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx) {
  ctx->method->free_client(ctx);
  OPENSSL_free(ctx);
}

void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx) {
  ctx->method->free_issuer(ctx);
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_CLIENT_set_srr_key(TRUST_TOKEN_CLIENT *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_ISSUER_set_srr_key(TRUST_TOKEN_ISSUER *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                      size_t *out_len, size_t count) {
  return ctx->method->begin_issuance(ctx, out, out_len, count);
}

int TRUST_TOKEN_ISSUER_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                    uint8_t public_metadata,
                                    int private_metadata) {
  return ctx->method->set_metadata(ctx, public_metadata,
                                          private_metadata);
}

int TRUST_TOKEN_ISSUER_issue(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                             size_t *out_len, const uint8_t *request,
                             size_t request_len) {
  return ctx->method->issue(ctx, out, out_len, request, request_len);
}

STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       const uint8_t *response,
                                       size_t response_len) {
  return ctx->method->finish_issuance(ctx, response, response_len);
}

int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                        size_t *out_len,
                                        const TRUST_TOKEN *token,
                                        const uint8_t *data,
                                        size_t data_len,
                                        uint64_t time) {
  uint8_t *inner;
  size_t inner_len;
  if (!ctx->method->begin_redemption(ctx, &inner, &inner_len, token)) {
    return 0;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, inner_len) ||
      !CBB_add_bytes(&request, inner, inner_len) ||
      !CBB_add_u16(&request, data_len) ||
      !CBB_add_bytes(&request, data, data_len) ||
      !CBB_add_u64(&request, time)) {
    return 0;
  }
  OPENSSL_free(inner);
  return CBB_finish(&request, out, out_len);
}

int TRUST_TOKEN_ISSUER_redeem(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, TRUST_TOKEN **out_token,
                              const uint8_t *request, size_t request_len,
                              uint64_t lifetime) {
  CBS outer;
  CBS_init(&outer, request, request_len);
  CBS inner;
  if (!CBS_get_u16_length_prefixed(&outer, &inner)) {
    return 0;
  }

  int result;
  uint8_t public_metadata;
  int private_metadata;
  if (!ctx->method->redeem(ctx, &result, out_token, &public_metadata,
                           &private_metadata, CBS_data(&inner),
                           CBS_len(&inner))) {
    return 0;
  }
  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u8(&response, result)) {
    return 0;
  }
  if (result) {
    CBS client_data;
    uint64_t redemption_time;
    if (!CBS_get_u16_length_prefixed(&outer, &client_data) ||
        !CBS_get_u64(&outer, &redemption_time)) {
      return 0;
    }
    // TODO: Generate CBOR version of SRR, encode private metadata with key.
    CBB srr;
    if (!CBB_init(&srr, 0) ||
        !CBB_add_u16(&srr, CBS_len(&client_data)) ||
        !CBB_add_bytes(&srr, CBS_data(&client_data), CBS_len(&client_data))) {
      return 0;
    }
    uint8_t *public_id;
    size_t public_id_len;
    if (!ctx->method->get_public(ctx, &public_id, &public_id_len, public_metadata)) {
      return 0;
    }
    if (!CBB_add_u16(&srr, public_id_len) ||
        !CBB_add_bytes(&srr, public_id, public_id_len) ||
        !CBB_add_u8(&srr, private_metadata) ||
        !CBB_add_u64(&srr, redemption_time + lifetime)) {
      return 0;
    }

    uint8_t *srr_buf;
    size_t srr_len;
    if (!CBB_finish(&srr, &srr_buf, &srr_len)) {
      return 0;
    }

    size_t sig_len = 0;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);
    if (!EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
        !EVP_DigestSign(&md_ctx, NULL, &sig_len, srr_buf, srr_len)) {
      return 0;
    }
    uint8_t *sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!EVP_DigestSign(&md_ctx, sig, &sig_len, srr_buf, srr_len)) {
      return 0;
    }
    if (!CBB_add_u16(&response, srr_len) ||
        !CBB_add_bytes(&response, srr_buf, srr_len) ||
        !CBB_add_u16(&response, sig_len) ||
        !CBB_add_bytes(&response, sig, sig_len)) {
      return 0;
    }
    OPENSSL_free(srr_buf);
  }
  return CBB_finish(&response, out, out_len);
}

int TRUST_TOKEN_CLIENT_finish_redemption(TRUST_TOKEN_CLIENT *ctx, int *result,
                                         uint8_t **out_srr, size_t *out_srr_len,
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
    size_t srr_len = CBS_len(&in);
    uint8_t *srr_buf = (uint8_t *)OPENSSL_malloc(srr_len);
    CBS in_copy(in);
    if (srr_buf == NULL || !CBS_copy_bytes(&in_copy, srr_buf, srr_len)) {
      return 0;
    }
    CBS data, sig;
    if (!CBS_get_u16_length_prefixed(&in, &data) ||
        !CBS_get_u16_length_prefixed(&in, &sig)) {
      return 0;
    }
    if (ctx->srr_key != NULL) {
      EVP_MD_CTX md_ctx;
      EVP_MD_CTX_init(&md_ctx);
      if (!EVP_DigestVerifyInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
          !EVP_DigestVerify(&md_ctx, CBS_data(&sig),
                            CBS_len(&sig), CBS_data(&data), CBS_len(&data))) {
        return 0;
      }
    }
    *out_srr = srr_buf;
    *out_srr_len = srr_len;
  }
  return 1;
}
