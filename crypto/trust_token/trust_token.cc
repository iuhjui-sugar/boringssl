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


void TRUST_TOKEN_free(TRUST_TOKEN *token) {
  OPENSSL_free(token->data);
}

void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx) {
  ctx->method->free(ctx);
  OPENSSL_free(ctx);
}

void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx) {
  ctx->method->free(ctx);
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
                             size_t *out_len, const CBS request) {
  return ctx->method->issue(ctx, out, out_len, request);
}

STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       const CBS response) {
  return ctx->method->finish_issuance(ctx, response);
}

int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                        size_t *out_len,
                                        const TRUST_TOKEN *token,
                                        const CBS data) {
  uint8_t *inner;
  size_t inner_len;
  if (!ctx->method->begin_redemption(ctx, &inner, &inner_len, token)) {
    return 0;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, inner_len) ||
      !CBB_add_bytes(&request, inner, inner_len) ||
      !CBB_add_u16(&request, CBS_len(&data)) ||
      !CBB_add_bytes(&request, CBS_data(&data), CBS_len(&data))) {
    return 0;
  }
  OPENSSL_free(inner);
  return CBB_finish(&request, out, out_len);
}

int TRUST_TOKEN_ISSUER_redeem(TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, const CBS request,
                              uint64_t time) {
  CBS outer(request);
  CBS inner;
  if (!CBS_get_u16_length_prefixed(&outer, &inner)) {
    return 0;
  }

  int result;
  if (!ctx->method->redeem(ctx, &result, inner)) {
    return 0;
  }
  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u8(&response, result)) {
    return 0;
  }
  if (result) {
    CBB srr;
    if (!CBB_init(&srr, 0) ||
        !CBB_add_u64(&srr, time)) {
      return 0;
    }

    // TODO: Add SRR DATA + Metadata Value + Signature
    uint8_t *data;
    size_t data_len;
    if (!CBB_finish(&srr, &data, &data_len)) {
      return 0;
    }
    size_t sig_len = 0;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);
    if (!EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
        !EVP_DigestSign(&md_ctx, NULL, &sig_len, data, data_len)) {
      return 0;
    }
    uint8_t *sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!EVP_DigestSign(&md_ctx, sig, &sig_len, data, data_len)) {
      return 0;
    }
    if (!CBB_add_u16(&response, data_len) ||
        !CBB_add_bytes(&response, data, data_len) ||
        !CBB_add_u16(&response, sig_len) ||
        !CBB_add_bytes(&response, sig, sig_len)) {
      return 0;
    }
  }
  return CBB_finish(&response, out, out_len);
}

int TRUST_TOKEN_CLIENT_finish_redemption(TRUST_TOKEN_CLIENT *ctx, int *result,
                                         uint8_t **out_srr, size_t *out_srr_len,
                                         const CBS response) {
  CBS in(response);
  uint8_t res;
  if (!CBS_get_u8(&in, &res)) {
    return 0;
  }
  *result = (res == 1);
  if (*result) {
    size_t srr_len = CBS_len(&in);
    uint8_t *srr = (uint8_t *)OPENSSL_malloc(srr_len);
    CBS in_copy(in);
    if (!CBS_copy_bytes(&in_copy, srr, srr_len)) {
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
          !EVP_DigestVerify(&md_ctx, CBS_data(&sig), CBS_len(&sig),
                            CBS_data(&data), CBS_len(&data))) {
        return 0;
      }
    }
    *out_srr = srr;
    *out_srr_len = srr_len;
  }
  return 1;
}
