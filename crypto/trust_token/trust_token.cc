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


void TRUST_TOKEN_free(TT_CTX *ctx) {
  ctx->method->tt_free(ctx);
  OPENSSL_free(ctx);
}

bool TRUST_TOKEN_client_set_srr_key(TT_CTX *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return true;
}

bool TRUST_TOKEN_issuer_set_srr_key(TT_CTX *ctx, EVP_PKEY *key) {
  ctx->srr_key = key;
  return true;
}

bool TRUST_TOKEN_client_begin_issuance(TT_CTX *ctx, uint8_t **out,
                                       size_t *out_len, size_t count) {
  return ctx->method->client_begin_issuance(ctx, out, out_len, count);
}

bool TRUST_TOKEN_issuer_perform_issuance(TT_CTX *ctx, uint8_t **out,
                                         size_t *out_len, const CBS request) {
  return ctx->method->issuer_do_issuance(ctx, out, out_len, request);
}

bool TRUST_TOKEN_client_finish_issuance(TT_CTX *ctx,
                                        STACK_OF(TRUST_TOKEN) **out_tokens,
                                        const CBS response) {
  return ctx->method->client_finish_issuance(ctx, out_tokens, response);
}

bool TRUST_TOKEN_client_begin_redemption(TT_CTX *ctx, uint8_t **out,
                                         size_t *out_len,
                                         const TRUST_TOKEN *token,
                                         const CBS data) {
  uint8_t *inner;
  size_t inner_len;
  if (!ctx->method->client_begin_redemption(ctx, &inner, &inner_len, token)) {
    return false;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, inner_len) ||
      !CBB_add_bytes(&request, inner, inner_len) ||
      !CBB_add_u16(&request, CBS_len(&data)) ||
      !CBB_add_bytes(&request, CBS_data(&data), CBS_len(&data))) {
    return false;
  }
  OPENSSL_free(inner);
  return CBB_finish(&request, out, out_len);
}

bool TRUST_TOKEN_issuer_set_metadata(TT_CTX *ctx, uint8_t public_metadata,
                                     bool private_metadata) {
  return ctx->method->issuer_set_metadata(ctx, public_metadata,
                                          private_metadata);
}

bool TRUST_TOKEN_issuer_perform_redemption(TT_CTX *ctx, uint8_t **out,
                                           size_t *out_len, const CBS request,
                                           uint64_t time) {
  CBS outer(request);
  CBS inner;
  if (!CBS_get_u16_length_prefixed(&outer, &inner)) {
    return false;
  }

  bool result;
  if (!ctx->method->issuer_do_redemption(ctx, &result, inner)) {
    return false;
  }
  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u8(&response, result)) {
    return false;
  }
  if (result) {
    CBB srr;
    if (!CBB_init(&srr, 0) ||
        !CBB_add_u64(&srr, time)) {
      return false;
    }
    // TODO: Add SRR DATA + Metadata Value + Signature
    uint8_t *data;
    size_t data_len;
    if (!CBB_finish(&srr, &data, &data_len)) {
      return false;
    }
    size_t sig_len = 0;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);
    if (!EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
        !EVP_DigestSign(&md_ctx, NULL, &sig_len, data, data_len)) {
      return false;
    }
    uint8_t *sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (!EVP_DigestSign(&md_ctx, sig, &sig_len, data, data_len)) {
      return false;
    }
    if (!CBB_add_u16(&response, data_len) ||
        !CBB_add_bytes(&response, data, data_len) ||
        !CBB_add_u16(&response, sig_len) ||
        !CBB_add_bytes(&response, sig, sig_len)) {
      return false;
    }
  }
  return CBB_finish(&response, out, out_len);
}

bool TRUST_TOKEN_client_finish_redemption(TT_CTX *ctx, bool *result,
                                          uint8_t **out_srr,
                                          size_t *out_srr_len,
                                          const CBS response) {
  CBS in(response);
  uint8_t res;
  if (!CBS_get_u8(&in, &res)) {
    return false;
  }
  *result = (res == 1);
  if (*result) {
    size_t srr_len = CBS_len(&in);
    uint8_t *srr = (uint8_t *)OPENSSL_malloc(srr_len);
    CBS in_copy(in);
    if (!CBS_copy_bytes(&in_copy, srr, srr_len)) {
      return false;
    }
    CBS data, sig;
    if (!CBS_get_u16_length_prefixed(&in, &data) ||
        !CBS_get_u16_length_prefixed(&in, &sig)) {
      return false;
    }
    if (ctx->srr_key != NULL) {
      EVP_MD_CTX md_ctx;
      EVP_MD_CTX_init(&md_ctx);
      if (!EVP_DigestVerifyInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
          !EVP_DigestVerify(&md_ctx, CBS_data(&sig), CBS_len(&sig),
                            CBS_data(&data), CBS_len(&data))) {
        return false;
      }
    }
    *out_srr = srr;
    *out_srr_len = srr_len;
  }
  return true;
}
