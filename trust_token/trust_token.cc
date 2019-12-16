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


void TRUST_TOKEN_free(TT_CTX *ctx) {
  ctx->method->tt_free(ctx);
  OPENSSL_free(ctx);
}

bool TRUST_TOKEN_Client_BeginIssuance(TT_CTX *ctx, uint8_t **out,
                                      size_t *out_len, size_t count) {
  return ctx->method->client_begin_issuance(ctx, out, out_len, count);
}

bool TRUST_TOKEN_Issuer_PerformIssuance(TT_CTX *ctx, uint8_t **out,
                                        size_t *out_len, const uint8_t *request,
                                        size_t request_len) {
  return ctx->method->issuer_do_issuance(ctx, out, out_len, request,
                                         request_len);
}

bool TRUST_TOKEN_Client_FinishIssuance(TT_CTX *ctx, TRUST_TOKEN ***tokens,
                                       size_t *tokens_len,
                                       const uint8_t *response,
                                       size_t response_len) {
  return ctx->method->client_finish_issuance(ctx, tokens, tokens_len, response,
                                             response_len);
}


bool TRUST_TOKEN_Client_BeginRedemption(TT_CTX *ctx, uint8_t **out,
                                        size_t *out_len, TRUST_TOKEN *token,
                                        uint8_t *data, size_t data_len) {
  uint8_t *inner;
  size_t inner_len;
  if (!ctx->method->client_begin_redemption(ctx, &inner, &inner_len, token)) {
    return false;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, inner_len) ||
      !CBB_add_bytes(&request, inner, inner_len) ||
      !CBB_add_u16(&request, data_len) ||
      !CBB_add_bytes(&request, data, data_len)) {
    return false;
  }
  OPENSSL_free(inner);
  return CBB_finish(&request, out, out_len);
}

bool TRUST_TOKEN_Issuer_PerformRedemption(TT_CTX *ctx, uint8_t **out,
                                          size_t *out_len,
                                          const uint8_t *request,
                                          size_t request_len) {
  CBS in(bssl::MakeSpan(request, request_len));
  uint16_t inner_request_len;
  if (!CBS_get_u16(&in, &inner_request_len)) {
    return false;
  }

  bool result;
  if (!ctx->method->issuer_do_redemption(ctx, &result, CBS_data(&in),
                                         inner_request_len)) {
    return false;
  }
  CBB response;
  if (!CBB_init(&response, 0) ||
      !CBB_add_u8(&response, result)) {
    return false;
  }
  if (result) {
    // TODO: Add SRR.
    // Timestamp + DATA + Signature
  }

  return CBB_finish(&response, out, out_len);
}

bool TRUST_TOKEN_Client_FinishRedemption(TT_CTX *ctx, bool *result, const uint8_t *response, size_t response_len) {
  CBS in(bssl::MakeSpan(response, response_len));
  uint8_t res;
  if (!CBS_get_u8(&in, &res)) {
    return false;
  }
  *result = (res == 1);
  if (*result) {
    // TODO: Extract SRR.
  }
  return true;
}
