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

bool TRUST_TOKEN_Client_BeginIssuance(TT_CTX *ctx, std::vector<uint8_t> *out,
                                      size_t count) {
  return ctx->method->client_begin_issuance(ctx, out, count);
}

bool TRUST_TOKEN_Issuer_PerformIssuance(TT_CTX *ctx, std::vector<uint8_t> *out,
                                        const std::vector<uint8_t> request) {
  return ctx->method->issuer_do_issuance(ctx, out, request);
}

bool TRUST_TOKEN_Client_FinishIssuance(TT_CTX *ctx,
                                       std::vector<TRUST_TOKEN *> *tokens,
                                       const std::vector<uint8_t> response) {
  return ctx->method->client_finish_issuance(ctx, tokens, response);
}


bool TRUST_TOKEN_Client_BeginRedemption(TT_CTX *ctx, std::vector<uint8_t> *out,
                                        const TRUST_TOKEN *token,
                                        const std::vector<uint8_t> data) {
  std::vector<uint8_t> inner;
  if (!ctx->method->client_begin_redemption(ctx, &inner, token)) {
    return false;
  }
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, inner.size()) ||
      !CBB_add_bytes(&request, inner.data(), inner.size()) ||
      !CBB_add_u16(&request, data.size()) ||
      !CBB_add_bytes(&request, data.data(), data.size())) {
    return false;
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

bool TRUST_TOKEN_Issuer_PerformRedemption(TT_CTX *ctx,
                                          std::vector<uint8_t> *out,
                                          const std::vector<uint8_t> request) {
  CBS in(request);
  uint16_t inner_request_len;
  if (!CBS_get_u16(&in, &inner_request_len)) {
    return false;
  }

  std::vector<uint8_t> inner;
  inner.assign(CBS_data(&in), CBS_data(&in) + inner_request_len);
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
    // TODO: Add SRR.
    // Timestamp + DATA + Signature
  }

  uint8_t *der;
  size_t der_len;
  if (!CBB_finish(&response, &der, &der_len)) {
    return false;
  }
  out->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

bool TRUST_TOKEN_Client_FinishRedemption(TT_CTX *ctx, bool *result, const std::vector<uint8_t> response) {
  CBS in(response);
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
