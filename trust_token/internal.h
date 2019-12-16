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

#ifndef OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
#define OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H

#include <vector>

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>

#include <openssl/trust_token.h>


struct TRUST_TOKEN_METHOD {
  bool (*tt_new_client)(TT_CTX *ctx);
  bool (*tt_new_issuer)(TT_CTX *ctx);
  void (*tt_free)(TT_CTX *ctx);
  bool (*client_begin_issuance)(TT_CTX *ctx, std::vector<uint8_t> *out, size_t count);
  bool (*issuer_do_issuance)(TT_CTX *ctx, std::vector<uint8_t> *out, const std::vector<uint8_t> request);
  bool (*client_finish_issuance)(TT_CTX *ctx, std::vector<TRUST_TOKEN *> *tokens, const std::vector<uint8_t> response);
  bool (*client_begin_redemption)(TT_CTX *ctx, std::vector<uint8_t> *out, const TRUST_TOKEN *token);
  bool (*issuer_do_redemption)(TT_CTX *ctx, bool *result, const std::vector<uint8_t> request);
};

struct trust_token_ctx_st {
  const TRUST_TOKEN_METHOD *method = nullptr;
  void *protocol;
};

bssl::UniquePtr<EC_KEY> VOPRF_Setup(uint16_t ciphersuite);

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
