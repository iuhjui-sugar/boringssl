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

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>

#include <openssl/trust_token.h>


struct TRUST_TOKEN_METHOD {
  bool (*tt_new_client)(TT_CTX *ctx);
  bool (*tt_new_issuer)(TT_CTX *ctx);
  void (*tt_free)(TT_CTX *ctx);
  bool (*client_begin_issuance)(TT_CTX *ctx, uint8_t **out, size_t *out_len,
                                size_t count);
  bool (*issuer_set_metadata)(TT_CTX *ctx, uint8_t public_metadata,
                              bool private_metadata);
  bool (*issuer_do_issuance)(TT_CTX *ctx, uint8_t **out, size_t *out_len,
                             const CBS request);
  bool (*client_finish_issuance)(TT_CTX *ctx,
                                 STACK_OF(TRUST_TOKEN) * *out_tokens,
                                 const CBS response);
  bool (*client_begin_redemption)(TT_CTX *ctx, uint8_t **out, size_t *out_len,
                                  const TRUST_TOKEN *token);
  bool (*issuer_do_redemption)(TT_CTX *ctx, bool *result, const CBS request);
};

struct trust_token_ctx_st {
  const TRUST_TOKEN_METHOD *method = nullptr;
  void *protocol;
  EVP_PKEY *srr_key;
  
};

EC_KEY *VOPRF_Setup(uint16_t ciphersuite);

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
