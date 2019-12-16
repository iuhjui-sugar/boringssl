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

#ifndef OPENSSL_HEADER_TRUST_TOKEN_H
#define OPENSSL_HEADER_TRUST_TOKEN_H

#include <vector>

#include <openssl/base.h>
#include <openssl/stack.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct trust_token_st {
  uint8_t *data;
  size_t len;
};

DEFINE_STACK_OF(TRUST_TOKEN)

// Initialize a client using the 'cleartext' protocol and public key
// |public_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_clear_init_client(uint32_t public_key);

// Initialize an issuer using the 'cleartext' protocol and private key
// |private_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_clear_init_issuer(uint32_t private_key);

// TRUST_TOKEN_privacy_pass_init_key creates a new PrivacyPass key labeled
// with version |version| and serializes the private and public keys, setting
// |*out_priv_key| and |*out_priv_key_len| to point to the private key and
// |*out_pub_key| and |*out_pub_key_len| to point to the public key. It returns
// true on success or false if an error occurred.
OPENSSL_EXPORT bool TRUST_TOKEN_privacy_pass_init_key(uint8_t **out_priv_key,
                                                      size_t *out_priv_key_len,
                                                      uint8_t **out_pub_key,
                                                      size_t *out_pub_key_len,
                                                      uint16_t version);

// TRUST_TOKEN_privacy_pass_init_private_metadata_key creates a new PrivacyPass
// private metadata key labeled with version |version| and serializes the
// private and public keys, setting |*out_priv_key| and |*out_priv_key_len| to
// point to the private key and |*out_pub_key| and |*out_pub_key_len| to point
// to the public key. It returns true on success or false if an error occurred.
OPENSSL_EXPORT bool TRUST_TOKEN_privacy_pass_init_private_metadata_key(
    uint8_t **out_priv_key, size_t *out_priv_key_len, uint8_t **out_pub_key,
    size_t *out_pub_key_len, uint16_t version);

// TRUST_TOKEN_privacy_pass_init_client returns a trust token client |ctx|
// configured to use PrivacyPass with a max batchsize of |max_batchsize|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacy_pass_init_client(
    uint16_t max_batchsize);

// TRUST_TOKEN_privacy_pass_client_add_key configures the |ctx| to support the
// public PrivacyPass key |key|. It returns true on success or false on error if
// the |key| can't be parsed or too many keys have been configured.
OPENSSL_EXPORT bool TRUST_TOKEN_privacy_pass_client_add_key(TT_CTX *ctx,
                                                            const CBS key);

// TRUST_TOKEN_privacy_pass_init_issuer returns a trust token issuer |ctx|
// configured to use PrivacyPass with a max batchsize of |max_batchsize|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacy_pass_init_issuer(
    uint16_t max_batchsize);

// TRUST_TOKEN_privacy_pass_issuer_add_key configures the |ctx| to support the
// private PrivacyPass key |key|. It may either be a basic PrivacyPass key
// returned by |TRUST_TOKEN_privacy_pass_init_key| or a private metadata key
// returned by |TRUST_TOKEN_privacy_pass_init_private_metadata_key|. It returns
// true on success or false on error if the |key| can't be parsed or too many
// keys have been configured.
OPENSSL_EXPORT bool TRUST_TOKEN_privacy_pass_issuer_add_key(TT_CTX *ctx,
                                                            const CBS key);

// TRUST_TOKEN_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TT_CTX *ctx);

// TRUST_TOKEN_issuer_set_srr_key sets the public key used to verify the SRR.
OPENSSL_EXPORT bool TRUST_TOKEN_client_set_srr_key(TT_CTX *ctx,
                                                   EVP_PKEY *key);

// TRUST_TOKEN_issuer_set_srr_key sets the private key used to sign the SRR.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_set_srr_key(TT_CTX *ctx,
                                                   EVP_PKEY *key);

// TRUST_TOKEN_client_begin_issuance produces a request for |count| trust tokens
// and serializes the request into a newly allocated beffer, settings |*out| to
// that buffer and |*out_len| to its length. The caller takes ownership of the
// buffer and must call |OPENSSL_free| when done. It returns true on success and
// false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_begin_issuance(TT_CTX *ctx,
                                                      uint8_t **out,
                                                      size_t *out_len,
                                                      size_t count);

// TRUST_TOKEN_issuer_perform_issuance ingests a |request| for token issuance
// and generates valid tokens, producing a list of blinded tokens and storing
// the response into a newly allocated buffer and setting |*out| to that buffer
// and |*out_len| to its length. The caller takes ownership of the buffer and
// must call |OPENSSL_free| when done. It returns true on success or false on
// error.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_perform_issuance(TT_CTX *ctx,
                                                        uint8_t **out,
                                                        size_t *out_len,
                                                        const CBS request);

// TRUST_TOKEN_client_finish_issuance consumes a |response| from the issuer and
// extracts the tokens, allocating a buffer to store pointers to each token and
// setting |*tokens| to that buffer and |*tokens_len| to its length. The caller
// takes ownership of the buffer and must call |OPENSSL_free| when done. It
// returns true on success or false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_finish_issuance(
    TT_CTX *ctx, STACK_OF(TRUST_TOKEN) **out_tokens, const CBS response);


// TRUST_TOKEN_client_begin_redemption produces a request to redeem a token
// |token| and receive a signature over |data| and serializes the request into
// a newly allocated beffer, settings |*out| to that buffer and |*out_len| to
// its length. The caller takes ownership of the buffer and must call
// |OPENSSL_free| when done. It returns true on success or false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_begin_redemption(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, const TRUST_TOKEN *token,
    const CBS data);

// TRUST_TOKEN_issuer_set_metadata configures the issuer to issue token with
// public metadata of |public_metadata| and a private metadata value of
// |private_metadata|. It returns true on success or false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_set_metadata(TT_CTX *ctx,
                                                    uint8_t public_metadata,
                                                    bool private_metadata);


// TRUST_TOKEN_issuer_perform_redemption ingests a |request| for token
// redemption and verifies the token. If the token is valid, a signed redemption
// record is produced, signing over the requested data from the request and the
// value of the token, storing the result into a newly allocated buffer and
// setting |*out| to that buffer and |*out_len| to its length. The caller
// takes ownership of the buffer and must call |OPENSSL_free| when done. It
// returns true on success or false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_perform_redemption(TT_CTX *ctx,
                                                          uint8_t **out,
                                                          size_t *out_len,
                                                          const CBS request,
                                                          uint64_t time);

// TRUST_TOKEN_client_finish_redemption consumes a |response| from the issuer
// and extracts the SRR, verifying its integrity and storing the result of the
// redemption in |*result|. It returns true on success or false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_finish_redemption(TT_CTX *ctx,
                                                         bool *result,
                                                         uint8_t **out_srr,
                                                         size_t *out_srr_len,
                                                         const CBS response);

#if defined(__cplusplus)
}  // extern C
#endif

#define TRUST_TOKEN_R_OVER_BATCHSIZE 100

#endif  // OPENSSL_HEADER_TRUST_TOKEN_H
