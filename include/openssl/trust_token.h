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

#include <openssl/base.h>
#include <openssl/stack.h>

#if defined(__cplusplus)
extern "C" {
#endif


// Trust Token implementation.
//
// |TRUST_TOKEN| objects represent individual Trust Tokens that can be stored
// between issuance and redemption.
// https://github.com/alxdavids/draft-privacy-pass/blob/master/draft-privacy-pass.md

struct trust_token_st {
  uint8_t *data;
  size_t len;
};

DEFINE_STACK_OF(TRUST_TOKEN)

// TRUST_TOKEN_new creates a new Trust Token from |data|. The buffer |data| must
// be allocated via OPENSSL_malloc and the returned token takes ownership of
// |data|.
OPENSSL_EXPORT TRUST_TOKEN *TRUST_TOKEN_new(uint8_t *data, size_t len);

// TRUST_TOKEN_free releases memory associated with |token|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TRUST_TOKEN *token);

#define TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE 256
#define TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE 256

// TRUST_TOKEN_generate_key creates a new Trust Token keypair labeled with |id|
// and serializes the private and public keys, writing the private key to
// |out_priv_key| and setting |*out_priv_key_len| to the number of bytes
// written, and writing the public key to |out_pub_key| and setting
// |*out_pub_key_len| to the number of bytes written.
//
// At most |max_priv_key_len| and |max_pub_key_len| bytes are written. In order
// to ensure success, these should be at least
// |TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE| and |TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE|.
//
// It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_generate_key(
    uint8_t *out_priv_key, size_t *out_priv_key_len, size_t max_priv_key_len,
    uint8_t *out_pub_key, size_t *out_pub_key_len, size_t max_pub_key_len,
    uint32_t id);

// TRUST_TOKEN_CLIENT_new returns a newly-allocated |TRUST_TOKEN_CLIENT|
// configured to use a max batchsize of |max_batchsize| or NULL on error.
OPENSSL_EXPORT TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(
    uint16_t max_batchsize);

// TRUST_TOKEN_CLIENT_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx);

// TRUST_TOKEN_CLIENT_add_key configures the |ctx| to support the public key
// |key|. It returns one on success or zero on error if the |key| can't be
// parsed or too many keys have been configured.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_add_key(TRUST_TOKEN_CLIENT *ctx,
                                              uint32_t id,
                                              const uint8_t *key,
                                              size_t key_len);

// TRUST_TOKEN_ISSUER_new returns a newly-allocated |TRUST_TOKEN_ISSUER|
// configured to use a max batchsize of |max_batchsize| or NULL on error.
OPENSSL_EXPORT TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(
    uint16_t max_batchsize);

// TRUST_TOKEN_ISSUER_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx);

// TRUST_TOKEN_ISSUER_add_key configures the |ctx| to support the private key
// |key|. It must be a private key returned by |TRUST_TOKEN_generate_key|. It
// returns one on success or zero on error if the |key| can't be parsed or too
// many keys have been configured.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_add_key(TRUST_TOKEN_ISSUER *ctx,
                                              uint32_t id,
                                              const uint8_t *key,
                                              size_t key_len);


// Trust Token client implementation.
//
// These functions implements the client half of a Trust Token protocol. An
// instance of the TRUST_TOKEN_CLIENT can perform a single protocol operation.

// TRUST_TOKEN_CLIENT_set_srr_key sets the public key used to verify the SRR. It
// returns one on success and zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_set_srr_key(TRUST_TOKEN_CLIENT *ctx,
                                                  EVP_PKEY *key);

// TRUST_TOKEN_CLIENT_begin_issuance produces a request for |count| trust tokens
// and serializes the request into a newly-allocated buffer, setting |*out| to
// that buffer and |*out_len| to its length. The caller takes ownership of the
// buffer and must call |OPENSSL_free| when done. It returns one on success and
// zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx,
                                                     uint8_t **out,
                                                     size_t *out_len,
                                                     size_t count);

// TRUST_TOKEN_CLIENT_finish_issuance consumes a |response| from the issuer and
// extracts the tokens, returning a list of tokens and the id of the key used to
// sign the tokens in |*out_id|. The caller takes ownership of the list and must
// call |sk_TRUST_TOKEN_pop_free| when done. The list is empty if issuance
// fails.
OPENSSL_EXPORT STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       uint32_t *out_id,
                                       const uint8_t *response,
                                       size_t response_len);


// TRUST_TOKEN_CLIENT_begin_redemption produces a request to redeem a token
// |token| and receive a signature over |data| and serializes the request into
// a newly-allocated beffer, setting |*out| to that buffer and |*out_len| to
// its length. The caller takes ownership of the buffer and must call
// |OPENSSL_free| when done. It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_begin_redemption(
    TRUST_TOKEN_CLIENT *ctx, uint8_t **out, size_t *out_len,
    const TRUST_TOKEN *token, const uint8_t *data, size_t data_len,
    uint64_t time);

// TRUST_TOKEN_CLIENT_finish_redemption consumes a |response| from the issuer
// and extracts the SRR, verifying its integrity and storing the result of the
// redemption in |*result|. The SRR is stored into a newly-allocated buffer,
// setting |*out_srr| to that buffer and |*out_srr_len| to its length. It
// returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_finish_redemption(
    TRUST_TOKEN_CLIENT *ctx, int *result, uint8_t **out_srr,
    size_t *out_srr_len, const uint8_t *response, size_t response_len);



// Trust Token issuer implementation.
//
// These functions implement the issuer half of a Trust Token protocol. An
// instance of the TRUST_TOKEN_ISSUER can be reused across multiple protocol
// operations.

// TRUST_TOKEN_ISSUER_set_srr_key sets the private key used to sign the SRR. It
// returns one on success and zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_set_srr_key(TRUST_TOKEN_ISSUER *ctx,
                                                  EVP_PKEY *key);

// TRUST_TOKEN_ISSUER_set_metadata_key sets the key used to encrypt the private
// metadata. It returns one on success and zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_set_metadata_key(TRUST_TOKEN_ISSUER *ctx,
                                                       EVP_PKEY *key);

// TRUST_TOKEN_ISSUER_set_metadata configures the issuer to issue token with
// public metadata of |public_metadata| and a private metadata value of
// |private_metadata|. |private_metadata| must be 0 or 1. It returns one on
// success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                                   uint8_t public_metadata,
                                                   int private_metadata);

// TRUST_TOKEN_ISSUER_issue ingests a |request| for token issuance
// and generates valid tokens, producing a list of blinded tokens and storing
// the response into a newly-allocated buffer and setting |*out| to that buffer
// and |*out_len| to its length. The caller takes ownership of the buffer and
// must call |OPENSSL_free| when done. It returns one on success or zero on
// error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_issue(TRUST_TOKEN_ISSUER *ctx,
                                            uint8_t **out, size_t *out_len,
                                            const uint8_t *request,
                                            size_t request_len);


// TRUST_TOKEN_ISSUER_redeem ingests a |request| for token redemption and
// verifies the token. If the token is valid, a signed redemption record is
// produced, signing over the requested data from the request and the value of
// the token, storing the result into a newly-allocated buffer and setting
// |*out| to that buffer and |*out_len| to its length. The extracted token is
// stored into a newly-allocated buffer and stored in |*out_token|. The caller
// takes ownership of the buffer and must call |OPENSSL_free| when done. It
// returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_redeem(TRUST_TOKEN_ISSUER *ctx,
                                             uint8_t **out, size_t *out_len,
                                             TRUST_TOKEN **out_token,
                                             const uint8_t *request,
                                             size_t request_len,
                                             uint64_t lifetime);


#if defined(__cplusplus)
}  // extern C
#endif

#define TRUST_TOKEN_R_OVER_BATCHSIZE 100

#endif  // OPENSSL_HEADER_TRUST_TOKEN_H
