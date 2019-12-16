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

struct trust_token_st {
  uint8_t *data;
  size_t len;
};

DEFINE_STACK_OF(TRUST_TOKEN)

// TRUST_TOKEN_free releases memory associated with |token|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TRUST_TOKEN *token);  

// TRUST_TOKEN_CLIENT_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx);

// TRUST_TOKEN_ISSUER_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx);


// Trust Token Cleartext implementation.
//
// The cleartext implementation provides a minimal protocol underneath Trust
// Token to test functionality.

// Initialize a client using the 'cleartext' protocol and public key
// |public_key|.
OPENSSL_EXPORT TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new_clear(uint32_t public_key);


// Initialize an issuer using the 'cleartext' protocol and private key
// |private_key|.
OPENSSL_EXPORT TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new_clear(uint32_t private_key);


// Trust Token Privacy Pass implementation.
//
// The privacy pass implementation uses the blinded token scheme to provide an
// underlying protocol which supports private and public metadata.

#define TRUST_TOKEN_PRIVACY_PASS_MAX_PRIVATE_KEY_SIZE 256
#define TRUST_TOKEN_PRIVACY_PASS_MAX_PUBLIC_KEY_SIZE 256

// TRUST_TOKEN_privacy_pass_init_key creates a new PrivacyPass key labeled
// with version |version| and serializes the private and public keys, writing
// the private key to |out_priv_key| and setting |*out_priv_key_len| to the
// number of bytes written, and writing the public key to |out_pub_key| and
// setting |*out_pub_key_len| to the number of bytes written.
//
// At most |max_out_priv_key_len| and |max_out_pub_key_len| bytes are written.
// In order to ensure success, these should be at least
// |TRUST_TOKEN_PRIVACY_PASS_MAX_PRIVATE_KEY_SIZE| and
// |TRUST_TOKEN_PRIVACY_PASS_MAX_PUBLIC_KEY_SIZE|.
//
// It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_privacy_pass_init_key(
    uint8_t *out_priv_key, size_t *out_priv_key_len,
    size_t max_out_priv_key_len, uint8_t *out_pub_key, size_t *out_pub_key_len,
    size_t max_out_pub_key_len, uint16_t version);

// TRUST_TOKEN_privacy_pass_init_private_metadata_key creates a new PrivacyPass
// private metadata key labeled with version |version| and serializes the
// private and public keys, writing the private key to |out_priv_key| and
// setting |*out_priv_key_len| to the number of bytes written, and writing the
// public key to |out_pub_key| and setting |*out_pub_key_len| to the number of
// bytes written.
//
// At most |max_out_priv_key_len| and |max_out_pub_key_len| bytes are written.
// In order to ensure success, these should be at least
// |TRUST_TOKEN_PRIVACY_PASS_MAX_PRIVATE_KEY_SIZE| and
// |TRUST_TOKEN_PRIVACY_PASS_MAX_PUBLIC_KEY_SIZE|.
//
// It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_privacy_pass_init_private_metadata_key(
    uint8_t *out_priv_key, size_t *out_priv_key_len,
    size_t max_out_priv_key_len, uint8_t *out_pub_key, size_t *out_pub_key_len,
    size_t max_out_pub_key_len, uint16_t version);

// TRUST_TOKEN_CLIENT_new_privacy_pass returns a trust token client |ctx|
// configured to use PrivacyPass with a max batchsize of |max_batchsize|.
OPENSSL_EXPORT TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new_privacy_pass(
    uint16_t max_batchsize);

// TRUST_TOKEN_CLIENT_privacy_pass_add_key configures the |ctx| to support the
// public PrivacyPass key |key|. It returns one on success or zero on error if
// the |key| can't be parsed or too many keys have been configured.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_privacy_pass_add_key(
    TRUST_TOKEN_CLIENT *ctx, const uint8_t *key, size_t key_len);

// TRUST_TOKEN_ISSUER_new_privacy_pass returns a trust token issuer |ctx|
// configured to use PrivacyPass with a max batchsize of |max_batchsize|.
OPENSSL_EXPORT TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new_privacy_pass(
    uint16_t max_batchsize);

// TRUST_TOKEN_ISSUER_privacy_pass_add_key configures the |ctx| to support the
// private PrivacyPass key |key|. It may either be a basic PrivacyPass key
// returned by |TRUST_TOKEN_privacy_pass_init_key| or a private metadata key
// returned by |TRUST_TOKEN_privacy_pass_init_private_metadata_key|. It returns
// one on success or zero on error if the |key| can't be parsed or too many
// keys have been configured.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_privacy_pass_add_key(
    TRUST_TOKEN_ISSUER *ctx, const uint8_t *key, size_t key_len);


// Trust Token client implementation.
//
// These methods implement the client half of a Trust Token protocol.

// TRUST_TOKEN_CLIENT_set_srr_key sets the public key used to verify the SRR.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_set_srr_key(TRUST_TOKEN_CLIENT *ctx,
                                                  EVP_PKEY *key);

// TRUST_TOKEN_CLIENT_begin_issuance produces a request for |count| trust tokens
// and serializes the request into a newly allocated beffer, setting |*out| to
// that buffer and |*out_len| to its length. The caller takes ownership of the
// buffer and must call |OPENSSL_free| when done. It returns one on success and
// zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx,
                                                     uint8_t **out,
                                                     size_t *out_len,
                                                     size_t count);

// TRUST_TOKEN_CLIENT_finish_issuance consumes a |response| from the issuer and
// extracts the tokens, returning a list of tokens. The caller takes ownership
// of the list and must call |OPENSSL_free| when done. The list is empty if
// issuance fails.
OPENSSL_EXPORT STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       const CBS response);


// TRUST_TOKEN_CLIENT_begin_redemption produces a request to redeem a token
// |token| and receive a signature over |data| and serializes the request into
// a newly allocated beffer, settings |*out| to that buffer and |*out_len| to
// its length. The caller takes ownership of the buffer and must call
// |OPENSSL_free| when done. It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx,
                                                       uint8_t **out,
                                                       size_t *out_len,
                                                       const TRUST_TOKEN *token,
                                                       const CBS data);

// TRUST_TOKEN_CLIENT_finish_redemption consumes a |response| from the issuer
// and extracts the SRR, verifying its integrity and storing the result of the
// redemption in |*result|. It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_CLIENT_finish_redemption(TRUST_TOKEN_CLIENT *ctx,
                                                        int *result,
                                                        uint8_t **out_srr,
                                                        size_t *out_srr_len,
                                                        const CBS response);


// Trust Token issuer implementation.
//
// These methods implement the issuer half of a Trust Token protocol.

// TRUST_TOKEN_ISSUER_set_srr_key sets the private key used to sign the SRR.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_set_srr_key(TRUST_TOKEN_ISSUER *ctx,
                                                  EVP_PKEY *key);

// TRUST_TOKEN_ISSUER_set_metadata configures the issuer to issue token with
// public metadata of |public_metadata| and a private metadata value of
// |private_metadata|. It returns one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_set_metadata(TRUST_TOKEN_ISSUER *ctx,
                                                   uint8_t public_metadata,
                                                   int private_metadata);

// TRUST_TOKEN_ISSUER_issue ingests a |request| for token issuance
// and generates valid tokens, producing a list of blinded tokens and storing
// the response into a newly allocated buffer and setting |*out| to that buffer
// and |*out_len| to its length. The caller takes ownership of the buffer and
// must call |OPENSSL_free| when done. It returns one on success or zero on
// error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_issue(TRUST_TOKEN_ISSUER *ctx,
                                            uint8_t **out, size_t *out_len,
                                            const CBS request);

// TRUST_TOKEN_ISSUER_redeem ingests a |request| for token redemption and
// verifies the token. If the token is valid, a signed redemption record is
// produced, signing over the requested data from the request and the value of
// the token, storing the result into a newly allocated buffer and setting
// |*out| to that buffer and |*out_len| to its length. The caller takes
// ownership of the buffer and must call |OPENSSL_free| when done. It returns
// one on success or zero on error.
OPENSSL_EXPORT int TRUST_TOKEN_ISSUER_redeem(TRUST_TOKEN_ISSUER *ctx,
                                             uint8_t **out, size_t *out_len,
                                             const CBS request, uint64_t time);


#if defined(__cplusplus)
}  // extern C
#endif

#define TRUST_TOKEN_R_OVER_BATCHSIZE 100

#endif  // OPENSSL_HEADER_TRUST_TOKEN_H
