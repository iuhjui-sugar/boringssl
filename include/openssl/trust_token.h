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

OPENSSL_EXPORT bool TRUST_TOKEN_privacypass_init_key(
    uint8_t **out_priv_key, size_t *out_priv_key_len,
    uint8_t **out_pub_key, size_t *out_pub_key_len,
    uint16_t ciphersuite, uint16_t version);

// Generates keypairs for use with private metadata.
OPENSSL_EXPORT bool TRUST_TOKEN_privacypass_init_private_metadata_key(
    uint8_t **out_priv_key, size_t *out_priv_key_len,
    uint8_t **out_pub_key, size_t *out_pub_key_len,
    uint16_t ciphersuite, uint16_t version);

// Initialize a client using the 'PrivacyPass' protocol and public key
// |public_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacypass_init_client(
    uint16_t ciphersuite, uint16_t max_batchsize);

// Adds a key to the client to use when verifying the issuance/redemption requests.
OPENSSL_EXPORT bool TRUST_TOKEN_privacypass_client_add_key(TT_CTX *ctx, const CBS key);

// Initialize an issuer using the 'PrivacyPass' protocol and private key
// |private_key|.
// TODO: Add signing key for SRR.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacypass_init_issuer(
    uint16_t ciphersuite, uint16_t max_batchsize);

// TRUST_TOKEN_privacypass_add_key adds a privacy pass key to be used with this |ctx|.
// Returns false if too many keys have already been configured or the |key| doesn't parse.
OPENSSL_EXPORT bool TRUST_TOKEN_privacypass_issuer_add_key(TT_CTX *ctx, const CBS key);

// TRUST_TOKEN_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TT_CTX *ctx);

// TRUST_TOKEN_issuer_set_srr_key sets the public key to use to verify the SRR.
// TODO: Use reasonable key structure.
OPENSSL_EXPORT bool TRUST_TOKEN_client_set_srr_key(TT_CTX *ctx, const CBS key);

// TRUST_TOKEN_issuer_set_srr_key sets the private key to use to sign the SRR.
// TODO: Use reasonable key structure.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_set_srr_key(TT_CTX *ctx, const CBS key);
  
// TRUST_TOKEN_Client_BeginIssuance produces a request for |count| trust tokens
// and serializes the request into a newly allocated buffer and sets |*out| to
// that buffer and |*out_len| to its length. The caller takes ownership of the
// buffer and must call |OPENSSL_free| when done. It returns true on success and
// false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_begin_issuance(TT_CTX *ctx,
                                                      uint8_t **out, size_t *out_len,
                                                      size_t count);

// TRUST_TOKEN_Issuer_PerformIssuance ingests a |request| for token issuance and
// generates valid tokens, producing a list of blinded tokens and storing the
// response into a newly allocated buffer and setting |*out| to that buffer and
// |*out_len| to its length. The caller takes ownership of the buffer and must
// call |OPENSSL_free| when done. It returns true on success and false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_perform_issuance(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, const CBS request);

// TRUST_TOKEN_Client_FinishIssuance consumes a |response| from the issuer and
// extracts the tokens, allocating a buffer to store pointers to each token and
// setting |*tokens| to that buffer and |*tokens_len| to its length. The caller
// takes ownership of the buffer and must call |OPENSSL_free| when done. It
// returns true on success and false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_client_finish_issuance(
    TT_CTX *ctx, STACK_OF(TRUST_TOKEN) **out_tokens, const CBS response);

OPENSSL_EXPORT bool TRUST_TOKEN_client_begin_redemption(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, const TRUST_TOKEN *token,
    const CBS data);

OPENSSL_EXPORT bool TRUST_TOKEN_issuer_set_metadata(TT_CTX *ctx, uint8_t public_metadata, bool private_metadata);

// TODO: Add timestamp.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_perform_redemption(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, const CBS request);

// TODO: Add a way to extract the SRR.
OPENSSL_EXPORT bool TRUST_TOKEN_client_finish_redemption(
    TT_CTX *ctx, bool *result, const CBS response);

// Protocol, 

/* PrivateMetadataKeys { */
/*   PKey *trueKey; */
/*   PKey *falseKey; */
/* }; */

/* MetadataKeyConfig { */
/*   PrivateMetadataKeys[3] keys; */
/* }; */

/* Signing Request Data */
/* TRUST_TOKEN_GenerateKeypair() → (pub, priv) - Generates a public / private keypair for signing request data. */

/* TRUST_TOKEN_SignData(PrivateKey, const uint8_t* data, size_t len) → signature - Generates a signature over the given data.*/

#if defined(__cplusplus)
}  // extern C
#endif

#define TRUST_TOKEN_R_OVER_BATCHSIZE 100

#endif  // OPENSSL_HEADER_TRUST_TOKEN_H
