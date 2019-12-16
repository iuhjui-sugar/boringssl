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
  uint32_t data;
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

// Initialize a client using the 'PrivacyPass' protocol and public key
// |public_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacypass_init_client(
    uint16_t ciphersuite, uint16_t max_batchsize,
    const CBS *public_keys, size_t public_keys_len);

// Initialize an issuer using the 'PrivacyPass' protocol and private key
// |private_key|.
// TODO: Add signing key for SRR.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_privacypass_init_issuer(
    uint16_t ciphersuite, uint16_t max_batchsize, const CBS key);

// TRUST_TOKEN_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TT_CTX *ctx);

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

// TODO: Add timestamp.
OPENSSL_EXPORT bool TRUST_TOKEN_issuer_perform_redemption(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, const CBS request);

// TODO: Add a way to extract the SRR.
OPENSSL_EXPORT bool TRUST_TOKEN_client_finish_redemption(
    TT_CTX *ctx, bool *result, const CBS response);

// Protocol, 

/* // Generates a PrivacyPass key. (TODO: Parameterize to support multiple key types).  */
/* OPENSSL_EXPORT TRUST_TOKEN_Issuer_CreateKey(id); */

/* PrivateMetadataKeys { */
/*   PKey *trueKey; */
/*   PKey *falseKey; */
/* }; */

/* MetadataKeyConfig { */
/*   PrivateMetadataKeys[3] keys; */
/* }; */

/* TRUST_TOKEN_Issuer_SetMetadataKeys(TT_CTX *ctx, const MetadataKeyConfig *keys, size_t len) - Sets the key to use for this instantiation of PrivacyPass. */



/* Signing Request Data */
/* TRUST_TOKEN_GenerateKeypair() → (pub, priv) - Generates a public / private keypair for signing request data. */

/* TRUST_TOKEN_SignData(PrivateKey, const uint8_t* data, size_t len) → signature - Generates a signature over the given data.*/

#if defined(__cplusplus)
}  // extern C
#endif

#define TRUST_TOKEN_R_OVER_BATCHSIZE 100

#endif  // OPENSSL_HEADER_TRUST_TOKEN_H
