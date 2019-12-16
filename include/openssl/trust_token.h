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

#if defined(__cplusplus)
extern "C" {
#endif

struct trust_token_st {
  uint32_t data;
};

// Initialize a client using the 'cleartext' protocol and public key
// |public_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_Client_InitClear(uint32_t public_key);

// Initialize an issuer using the 'cleartext' protocol and private key
// |private_key|.
OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_Issuer_InitClear(uint32_t private_key);

// Initialize a client using the 'PrivacyPass' protocol and public key
// |public_key|.
//OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_Client_InitPrivacyPass;

// Initialize an issuer using the 'PrivacyPass' protocol and private key
// |private_key|.
//OPENSSL_EXPORT TT_CTX *TRUST_TOKEN_Issuer_InitPrivacyPass;

// TRUST_TOKEN_free releases memory associated with |ctx|.
OPENSSL_EXPORT void TRUST_TOKEN_free(TT_CTX *ctx);

// TRUST_TOKEN_Client_BeginIssuance produces a request for |count| trust tokens
// and serializes the request into a newly allocated buffer and sets |*out| to
// that buffer and |*out_len| to its length. The caller takes ownership of the
// buffer and must call |OPENSSL_free| when done. It returns true on success and
// false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_Client_BeginIssuance(TT_CTX *ctx, uint8_t **out,
                                                     size_t *out_len,
                                                     size_t count);

// TRUST_TOKEN_Issuer_PerformIssuance ingests a |request| for token issuance and
// generates valid tokens, producing a list of blinded tokens and storing the
// response into a newly allocated buffer and setting |*out| to that buffer and
// |*out_len| to its length. The caller takes ownership of the buffer and must
// call |OPENSSL_free| when done. It returns true on success and false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_Issuer_PerformIssuance(TT_CTX *ctx,
                                                       uint8_t **out,
                                                       size_t *out_len,
                                                       const uint8_t *request,
                                                       size_t request_len);

// TRUST_TOKEN_Client_FinishIssuance consumes a |response| from the issuer and
// extracts the tokens, allocating a buffer to store pointers to each token and
// setting |*tokens| to that buffer and |*tokens_len| to its length. The caller
// takes ownership of the buffer and must call |OPENSSL_free| when done. It
// returns true on success and false on error.
OPENSSL_EXPORT bool TRUST_TOKEN_Client_FinishIssuance(TT_CTX *ctx,
                                                      TRUST_TOKEN ***tokens,
                                                      size_t *tokens_len,
                                                      const uint8_t *response,
                                                      size_t response_len);

OPENSSL_EXPORT bool TRUST_TOKEN_Client_BeginRedemption(
    TT_CTX *ctx, uint8_t **out, size_t *out_len, TRUST_TOKEN *token,
    uint8_t *data, size_t data_len);

// TODO: Add timestamp.
OPENSSL_EXPORT bool TRUST_TOKEN_Issuer_PerformRedemption(TT_CTX *ctx,
                                                         uint8_t **out,
                                                         size_t *out_len,
                                                         const uint8_t *request,
                                                         size_t request_len);

//TODO: Add a way to extract the SRR.
OPENSSL_EXPORT bool TRUST_TOKEN_Client_FinishRedemption(TT_CTX *ctx,
                                                        bool *result,
                                                        const uint8_t *response,
                                                        size_t response_len);

// Protocol, 

/* // Generates a P521 key. (TODO: Parameterize to support multiple key types).  */
/* OPENSSL_EXPORT TRUST_TOKEN_Issuer_CreateKey(void); */

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
