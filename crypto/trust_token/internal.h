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

#include "../fipsmodule/ec/internal.h"

#include <openssl/trust_token.h>


#if defined(__cplusplus)
extern "C" {
#endif


// PMBTokens is described in https://eprint.iacr.org/2020/072/20200324:214215
// and provides anonymous tokens with private metadata. We implement the
// construction with validity verification, described in appendix H,
// construction 6, using P-521 as the group.

// PMBTOKEN_NONCE_SIZE is the size of nonces used as part of the PMBToken
// protocol.
#define PMBTOKEN_NONCE_SIZE 64

// PMBTOKEN_POINT_SIZE is the size of an encoded point in the curve used by
// PMBTokens.
#define PMBTOKEN_POINT_SIZE (1 + 66 * 2)

// PMBTOKEN_PREFIXED_POINT_SIZE is |PMBTOKEN_POINT_SIZE| with a length prefix
// prepended.
//
// TODO(https://crbug.com/boringssl/331): When updating the wire format, remove
// the redundant length prefix.
#define PMBTOKEN_PREFIXED_POINT_SIZE (2 + PMBTOKEN_POINT_SIZE)

// PMBTOKEN_SCALAR_SIZE is the size of an encoded scalar in the curve used by
// PMBTokens.
#define PMBTOKEN_SCALAR_SIZE 66

// PMBTOKEN_REQUEST_SIZE is the size of an issuance request from the client.
// This is T'.
#define PMBTOKEN_REQUEST_SIZE PMBTOKEN_PREFIXED_POINT_SIZE

// PMBTOKEN_PROOF_SIZE is the size of the proof portion of the issuance
// response. This is nine scalars and an internal length prefix.
//
// TODO(https://crbug.com/boringssl/331): When updating the wire format, remove
// redundant length prefix.
#define PMBTOKEN_PROOF_SIZE (2 + 9 * PMBTOKEN_SCALAR_SIZE)

// PMBTOKEN_RESPONSE_SIZE is the size of an issuance response from the issuer.
// This is s, W', Ws', and the DLEQ proofs.
#define PMBTOKEN_RESPONSE_SIZE \
  (PMBTOKEN_NONCE_SIZE + 2 * PMBTOKEN_PREFIXED_POINT_SIZE + PMBTOKEN_PROOF_SIZE)

// PMBTOKEN_TOKEN_SIZE is the size of an unblinded token. This is t, S, W, and
// Ws.
#define PMBTOKEN_TOKEN_SIZE \
  (PMBTOKEN_NONCE_SIZE + 3 * PMBTOKEN_PREFIXED_POINT_SIZE)

typedef struct {
  EC_RAW_POINT pub0;
  EC_RAW_POINT pub1;
  EC_RAW_POINT pubs;
} PMBTOKEN_CLIENT_KEY;

typedef struct {
  EC_SCALAR x0;
  EC_SCALAR y0;
  EC_SCALAR x1;
  EC_SCALAR y1;
  EC_SCALAR xs;
  EC_SCALAR ys;
  EC_RAW_POINT pub0;
  EC_RAW_POINT pub1;
  EC_RAW_POINT pubs;
} PMBTOKEN_ISSUER_KEY;

// PMBTOKEN_PRETOKEN represents the intermediate state a client keeps during a
// PMBToken issuance operation.
typedef struct pmb_pretoken_st {
  uint8_t t[PMBTOKEN_NONCE_SIZE];
  EC_SCALAR r;
  EC_RAW_POINT T;
  EC_RAW_POINT Tp;
} PMBTOKEN_PRETOKEN;

// PMBTOKEN_PRETOKEN_free releases the memory associated with |token|.
OPENSSL_EXPORT void PMBTOKEN_PRETOKEN_free(PMBTOKEN_PRETOKEN *token);

DEFINE_STACK_OF(PMBTOKEN_PRETOKEN)

// pmbtoken_generate_key generates a fresh keypair and writes their serialized
// forms into |out_private| and |out_public|. It returns one on success and zero
// on failure.
int pmbtoken_generate_key(CBB *out_private, CBB *out_public);

// pmbtoken_client_key_from_bytes decodes a client key from |in| and sets |key|
// to the resulting key. It returns one on success and zero
// on failure.
int pmbtoken_client_key_from_bytes(PMBTOKEN_CLIENT_KEY *key, const uint8_t *in,
                                   size_t len);

// pmbtoken_issuer_key_from_bytes decodes a issuer key from |in| and sets |key|
// to the resulting key. It returns one on success and zero
// on failure.
int pmbtoken_issuer_key_from_bytes(PMBTOKEN_ISSUER_KEY *key, const uint8_t *in,
                                   size_t len);

// pmbtoken_blind generates a new issuance request. On success, it returns a
// newly-allocated |PMBTOKEN_PRETOKEN| and writes a serialized request to the
// server to |out_request|. On failure, it returns NULL.
//
// This function implements the AT.Usr0 operation.
PMBTOKEN_PRETOKEN *pmbtoken_blind(uint8_t out_request[PMBTOKEN_REQUEST_SIZE]);

// pmbtoken_sign signs |count| tokens in |request| with |key| and a private
// metadata value of |private_metadata|. If |out_response| is NULL then
// |*out_response_len| is set to the maximum number of output bytes. Otherwise,
// it writes the response to |out_response|. It returns one on success and zero
// on failure.
//
// This function implements the AT.Sig operation.
int pmbtoken_sign(const PMBTOKEN_ISSUER_KEY *key, uint8_t *out_response,
                  size_t *out_response_len, const uint8_t *request,
                  size_t request_len, size_t count, uint8_t private_metadata);

// pmbtoken_unblind processes an issuance response and unblinds the signed
// tokens. |pretokens| are the pre-tokens returned from the corresponding
// |pmbtoken_blind| calls. If |out_tokens| is NULL then |*out_tokens_len| is set
// to the maximum number of output bytes. Otherwise, it writes the resulting
// tokens to |out_token|. It returns one on success and zero on failure.
//
// This function implements the AT.Usr1 operation.
int pmbtoken_unblind(const PMBTOKEN_CLIENT_KEY *key, uint8_t *out_tokens,
                     size_t *out_tokens_len,
                     const STACK_OF(PMBTOKEN_PRETOKEN) * pretokens,
                     const uint8_t *response, size_t response_len,
                     size_t count);

// pmbtoken_read verifies a PMBToken |token| using |key| and stores the nonce
// and private metadata bit in |out_nonce| and |*out_private_metadata|. It
// returns one if the token is valid and zero otherwise.
int pmbtoken_read(const PMBTOKEN_ISSUER_KEY *key,
                  uint8_t out_nonce[PMBTOKEN_NONCE_SIZE],
                  uint8_t *out_private_metadata,
                  const uint8_t token[PMBTOKEN_TOKEN_SIZE]);


// Structure representing a single Trust Token public key with the specified ID.
struct trust_token_client_key_st {
  uint32_t id;
  PMBTOKEN_CLIENT_KEY key;
};

// Structure representing a single Trust Token private key with the specified
// ID.
struct trust_token_issuer_key_st {
  uint32_t id;
  PMBTOKEN_ISSUER_KEY key;
};

struct trust_token_client_st {
  // max_batchsize is the maximum supported batchsize.
  uint16_t max_batchsize;

  // keys is the set of public keys that are supported by the client for
  // issuance/redemptions.
  struct trust_token_client_key_st keys[3];

  // num_keys is the number of keys currently configured.
  size_t num_keys;

  // pretokens is the intermediate state during an active issuance.
  STACK_OF(PMBTOKEN_PRETOKEN)* pretokens;

  // srr_key is the public key used to verify the signature of the SRR.
  EVP_PKEY *srr_key;
};


struct trust_token_issuer_st {
  // max_batchsize is the maximum supported batchsize.
  uint16_t max_batchsize;

  // keys is the set of private keys that are supported by the issuer for
  // issuance/redemptions. The public metadata is an index into this list of
  // keys.
  struct trust_token_issuer_key_st keys[3];

  // num_keys is the number of keys currently configured.
  size_t num_keys;

  // srr_key is the private key used to sign the SRR.
  EVP_PKEY *srr_key;

  // metadata_key is the secret material used to encode the private metadata bit
  // in the SRR.
  uint8_t *metadata_key;
  size_t metadata_key_len;
};


#if defined(__cplusplus)
}  // extern C

extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(PMBTOKEN_PRETOKEN, PMBTOKEN_PRETOKEN_free)

BSSL_NAMESPACE_END

}  // extern C++
#endif

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
