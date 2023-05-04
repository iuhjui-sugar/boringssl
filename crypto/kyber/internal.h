/* Copyright (c) 2023, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H

#include <openssl/base.h>
#include <openssl/kyber.h>

#if defined(__cplusplus)
extern "C" {
#endif


// KYBER_ENCAP_ENTROPY is the number of bytes of uniformly random entropy
// necessary to encapsulate a secret. The entropy will be leaked to the
// decapsulating party.
#define KYBER_ENCAP_ENTROPY 32

// KYBER_GENERATE_KEY_ENTROPY is the number of bytes of uniformly random entropy
// necessary to generate a key.
#define KYBER_GENERATE_KEY_ENTROPY 64

struct BORINGSSL_keccak_st {
  uint64_t state[25];
  // rate_bytes is the number of bytes outside of the sponge's capacity.
  uint8_t rate_bytes;
  // rounds is the number of Keccek rounds to do, normally 24.
  uint8_t rounds;
  // offset is the offset into |state| when squeezing.
  uint8_t offset;
  // terminator is the "domain separation" byte, or zero if it has already
  // been applied.
  uint8_t terminator;
  // next_word is the index (0..24) into `state` of the next word to update when
  // absorbing.
  uint8_t next_word;
  // word_offset is offset (0..7) within |next_word| when absorbing.
  uint8_t word_offset;
  // required_out_len is the required number of bytes to squeeze. This is used
  // for configurations like SHA-3 which have a fixed output size.
  uint8_t required_out_len;
};

enum boringssl_keccak_config_t {
  boringssl_sha3_256,
  boringssl_sha3_512,
  boringssl_shake128,
  boringssl_shake256,
  boringssl_turboshake128,
  boringssl_turboshake256,
};

enum boringssl_keccak_customization_config_t {
  boringssl_cshake128,
  boringssl_cshake256,
};

// BORINGSSL_keccak hashes |in_len| bytes from |in| and writes |out_len| bytes
// of output to |out|. If the |config| specifies a fixed-output function, like
// SHA3-256, then |out_len| must be the correct length for that function.
OPENSSL_EXPORT void BORINGSSL_keccak(uint8_t *out, size_t out_len,
                                     const uint8_t *in, size_t in_len,
                                     enum boringssl_keccak_config_t config);

// BORINGSSL_keccak_init sets up |ctx| for hashing.
OPENSSL_EXPORT void BORINGSSL_keccak_init(
    struct BORINGSSL_keccak_st *ctx, enum boringssl_keccak_config_t config);

// BORINGSSL_keccak_init sets up |ctx| for hashing a customizable function. The
// length of |customization| must be less than 1GiB.
OPENSSL_EXPORT void BORINGSSL_keccak_init_with_customization(
    struct BORINGSSL_keccak_st *ctx,
    enum boringssl_keccak_customization_config_t config,
    const uint8_t *customization, size_t customization_len);

// BORINGSSL_keccak_absorb absorbs |in_len| bytes in |in| into |ctx|. The |ctx|
// argument must have been set up with |BORINGSSL_keccak_init*| previously.
OPENSSL_EXPORT void BORINGSSL_keccak_absorb(struct BORINGSSL_keccak_st *ctx,
                                            const uint8_t *in, size_t in_len);

// BORINGSSL_keccak_squeeze writes |out_len| bytes to |out| from |ctx|. If |ctx|
// was set up as a fixed-output function (e.g. boringssl_sha3_*) then this can
// only be called once and |out_len| must be the correct length.
OPENSSL_EXPORT void BORINGSSL_keccak_squeeze(struct BORINGSSL_keccak_st *ctx,
                                             uint8_t *out, size_t out_len);

// KYBER_generate_key_external_entropy is a deterministic function to create a
// pair of Kyber768 keys, using the supplied entropy. The entropy needs to be
// uniformly random generated. This function is should only be used for tests,
// regular callers should use the non-deterministic |KYBER_generate_key|
// directly.
OPENSSL_EXPORT void KYBER_generate_key_external_entropy(
    uint8_t out_encoded_public_key[KYBER_PUBLIC_KEY_BYTES],
    struct KYBER_private_key *out_private_key,
    const uint8_t entropy[KYBER_GENERATE_KEY_ENTROPY]);

// KYBER_encap_external_entropy is a deterministic function to encapsulate
// |out_shared_secret_len| bytes of |out_shared_secret| to |ciphertext|, using
// |KYBER_ENCAP_ENTROPY| bytes of |entropy| for randomization. The
// decapsulating side will be able to recover |entropy| in full. This
// function is should only be used for tests, regular callers should use the
// non-deterministic |KYBER_encap| directly.
OPENSSL_EXPORT void KYBER_encap_external_entropy(
    uint8_t out_ciphertext[KYBER_CIPHERTEXT_BYTES], uint8_t *out_shared_secret,
    size_t out_shared_secret_len, const struct KYBER_public_key *public_key,
    const uint8_t entropy[KYBER_ENCAP_ENTROPY]);

#if defined(__cplusplus)
}
#endif

#endif  // OPENSSL_HEADER_CRYPTO_KYBER_INTERNAL_H
