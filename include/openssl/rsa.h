/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_RSA_H
#define OPENSSL_HEADER_RSA_H

#include <openssl/base.h>

#include <openssl/engine.h>
#include <openssl/ex_data.h>
#include <openssl/thread.h>

#if defined(__cplusplus)
extern "C" {
#endif


// rsa.h contains functions for handling encryption and signature using RSA.


// Allocation and destruction.

// RSA_new returns a new, empty RSA object or NULL on error.
OPENSSL_EXPORT RSA *RSA_new(void);

// RSA_new_method acts the same as |RSA_new| but takes an explicit |ENGINE|.
OPENSSL_EXPORT RSA *RSA_new_method(const ENGINE *engine);

// RSA_free decrements the reference count of |rsa| and frees it if the
// reference count drops to zero.
OPENSSL_EXPORT void RSA_free(RSA *rsa);

// RSA_up_ref increments the reference count of |rsa| and returns one.
OPENSSL_EXPORT int RSA_up_ref(RSA *rsa);


// Properties.

// RSA_get0_key sets |*out_n|, |*out_e|, and |*out_d|, if non-NULL, to |rsa|'s
// modulus, public exponent, and private exponent, respectively. If |rsa| is a
// public key, the private exponent will be set to NULL.
OPENSSL_EXPORT void RSA_get0_key(const RSA *rsa, const BIGNUM **out_n,
                                 const BIGNUM **out_e, const BIGNUM **out_d);

// RSA_get0_factors sets |*out_p| and |*out_q|, if non-NULL, to |rsa|'s prime
// factors. If |rsa| is a public key, they will be set to NULL.
OPENSSL_EXPORT void RSA_get0_factors(const RSA *rsa, const BIGNUM **out_p,
                                     const BIGNUM **out_q);

// RSA_get0_crt_params sets |*out_dmp1|, |*out_dmq1|, and |*out_iqmp|, if
// non-NULL, to |rsa|'s CRT parameters. These are d (mod p-1), d (mod q-1) and
// q^-1 (mod p), respectively. If |rsa| is a public key, each parameter will be
// set to NULL.
OPENSSL_EXPORT void RSA_get0_crt_params(const RSA *rsa, const BIGNUM **out_dmp1,
                                        const BIGNUM **out_dmq1,
                                        const BIGNUM **out_iqmp);

// RSA_set0_key sets |rsa|'s modulus, public exponent, and private exponent to
// |n|, |e|, and |d| respectively, if non-NULL. On success, it takes ownership
// of each argument and returns one. Otherwise, it returns zero.
//
// |d| may be NULL, but |n| and |e| must either be non-NULL or already
// configured on |rsa|.
OPENSSL_EXPORT int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d);

// RSA_set0_factors sets |rsa|'s prime factors to |p| and |q|, if non-NULL, and
// takes ownership of them. On success, it takes ownership of each argument and
// returns one. Otherwise, it returns zero.
//
// Each argument must either be non-NULL or already configured on |rsa|.
OPENSSL_EXPORT int RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q);

// RSA_set0_crt_params sets |rsa|'s CRT parameters to |dmp1|, |dmq1|, and
// |iqmp|, if non-NULL, and takes ownership of them. On success, it takes
// ownership of its parameters and returns one. Otherwise, it returns zero.
//
// Each argument must either be non-NULL or already configured on |rsa|.
OPENSSL_EXPORT int RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1,
                                       BIGNUM *iqmp);


// Key generation.

// RSA_generate_key_ex generates a new RSA key where the modulus has size
// |bits| and the public exponent is |e|. If unsure, |RSA_F4| is a good value
// for |e|. If |cb| is not NULL then it is called during the key generation
// process. In addition to the calls documented for |BN_generate_prime_ex|, it
// is called with event=2 when the n'th prime is rejected as unsuitable and
// with event=3 when a suitable value for |p| is found.
//
// It returns one on success or zero on error.
OPENSSL_EXPORT int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e,
                                       BN_GENCB *cb);

// RSA_generate_key_fips behaves like |RSA_generate_key_ex| but performs
// additional checks for FIPS compliance. The public exponent is always 65537
// and |bits| must be either 2048 or 3072.
OPENSSL_EXPORT int RSA_generate_key_fips(RSA *rsa, int bits, BN_GENCB *cb);


// Encryption / Decryption

// Padding types for encryption.
#define RSA_PKCS1_PADDING 1
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
// RSA_PKCS1_PSS_PADDING can only be used via the EVP interface.
#define RSA_PKCS1_PSS_PADDING 6

// RSA_encrypt encrypts |in_len| bytes from |in| to the public key from |rsa|
// and writes, at most, |max_out| bytes of encrypted data to |out|. The
// |max_out| argument must be, at least, |RSA_size| in order to ensure success.
//
// It returns 1 on success or zero on error.
//
// The |padding| argument must be one of the |RSA_*_PADDING| values. If in
// doubt, use |RSA_PKCS1_OAEP_PADDING| for new protocols but
// |RSA_PKCS1_PADDING| is most common.
OPENSSL_EXPORT int RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out,
                               size_t max_out, const uint8_t *in, size_t in_len,
                               int padding);

// RSA_decrypt decrypts |in_len| bytes from |in| with the private key from
// |rsa| and writes, at most, |max_out| bytes of plaintext to |out|. The
// |max_out| argument must be, at least, |RSA_size| in order to ensure success.
//
// It returns 1 on success or zero on error.
//
// The |padding| argument must be one of the |RSA_*_PADDING| values. If in
// doubt, use |RSA_PKCS1_OAEP_PADDING| for new protocols.
//
// Passing |RSA_PKCS1_PADDING| into this function is deprecated and insecure. If
// implementing a protocol using RSAES-PKCS1-V1_5, use |RSA_NO_PADDING| and then
// check padding in constant-time combined with a swap to a random session key
// or other mitigation. See "Chosen Ciphertext Attacks Against Protocols Based
// on the RSA Encryption Standard PKCS #1", Daniel Bleichenbacher, Advances in
// Cryptology (Crypto '98).
OPENSSL_EXPORT int RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out,
                               size_t max_out, const uint8_t *in, size_t in_len,
                               int padding);

// RSA_public_encrypt encrypts |flen| bytes from |from| to the public key in
// |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
// least |RSA_size| bytes of space. It returns the number of bytes written, or
// -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
// values. If in doubt, use |RSA_PKCS1_OAEP_PADDING| for new protocols but
// |RSA_PKCS1_PADDING| is most common.
//
// WARNING: this function is dangerous because it breaks the usual return value
// convention. Use |RSA_encrypt| instead.
OPENSSL_EXPORT int RSA_public_encrypt(size_t flen, const uint8_t *from,
                                      uint8_t *to, RSA *rsa, int padding);

// RSA_private_decrypt decrypts |flen| bytes from |from| with the public key in
// |rsa| and writes the plaintext to |to|. The |to| buffer must have at least
// |RSA_size| bytes of space. It returns the number of bytes written, or -1 on
// error. The |padding| argument must be one of the |RSA_*_PADDING| values. If
// in doubt, use |RSA_PKCS1_OAEP_PADDING| for new protocols. Passing
// |RSA_PKCS1_PADDING| into this function is deprecated and insecure. See
// |RSA_decrypt|.
//
// WARNING: this function is dangerous because it breaks the usual return value
// convention. Use |RSA_decrypt| instead.
OPENSSL_EXPORT int RSA_private_decrypt(size_t flen, const uint8_t *from,
                                       uint8_t *to, RSA *rsa, int padding);


// Signing / Verification

// RSA_sign signs |in_len| bytes of digest from |in| with |rsa| using
// RSASSA-PKCS1-v1_5. It writes, at most, |RSA_size(rsa)| bytes to |out|. On
// successful return, the actual number of bytes written is written to
// |*out_len|.
//
// The |hash_nid| argument identifies the hash function used to calculate |in|
// and is embedded in the resulting signature. For example, it might be
// |NID_sha256|.
//
// It returns 1 on success and zero on error.
OPENSSL_EXPORT int RSA_sign(int hash_nid, const uint8_t *in,
                            unsigned int in_len, uint8_t *out,
                            unsigned int *out_len, RSA *rsa);

// RSA_sign_pss_mgf1 signs |in_len| bytes from |in| with the public key from
// |rsa| using RSASSA-PSS with MGF1 as the mask generation function. It writes,
// at most, |max_out| bytes of signature data to |out|. The |max_out| argument
// must be, at least, |RSA_size| in order to ensure success. It returns 1 on
// success or zero on error.
//
// The |md| and |mgf1_md| arguments identify the hash used to calculate |msg|
// and the MGF1 hash, respectively. If |mgf1_md| is NULL, |md| is
// used.
//
// |salt_len| specifies the expected salt length in bytes. If |salt_len| is -1,
// then the salt length is the same as the hash length. If -2, then the salt
// length is maximal given the size of |rsa|. If unsure, use -1.
OPENSSL_EXPORT int RSA_sign_pss_mgf1(RSA *rsa, size_t *out_len, uint8_t *out,
                                     size_t max_out, const uint8_t *in,
                                     size_t in_len, const EVP_MD *md,
                                     const EVP_MD *mgf1_md, int salt_len);

// RSA_sign_raw signs |in_len| bytes from |in| with the public key from |rsa|
// and writes, at most, |max_out| bytes of signature data to |out|. The
// |max_out| argument must be, at least, |RSA_size| in order to ensure success.
//
// It returns 1 on success or zero on error.
//
// The |padding| argument must be one of the |RSA_*_PADDING| values. If in
// doubt, |RSA_PKCS1_PADDING| is the most common but |RSA_PKCS1_PSS_PADDING|
// (via the |EVP_PKEY| interface) is preferred for new protocols.
OPENSSL_EXPORT int RSA_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out,
                                size_t max_out, const uint8_t *in,
                                size_t in_len, int padding);

// RSA_verify verifies that |sig_len| bytes from |sig| are a valid,
// RSASSA-PKCS1-v1_5 signature of |msg_len| bytes at |msg| by |rsa|.
//
// The |hash_nid| argument identifies the hash function used to calculate |msg|
// and is embedded in the resulting signature in order to prevent hash
// confusion attacks. For example, it might be |NID_sha256|.
//
// It returns one if the signature is valid and zero otherwise.
//
// WARNING: this differs from the original, OpenSSL function which additionally
// returned -1 on error.
OPENSSL_EXPORT int RSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len, RSA *rsa);

// RSA_verify_pss_mgf1 verifies that |sig_len| bytes from |sig| are a valid,
// RSASSA-PSS signature of |msg_len| bytes at |msg| by |rsa|. It returns one if
// the signature is valid and zero otherwise. MGF1 is used as the mask
// generation function.
//
// The |md| and |mgf1_md| arguments identify the hash used to calculate |msg|
// and the MGF1 hash, respectively. If |mgf1_md| is NULL, |md| is
// used. |salt_len| specifies the expected salt length in bytes.
//
// If |salt_len| is -1, then the salt length is the same as the hash length. If
// -2, then the salt length is recovered and all values accepted. If unsure, use
// -1.
OPENSSL_EXPORT int RSA_verify_pss_mgf1(RSA *rsa, const uint8_t *msg,
                                       size_t msg_len, const EVP_MD *md,
                                       const EVP_MD *mgf1_md, int salt_len,
                                       const uint8_t *sig, size_t sig_len);

// RSA_verify_raw verifies |in_len| bytes of signature from |in| using the
// public key from |rsa| and writes, at most, |max_out| bytes of plaintext to
// |out|. The |max_out| argument must be, at least, |RSA_size| in order to
// ensure success.
//
// It returns 1 on success or zero on error.
//
// The |padding| argument must be one of the |RSA_*_PADDING| values. If in
// doubt, |RSA_PKCS1_PADDING| is the most common but |RSA_PKCS1_PSS_PADDING|
// (via the |EVP_PKEY| interface) is preferred for new protocols.
OPENSSL_EXPORT int RSA_verify_raw(RSA *rsa, size_t *out_len, uint8_t *out,
                                  size_t max_out, const uint8_t *in,
                                  size_t in_len, int padding);

// RSA_private_encrypt encrypts |flen| bytes from |from| with the private key in
// |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
// least |RSA_size| bytes of space. It returns the number of bytes written, or
// -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
// values. If in doubt, |RSA_PKCS1_PADDING| is the most common but
// |RSA_PKCS1_PSS_PADDING| (via the |EVP_PKEY| interface) is preferred for new
// protocols.
//
// WARNING: this function is dangerous because it breaks the usual return value
// convention. Use |RSA_sign_raw| instead.
OPENSSL_EXPORT int RSA_private_encrypt(size_t flen, const uint8_t *from,
                                       uint8_t *to, RSA *rsa, int padding);

// RSA_public_decrypt verifies |flen| bytes of signature from |from| using the
// public key in |rsa| and writes the plaintext to |to|. The |to| buffer must
// have at least |RSA_size| bytes of space. It returns the number of bytes
// written, or -1 on error. The |padding| argument must be one of the
// |RSA_*_PADDING| values. If in doubt, |RSA_PKCS1_PADDING| is the most common
// but |RSA_PKCS1_PSS_PADDING| (via the |EVP_PKEY| interface) is preferred for
// new protocols.
//
// WARNING: this function is dangerous because it breaks the usual return value
// convention. Use |RSA_verify_raw| instead.
OPENSSL_EXPORT int RSA_public_decrypt(size_t flen, const uint8_t *from,
                                      uint8_t *to, RSA *rsa, int padding);


// Utility functions.

// RSA_size returns the number of bytes in the modulus, which is also the size
// of a signature or encrypted value using |rsa|.
OPENSSL_EXPORT unsigned RSA_size(const RSA *rsa);

// RSA_is_opaque returns one if |rsa| is opaque and doesn't expose its key
// material. Otherwise it returns zero.
OPENSSL_EXPORT int RSA_is_opaque(const RSA *rsa);

// RSAPublicKey_dup allocates a fresh |RSA| and copies the public key from
// |rsa| into it. It returns the fresh |RSA| object, or NULL on error.
OPENSSL_EXPORT RSA *RSAPublicKey_dup(const RSA *rsa);

// RSAPrivateKey_dup allocates a fresh |RSA| and copies the private key from
// |rsa| into it. It returns the fresh |RSA| object, or NULL on error.
OPENSSL_EXPORT RSA *RSAPrivateKey_dup(const RSA *rsa);

// RSA_check_key performs basic validity tests on |rsa|. It returns one if
// they pass and zero otherwise. Opaque keys and public keys always pass. If it
// returns zero then a more detailed error is available on the error queue.
OPENSSL_EXPORT int RSA_check_key(const RSA *rsa);

// RSA_check_fips performs public key validity tests on |key|. It returns one
// if they pass and zero otherwise. Opaque keys always fail.
OPENSSL_EXPORT int RSA_check_fips(RSA *key);

// RSA_verify_PKCS1_PSS_mgf1 verifies that |EM| is a correct PSS padding of
// |mHash|, where |mHash| is a digest produced by |Hash|. |EM| must point to
// exactly |RSA_size(rsa)| bytes of data. The |mgf1Hash| argument specifies the
// hash function for generating the mask. If NULL, |Hash| is used. The |sLen|
// argument specifies the expected salt length in bytes. If |sLen| is -1 then
// the salt length is the same as the hash length. If -2, then the salt length
// is recovered and all values accepted.
//
// If unsure, use -1.
//
// It returns one on success or zero on error.
//
// This function implements only the low-level padding logic. Use
// |RSA_verify_pss_mgf1| instead.
OPENSSL_EXPORT int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const uint8_t *mHash,
                                             const EVP_MD *Hash,
                                             const EVP_MD *mgf1Hash,
                                             const uint8_t *EM, int sLen);

// RSA_padding_add_PKCS1_PSS_mgf1 writes a PSS padding of |mHash| to |EM|,
// where |mHash| is a digest produced by |Hash|. |RSA_size(rsa)| bytes of
// output will be written to |EM|. The |mgf1Hash| argument specifies the hash
// function for generating the mask. If NULL, |Hash| is used. The |sLen|
// argument specifies the expected salt length in bytes. If |sLen| is -1 then
// the salt length is the same as the hash length. If -2, then the salt length
// is maximal given the space in |EM|.
//
// It returns one on success or zero on error.
//
// This function implements only the low-level padding logic. Use
// |RSA_sign_pss_mgf1| instead.
OPENSSL_EXPORT int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, uint8_t *EM,
                                                  const uint8_t *mHash,
                                                  const EVP_MD *Hash,
                                                  const EVP_MD *mgf1Hash,
                                                  int sLen);

// RSA_padding_add_PKCS1_OAEP_mgf1 writes an OAEP padding of |from| to |to|
// with the given parameters and hash functions. If |md| is NULL then SHA-1 is
// used. If |mgf1md| is NULL then the value of |md| is used (which means SHA-1
// if that, in turn, is NULL).
//
// It returns one on success or zero on error.
OPENSSL_EXPORT int RSA_padding_add_PKCS1_OAEP_mgf1(
    uint8_t *to, size_t to_len, const uint8_t *from, size_t from_len,
    const uint8_t *param, size_t param_len, const EVP_MD *md,
    const EVP_MD *mgf1md);

// RSA_add_pkcs1_prefix builds a version of |msg| prefixed with the DigestInfo
// header for the given hash function and sets |out_msg| to point to it. On
// successful return, if |*is_alloced| is one, the caller must release
// |*out_msg| with |OPENSSL_free|.
OPENSSL_EXPORT int RSA_add_pkcs1_prefix(uint8_t **out_msg, size_t *out_msg_len,
                                        int *is_alloced, int hash_nid,
                                        const uint8_t *msg, size_t msg_len);


// ASN.1 functions.

// RSA_parse_public_key parses a DER-encoded RSAPublicKey structure (RFC 3447)
// from |cbs| and advances |cbs|. It returns a newly-allocated |RSA| or NULL on
// error.
OPENSSL_EXPORT RSA *RSA_parse_public_key(CBS *cbs);

// RSA_parse_public_key_buggy behaves like |RSA_parse_public_key|, but it
// tolerates some invalid encodings. Do not use this function.
OPENSSL_EXPORT RSA *RSA_parse_public_key_buggy(CBS *cbs);

// RSA_public_key_from_bytes parses |in| as a DER-encoded RSAPublicKey structure
// (RFC 3447). It returns a newly-allocated |RSA| or NULL on error.
OPENSSL_EXPORT RSA *RSA_public_key_from_bytes(const uint8_t *in, size_t in_len);

// RSA_marshal_public_key marshals |rsa| as a DER-encoded RSAPublicKey structure
// (RFC 3447) and appends the result to |cbb|. It returns one on success and
// zero on failure.
OPENSSL_EXPORT int RSA_marshal_public_key(CBB *cbb, const RSA *rsa);

// RSA_public_key_to_bytes marshals |rsa| as a DER-encoded RSAPublicKey
// structure (RFC 3447) and, on success, sets |*out_bytes| to a newly allocated
// buffer containing the result and returns one. Otherwise, it returns zero. The
// result should be freed with |OPENSSL_free|.
OPENSSL_EXPORT int RSA_public_key_to_bytes(uint8_t **out_bytes, size_t *out_len,
                                           const RSA *rsa);

// RSA_parse_private_key parses a DER-encoded RSAPrivateKey structure (RFC 3447)
// from |cbs| and advances |cbs|. It returns a newly-allocated |RSA| or NULL on
// error.
OPENSSL_EXPORT RSA *RSA_parse_private_key(CBS *cbs);

// RSA_private_key_from_bytes parses |in| as a DER-encoded RSAPrivateKey
// structure (RFC 3447). It returns a newly-allocated |RSA| or NULL on error.
OPENSSL_EXPORT RSA *RSA_private_key_from_bytes(const uint8_t *in,
                                               size_t in_len);

// RSA_marshal_private_key marshals |rsa| as a DER-encoded RSAPrivateKey
// structure (RFC 3447) and appends the result to |cbb|. It returns one on
// success and zero on failure.
OPENSSL_EXPORT int RSA_marshal_private_key(CBB *cbb, const RSA *rsa);

// RSA_private_key_to_bytes marshals |rsa| as a DER-encoded RSAPrivateKey
// structure (RFC 3447) and, on success, sets |*out_bytes| to a newly allocated
// buffer containing the result and returns one. Otherwise, it returns zero. The
// result should be freed with |OPENSSL_free|.
OPENSSL_EXPORT int RSA_private_key_to_bytes(uint8_t **out_bytes,
                                            size_t *out_len, const RSA *rsa);


// ex_data functions.
//
// See |ex_data.h| for details.

OPENSSL_EXPORT int RSA_get_ex_new_index(long argl, void *argp,
                                        CRYPTO_EX_unused *unused,
                                        CRYPTO_EX_dup *dup_unused,
                                        CRYPTO_EX_free *free_func);
OPENSSL_EXPORT int RSA_set_ex_data(RSA *rsa, int idx, void *arg);
OPENSSL_EXPORT void *RSA_get_ex_data(const RSA *rsa, int idx);


// Flags.

// RSA_FLAG_OPAQUE specifies that this RSA_METHOD does not expose its key
// material. This may be set if, for instance, it is wrapping some other crypto
// API, like a platform key store.
#define RSA_FLAG_OPAQUE 1

// Deprecated and ignored.
#define RSA_FLAG_CACHE_PUBLIC 2

// Deprecated and ignored.
#define RSA_FLAG_CACHE_PRIVATE 4

// RSA_FLAG_NO_BLINDING disables blinding of private operations, which is a
// dangerous thing to do. It is deprecated and should not be used. It will
// be ignored whenever possible.
//
// This flag must be used if a key without the public exponent |e| is used for
// private key operations; avoid using such keys whenever possible.
#define RSA_FLAG_NO_BLINDING 8

// RSA_FLAG_EXT_PKEY is deprecated and ignored.
#define RSA_FLAG_EXT_PKEY 0x20

// RSA_FLAG_SIGN_VER causes the |sign| and |verify| functions of |rsa_meth_st|
// to be called when set.
#define RSA_FLAG_SIGN_VER 0x40


// RSA public exponent values.

#define RSA_3 0x3
#define RSA_F4 0x10001


// Deprecated functions.

// RSA_blinding_on returns one.
OPENSSL_EXPORT int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);

// RSA_generate_key behaves like |RSA_generate_key_ex|, which is what you
// should use instead. It returns NULL on error, or a newly-allocated |RSA| on
// success. This function is provided for compatibility only. The |callback|
// and |cb_arg| parameters must be NULL.
OPENSSL_EXPORT RSA *RSA_generate_key(int bits, unsigned long e, void *callback,
                                     void *cb_arg);

// d2i_RSAPublicKey parses an ASN.1, DER-encoded, RSA public key from |len|
// bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
// is in |*out|. Note that, even if |*out| is already non-NULL on entry, it
// will not be written to. Rather, a fresh |RSA| is allocated and the previous
// one is freed. On successful exit, |*inp| is advanced past the DER structure.
// It returns the result or NULL on error.
OPENSSL_EXPORT RSA *d2i_RSAPublicKey(RSA **out, const uint8_t **inp, long len);

// i2d_RSAPublicKey marshals |in| to an ASN.1, DER structure. If |outp| is not
// NULL then the result is written to |*outp| and |*outp| is advanced just past
// the output. It returns the number of bytes in the result, whether written or
// not, or a negative value on error.
OPENSSL_EXPORT int i2d_RSAPublicKey(const RSA *in, uint8_t **outp);

// d2i_RSAPrivateKey parses an ASN.1, DER-encoded, RSA private key from |len|
// bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
// is in |*out|. Note that, even if |*out| is already non-NULL on entry, it
// will not be written to. Rather, a fresh |RSA| is allocated and the previous
// one is freed. On successful exit, |*inp| is advanced past the DER structure.
// It returns the result or NULL on error.
OPENSSL_EXPORT RSA *d2i_RSAPrivateKey(RSA **out, const uint8_t **inp, long len);

// i2d_RSAPrivateKey marshals |in| to an ASN.1, DER structure. If |outp| is not
// NULL then the result is written to |*outp| and |*outp| is advanced just past
// the output. It returns the number of bytes in the result, whether written or
// not, or a negative value on error.
OPENSSL_EXPORT int i2d_RSAPrivateKey(const RSA *in, uint8_t **outp);

// RSA_padding_add_PKCS1_PSS acts like |RSA_padding_add_PKCS1_PSS_mgf1| but the
// |mgf1Hash| parameter of the latter is implicitly set to |Hash|.
//
// This function implements only the low-level padding logic. Use
// |RSA_sign_pss_mgf1| instead.
OPENSSL_EXPORT int RSA_padding_add_PKCS1_PSS(RSA *rsa, uint8_t *EM,
                                             const uint8_t *mHash,
                                             const EVP_MD *Hash, int sLen);

// RSA_verify_PKCS1_PSS acts like |RSA_verify_PKCS1_PSS_mgf1| but the
// |mgf1Hash| parameter of the latter is implicitly set to |Hash|.
//
// This function implements only the low-level padding logic. Use
// |RSA_verify_pss_mgf1| instead.
OPENSSL_EXPORT int RSA_verify_PKCS1_PSS(RSA *rsa, const uint8_t *mHash,
                                        const EVP_MD *Hash, const uint8_t *EM,
                                        int sLen);

// RSA_padding_add_PKCS1_OAEP acts like |RSA_padding_add_PKCS1_OAEP_mgf1| but
// the |md| and |mgf1md| parameters of the latter are implicitly set to NULL,
// which means SHA-1.
OPENSSL_EXPORT int RSA_padding_add_PKCS1_OAEP(uint8_t *to, size_t to_len,
                                              const uint8_t *from,
                                              size_t from_len,
                                              const uint8_t *param,
                                              size_t param_len);


struct rsa_meth_st {
  struct openssl_method_common_st common;

  void *app_data;

  int (*init)(RSA *rsa);
  int (*finish)(RSA *rsa);

  // size returns the size of the RSA modulus in bytes.
  size_t (*size)(const RSA *rsa);

  int (*sign)(int type, const uint8_t *m, unsigned int m_length,
              uint8_t *sigret, unsigned int *siglen, const RSA *rsa);

  // Ignored. Set this to NULL.
  // TODO(davidben): Remove this when
  // https://github.com/google/conscrypt/commit/bb0571e358e95e1c70ac7a6984fc4d7236cac72f
  // is in all BoringSSL consumers.
  int (*encrypt)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);

  // These functions mirror the |RSA_*| functions of the same name.
  int (*sign_raw)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                  const uint8_t *in, size_t in_len, int padding);
  int (*decrypt)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);

  // private_transform takes a big-endian integer from |in|, calculates the
  // d'th power of it, modulo the RSA modulus and writes the result as a
  // big-endian integer to |out|. Both |in| and |out| are |len| bytes long and
  // |len| is always equal to |RSA_size(rsa)|. If the result of the transform
  // can be represented in fewer than |len| bytes, then |out| must be zero
  // padded on the left.
  //
  // It returns one on success and zero otherwise.
  //
  // RSA decrypt and sign operations will call this, thus an ENGINE might wish
  // to override it in order to avoid having to implement the padding
  // functionality demanded by those, higher level, operations.
  int (*private_transform)(RSA *rsa, uint8_t *out, const uint8_t *in,
                           size_t len);

  int flags;
};


// Private functions.

typedef struct bn_blinding_st BN_BLINDING;

struct rsa_st {
  RSA_METHOD *meth;

  BIGNUM *n;
  BIGNUM *e;
  BIGNUM *d;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *dmp1;
  BIGNUM *dmq1;
  BIGNUM *iqmp;

  // be careful using this if the RSA structure is shared
  CRYPTO_EX_DATA ex_data;
  CRYPTO_refcount_t references;
  int flags;

  CRYPTO_MUTEX lock;

  // Used to cache montgomery values. The creation of these values is protected
  // by |lock|.
  BN_MONT_CTX *mont_n;
  BN_MONT_CTX *mont_p;
  BN_MONT_CTX *mont_q;

  // num_blindings contains the size of the |blindings| and |blindings_inuse|
  // arrays. This member and the |blindings_inuse| array are protected by
  // |lock|.
  unsigned num_blindings;
  // blindings is an array of BN_BLINDING structures that can be reserved by a
  // thread by locking |lock| and changing the corresponding element in
  // |blindings_inuse| from 0 to 1.
  BN_BLINDING **blindings;
  unsigned char *blindings_inuse;
};


#if defined(__cplusplus)
}  // extern C

extern "C++" {

namespace bssl {

BORINGSSL_MAKE_DELETER(RSA, RSA_free)

}  // namespace bssl

}  // extern C++

#endif

#define RSA_R_BAD_ENCODING 100
#define RSA_R_BAD_E_VALUE 101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT 102
#define RSA_R_BAD_PAD_BYTE_COUNT 103
#define RSA_R_BAD_RSA_PARAMETERS 104
#define RSA_R_BAD_SIGNATURE 105
#define RSA_R_BAD_VERSION 106
#define RSA_R_BLOCK_TYPE_IS_NOT_01 107
#define RSA_R_BN_NOT_INITIALIZED 108
#define RSA_R_CANNOT_RECOVER_MULTI_PRIME_KEY 109
#define RSA_R_CRT_PARAMS_ALREADY_GIVEN 110
#define RSA_R_CRT_VALUES_INCORRECT 111
#define RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN 112
#define RSA_R_DATA_TOO_LARGE 113
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE 114
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS 115
#define RSA_R_DATA_TOO_SMALL 116
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE 117
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY 118
#define RSA_R_D_E_NOT_CONGRUENT_TO_1 119
#define RSA_R_EMPTY_PUBLIC_KEY 120
#define RSA_R_ENCODE_ERROR 121
#define RSA_R_FIRST_OCTET_INVALID 122
#define RSA_R_INCONSISTENT_SET_OF_CRT_VALUES 123
#define RSA_R_INTERNAL_ERROR 124
#define RSA_R_INVALID_MESSAGE_LENGTH 125
#define RSA_R_KEY_SIZE_TOO_SMALL 126
#define RSA_R_LAST_OCTET_INVALID 127
#define RSA_R_MODULUS_TOO_LARGE 128
#define RSA_R_MUST_HAVE_AT_LEAST_TWO_PRIMES 129
#define RSA_R_NO_PUBLIC_EXPONENT 130
#define RSA_R_NULL_BEFORE_BLOCK_MISSING 131
#define RSA_R_N_NOT_EQUAL_P_Q 132
#define RSA_R_OAEP_DECODING_ERROR 133
#define RSA_R_ONLY_ONE_OF_P_Q_GIVEN 134
#define RSA_R_OUTPUT_BUFFER_TOO_SMALL 135
#define RSA_R_PADDING_CHECK_FAILED 136
#define RSA_R_PKCS_DECODING_ERROR 137
#define RSA_R_SLEN_CHECK_FAILED 138
#define RSA_R_SLEN_RECOVERY_FAILED 139
#define RSA_R_TOO_LONG 140
#define RSA_R_TOO_MANY_ITERATIONS 141
#define RSA_R_UNKNOWN_ALGORITHM_TYPE 142
#define RSA_R_UNKNOWN_PADDING_TYPE 143
#define RSA_R_VALUE_MISSING 144
#define RSA_R_WRONG_SIGNATURE_LENGTH 145
#define RSA_R_PUBLIC_KEY_VALIDATION_FAILED 146

#endif  // OPENSSL_HEADER_RSA_H
