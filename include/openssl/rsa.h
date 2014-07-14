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

#if defined(__cplusplus)
extern "C" {
#endif


/* rsa.h contains functions for handling encryption and signature using RSA. */


/* Allocation and destruction. */

/* RSA_new returns a new, empty RSA object or NULL on error. */
RSA *RSA_new(void);

/* RSA_new_method acts the same as |DH_new| but takes an explicit |ENGINE|. */
RSA *RSA_new_method(const ENGINE *engine);

/* RSA_free decrements the reference count of |rsa| and frees it if the
 * reference count drops to zero. */
void RSA_free(RSA *rsa);

/* RSA_up_ref increments the reference count of |rsa|. */
int RSA_up_ref(RSA *rsa);


/* Key generation. */

/* RSA_generate_key_ex generates a new RSA key where the modulus has size
 * |bits| and the public exponent is |e|. If unsure, |RSA_F4| is a good value
 * for |e|. If |cb| is not NULL then it is called during the key generation
 * process. In addition to the calls documented for |BN_generate_prime_ex|, it
 * is called with event=2 when the n'th prime is rejected as unsuitable and
 * with event=3 when a suitable value for |p| is found. */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);


/* Encryption / Decryption */

/* Padding types for encryption. */
#define RSA_PKCS1_PADDING 1
#define RSA_SSLV23_PADDING 2
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
/* RSA_PKCS1_PSS_PADDING can only be used via the EVP interface. */
#define RSA_PKCS1_PSS_PADDING 6

/* RSA_encrypt encrypts |in_len| bytes from |in| to the public key from |rsa|
 * and writes, at most, |max_out| bytes of encrypted data to |out|. The
 * |max_out| argument must be, at least, |RSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. If in
 * doubt, |RSA_PKCS1_PADDING| is the most common but |RSA_PKCS1_OAEP_PADDING|
 * is the most secure. */
int RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding);

/* RSA_decrypt decrypts |in_len| bytes from |in| with the private key from
 * |rsa| and writes, at most, |max_out| bytes of plaintext to |out|. The
 * |max_out| argument must be, at least, |RSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. If in
 * doubt, |RSA_PKCS1_PADDING| is the most common but |RSA_PKCS1_OAEP_PADDING|
 * is the most secure. */
int RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding);

/* RSA_public_encrypt encrypts |flen| bytes from |from| to the public key in
 * |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
 * least |RSA_size| bytes of space. It returns the number of bytes written, or
 * -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
 * values. If in doubt, |RSA_PKCS1_PADDING| is the most common but
 * |RSA_PKCS1_OAEP_PADDING| is the most secure.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |RSA_encrypt| instead. */
int RSA_public_encrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding);

/* RSA_private_decrypt decrypts |flen| bytes from |from| with the public key in
 * |rsa| and writes the plaintext to |to|. The |to| buffer must have at
 * least |RSA_size| bytes of space. It returns the number of bytes written, or
 * -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
 * values. If in doubt, |RSA_PKCS1_PADDING| is the most common but
 * |RSA_PKCS1_OAEP_PADDING| is the most secure.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |RSA_decrypt| instead. */
int RSA_private_decrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding);


/* Signing / Verification */

/* RSA_sign signs |in_len| bytes of digest from |in| with |rsa| and writes, at
 * most, |RSA_size(rsa)| bytes to |out|. On successful return, the actual
 * number of bytes written is written to |*out_len|.
 *
 * The |hash_nid| argument identifies the hash function used to calculate |in|
 * and is embedded in the resulting signature. For example, it might be
 * |NID_sha256|.
 *
 * It returns 1 on success and zero on error. */
int RSA_sign(int hash_nid, const uint8_t *in, unsigned int in_len, uint8_t *out,
             unsigned int *out_len, RSA *rsa);

/* RSA_sign_raw signs |in_len| bytes from |in| with the public key from |rsa|
 * and writes, at most, |max_out| bytes of encrypted data to |out|. The
 * |max_out| argument must be, at least, |RSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. If in
 * doubt, |RSA_PKCS1_PADDING| is the most common. */
int RSA_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);

/* RSA_verify verifies that |sig_len| bytes from |sig| are a valid, PKCS#1
 * signature of |msg_len| bytes at |msg| by |rsa|.
 *
 * The |hash_nid| argument identifies the hash function used to calculate |in|
 * and is embedded in the resulting signature in order to prevent hash
 * confusion attacks. For example, it might be |NID_sha256|.
 *
 * It returns one if the signature is valid and zero otherwise.
 *
 * WARNING: this differs from the original, OpenSSL function which additionally
 * returned -1 on error. */
int RSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len, RSA *rsa);

/* RSA_verify_raw verifies |in_len| bytes of signature from |in| using the
 * public key from |rsa| and writes, at most, |max_out| bytes of plaintext to
 * |out|. The |max_out| argument must be, at least, |RSA_size| in order to
 * ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. If in
 * doubt, |RSA_PKCS1_PADDING| is the most common. */
int RSA_verify_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                   const uint8_t *in, size_t in_len, int padding);

/* RSA_private_encrypt encrypts |flen| bytes from |from| with the private key in
 * |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
 * least |RSA_size| bytes of space. It returns the number of bytes written, or
 * -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
 * values. If in doubt, |RSA_PKCS1_PADDING| is the most common.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |RSA_sign_raw| instead. */
int RSA_private_encrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding);

/* RSA_private_encrypt verifies |flen| bytes of signature from |from| using the
 * public key in |rsa| and writes the plaintext to |to|. The |to| buffer must
 * have at least |RSA_size| bytes of space. It returns the number of bytes
 * written, or -1 on error. The |padding| argument must be one of the
 * |RSA_*_PADDING| values. If in doubt, |RSA_PKCS1_PADDING| is the most common.
 *
 * WARNING: this function is dangerous because it breaks the usual return value
 * convention. Use |RSA_verify_raw| instead. */
int RSA_public_decrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding);


/* Utility functions. */

/* RSA_size returns the number of bytes in the modulus, which is also the size
 * of a signature of encrypted value using |rsa|. */
unsigned RSA_size(const RSA *rsa);

/* RSAPublicKey_dup allocates a fresh |RSA| and copies the private key from
 * |rsa| into it. It returns the fresh |RSA| object, or NULL on error. */
RSA *RSAPublicKey_dup(const RSA *rsa);

/* RSAPrivateKey_dup allocates a fresh |RSA| and copies the private key from
 * |rsa| into it. It returns the fresh |RSA| object, or NULL on error. */
RSA *RSAPrivateKey_dup(const RSA *rsa);

/* RSA_recover_crt_params uses |rsa->n|, |rsa->d| and |rsa->e| in order to
 * calculate the two primes used and thus the precomputed, CRT values. These
 * values are set in the |p|, |q|, |dmp1|, |dmq1| and |iqmp| members of |rsa|,
 * which must be |NULL| on entry. It returns one on success and zero
 * otherwise. */
int RSA_recover_crt_params(RSA *rsa);


/* ASN.1 functions. */

/* d2i_RSAPublicKey parses an ASN.1, DER-encoded, RSA public key from |len|
 * bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
 * is in |*out|. If |*out| is already non-NULL on entry then the result is
 * written directly into |*out|, otherwise a fresh |RSA| is allocated. On
 * successful exit, |*inp| is advanced past the DER structure. It returns the
 * result or NULL on error. */
RSA *d2i_RSAPublicKey(RSA **out, const uint8_t **inp, long len);

/* i2d_RSAPublicKey marshals |in| to an ASN.1, DER structure. If |outp| is not
 * NULL then the result is written to |*outp| and |*outp| is advanced just past
 * the output. It returns the number of bytes in the result, whether written or
 * not, or a negative value on error. */
int i2d_RSAPublicKey(const RSA *in, uint8_t **outp);

/* d2i_RSAPrivateKey parses an ASN.1, DER-encoded, RSA private key from |len|
 * bytes at |*inp|. If |out| is not NULL then, on exit, a pointer to the result
 * is in |*out|. If |*out| is already non-NULL on entry then the result is
 * written directly into |*out|, otherwise a fresh |RSA| is allocated. On
 * successful exit, |*inp| is advanced past the DER structure. It returns the
 * result or NULL on error. */
RSA *d2i_RSAPrivateKey(RSA **out, const uint8_t **inp, long len);

/* i2d_RSAPrivateKey marshals |in| to an ASN.1, DER structure. If |outp| is not
 * NULL then the result is written to |*outp| and |*outp| is advanced just past
 * the output. It returns the number of bytes in the result, whether written or
 * not, or a negative value on error. */
int i2d_RSAPrivateKey(const RSA *in, uint8_t **outp);


/* ex_data functions.
 *
 * These functions are wrappers. See |ex_data.h| for details. */

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r, int idx, void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);


/* RSA_FLAG_CACHE_PUBLIC causes a precomputed Montgomery context to be created,
 * on demand, for the public key operations. */
#define RSA_FLAG_CACHE_PUBLIC 2

/* RSA_FLAG_CACHE_PRIVATE causes a precomputed Montgomery context to be
 * created, on demand, for the private key operations. */
#define RSA_FLAG_CACHE_PRIVATE 4

/* RSA_FLAG_NO_BLINDING disables blinding of private operations. */
#define RSA_FLAG_NO_BLINDING 8

/* RSA_FLAG_EXT_PKEY means that private key operations will be handled by
 * |mod_exp| and that they do not depend on the private key components being
 * present: for example a key stored in external hardware. */
#define RSA_FLAG_EXT_PKEY 0x20

/* RSA_FLAG_SIGN_VER causes the |sign| and |verify| functions of |rsa_meth_st|
 * to be called when set. */
#define RSA_FLAG_SIGN_VER 0x40


/* RSA public exponent values. */

#define RSA_3 0x3
#define RSA_F4 0x10001


struct rsa_meth_st {
  struct openssl_method_common_st common;

  void *app_data;

  int (*init)(RSA *rsa);
  int (*finish)(RSA *rsa);

  /* size returns the size of the RSA modulus in bytes. */
  size_t (*size)(const RSA *rsa);

  int (*sign)(int type, const uint8_t *m, unsigned int m_length,
              uint8_t *sigret, unsigned int *siglen, const RSA *rsa);

  int (*verify)(int dtype, const uint8_t *m, unsigned int m_length,
                const uint8_t *sigbuf, unsigned int siglen, const RSA *rsa);


  /* These functions mirror the |RSA_*| functions of the same name. */
  int (*encrypt)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);
  int (*sign_raw)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                  const uint8_t *in, size_t in_len, int padding);

  int (*decrypt)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding);
  int (*verify_raw)(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                    const uint8_t *in, size_t in_len, int padding);

  int (*mod_exp)(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                 BN_CTX *ctx); /* Can be null */
  int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx,
                    BN_MONT_CTX *m_ctx);

  int flags;

  int (*keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
};


/* Private functions. */

typedef struct bn_blinding_st BN_BLINDING;

struct rsa_st {
  /* version is only used during ASN.1 (de)serialisation. */
  long version;
  RSA_METHOD *meth;

  BIGNUM *n;
  BIGNUM *e;
  BIGNUM *d;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *dmp1;
  BIGNUM *dmq1;
  BIGNUM *iqmp;
  /* be careful using this if the RSA structure is shared */
  CRYPTO_EX_DATA ex_data;
  int references;
  int flags;

  /* Used to cache montgomery values */
  BN_MONT_CTX *_method_mod_n;
  BN_MONT_CTX *_method_mod_p;
  BN_MONT_CTX *_method_mod_q;

  /* num_blindings contains the size of the |blindings| and |blindings_inuse|
   * arrays. This member and the |blindings_inuse| array are protected by
   * CRYPTO_LOCK_RSA_BLINDING. */
  unsigned num_blindings;
  /* blindings is an array of BN_BLINDING structures that can be reserved by a
   * thread by locking CRYPTO_LOCK_RSA_BLINDING and changing the corresponding
   * element in |blindings_inuse| from 0 to 1. */
  BN_BLINDING **blindings;
  unsigned char *blindings_inuse;
};


#if defined(__cplusplus)
}  /* extern C */
#endif

#define RSA_F_RSA_padding_check_none 100
#define RSA_F_RSA_padding_add_none 101
#define RSA_F_RSA_padding_check_PKCS1_OAEP_mgf1 102
#define RSA_F_RSA_verify_PKCS1_PSS_mgf1 103
#define RSA_F_RSA_padding_add_PKCS1_PSS_mgf1 104
#define RSA_F_RSA_verify 105
#define RSA_F_rsa_setup_blinding 106
#define RSA_F_verify_raw 107
#define RSA_F_RSA_padding_add_PKCS1_type_1 108
#define RSA_F_keygen 109
#define RSA_F_RSA_padding_add_PKCS1_OAEP_mgf1 110
#define RSA_F_pkcs1_prefixed_msg 111
#define RSA_F_BN_BLINDING_update 112
#define RSA_F_RSA_padding_check_SSLv23 113
#define RSA_F_RSA_padding_add_SSLv23 114
#define RSA_F_BN_BLINDING_new 115
#define RSA_F_RSA_padding_add_PKCS1_type_2 116
#define RSA_F_BN_BLINDING_convert_ex 117
#define RSA_F_BN_BLINDING_invert_ex 118
#define RSA_F_encrypt 119
#define RSA_F_sign_raw 120
#define RSA_F_RSA_new_method 121
#define RSA_F_RSA_padding_check_PKCS1_type_1 122
#define RSA_F_RSA_sign 123
#define RSA_F_BN_BLINDING_create_param 124
#define RSA_F_decrypt 125
#define RSA_F_RSA_padding_check_PKCS1_type_2 126
#define RSA_F_RSA_recover_crt_params 127
#define RSA_R_INVALID_MESSAGE_LENGTH 100
#define RSA_R_DATA_GREATER_THAN_MOD_LEN 101
#define RSA_R_NO_PUBLIC_EXPONENT 102
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE 103
#define RSA_R_BLOCK_TYPE_IS_NOT_01 104
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE 105
#define RSA_R_UNKNOWN_PADDING_TYPE 106
#define RSA_R_TOO_MANY_ITERATIONS 107
#define RSA_R_SLEN_RECOVERY_FAILED 108
#define RSA_R_WRONG_SIGNATURE_LENGTH 109
#define RSA_R_MODULUS_TOO_LARGE 110
#define RSA_R_NULL_BEFORE_BLOCK_MISSING 111
#define RSA_R_DATA_TOO_LARGE 112
#define RSA_R_OUTPUT_BUFFER_TOO_SMALL 113
#define RSA_R_SLEN_CHECK_FAILED 114
#define RSA_R_FIRST_OCTET_INVALID 115
#define RSA_R_BAD_E_VALUE 116
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS 117
#define RSA_R_EMPTY_PUBLIC_KEY 118
#define RSA_R_BAD_PAD_BYTE_COUNT 119
#define RSA_R_OAEP_DECODING_ERROR 120
#define RSA_R_TOO_LONG 121
#define RSA_R_BAD_FIXED_HEADER_DECRYPT 122
#define RSA_R_DATA_TOO_SMALL 123
#define RSA_R_UNKNOWN_ALGORITHM_TYPE 124
#define RSA_R_PADDING_CHECK_FAILED 125
#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 126
#define RSA_R_BLOCK_TYPE_IS_NOT_02 127
#define RSA_R_LAST_OCTET_INVALID 128
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY 129
#define RSA_R_SSLV3_ROLLBACK_ATTACK 130
#define RSA_R_KEY_SIZE_TOO_SMALL 131
#define RSA_R_BAD_SIGNATURE 132
#define RSA_R_BN_NOT_INITIALIZED 133
#define RSA_R_PKCS_DECODING_ERROR 134
#define RSA_R_BAD_RSA_PARAMETERS 135
#define RSA_R_INTERNAL_ERROR 136
#define RSA_R_CRT_PARAMS_ALREADY_GIVEN 137

#endif  /* OPENSSL_HEADER_RSA_H */
