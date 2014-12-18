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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#ifndef OPENSSL_HEADER_SSL_INTERNAL_H
#define OPENSSL_HEADER_SSL_INTERNAL_H

#include <openssl/base.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>

#if defined(__cplusplus)
extern "C" {
}
#endif

/* Record layer cipher state. */

typedef struct ssl_aead_ctx_st SSL_AEAD_CTX;
typedef struct ssl_cipher_state_st SSL_CIPHER_STATE;

/* SSL_AEAD_CTX contains information about an AEAD that is being used to
 * encrypt an SSL connection. */
struct ssl_aead_ctx_st {
  EVP_AEAD_CTX ctx;
  /* fixed_nonce contains any bytes of the nonce that are fixed for all
   * records. */
  uint8_t fixed_nonce[8];
  uint8_t fixed_nonce_len, variable_nonce_len, tag_len;
  /* variable_nonce_included_in_record is non-zero if the variable nonce
   * for a record is included as a prefix before the ciphertext. */
  char variable_nonce_included_in_record;
};

/* ssl_cipher_state_direction_t denotes whether an SSL_CIPHER_STATE is
 * used for encryption (writing) or decryption (reading). */
enum ssl_cipher_state_direction_t {
  ssl_cipher_state_encrypt,
  ssl_cipher_state_decrypt,
};

/* An SSL_CIPHER_STATE encapsulates state associated with encrypting
 * or decrypting records in one direction of a connection. */
struct ssl_cipher_state_st {
  /* version is the TLS version to encrypt or decrypt for. If using
   * DTLS, it is the corresponding TLS version. Note: DTLS 1.0 maps to
   * TLS 1.1, not TLS 1.0. */
  uint16_t version;
  /* aead_ctx is the AEAD context for an EVP_AEAD-based cipher.
   * Otherwise, it is NULL. */
  SSL_AEAD_CTX *aead_ctx;
  /* enc_ctx is the cipher context if |aead_ctx| is NULL. It retains
   * the IV or stream cipher state across uses. */
  EVP_CIPHER_CTX *enc_ctx;
  /* md_ctx is the HMAC context if |aead_ctx| is NULL. */
  EVP_MD_CTX *md_ctx;
};

/* SSL_CIPHER_STATE_new allocates and derives key material for a new
 * SSL_CIPHER_STATE object. It is set up for encryption or decryption
 * based on |direction|. On success, the newly allocated
 * SSL_CIPHER_STATE is returned, otherwise NULL. */
SSL_CIPHER_STATE *SSL_CIPHER_STATE_new(ssl_cipher_state_direction_t direction,
                                       uint16_t version,
                                       const SSL_CIPHER *cipher,
                                       const uint8_t *master_secret,
                                       size_t master_secret_len);

/* SSL_CIPHER_STATE_free frees any data associated with |scs| and
 * |scs| itself. */
void SSL_CIPHER_STATE_free(SSL_CIPHER_STATE *scs);

/* SSL_CIPHER_STATE_encrypt encrypts |in_len| bytes starting at |in|
 * using |scs|. It writes the output to |out| and sets |*out_len| to
 * the number of bytes written. |type|, |wire_version|, and |seqnum|
 * are the record-layer content type, the wire form of the version,
 * and the sequence number, respectively. It returns one on success
 * and zero on failure. |scs| must have been allocated for
 * encrypting. */
int SSL_CIPHER_STATE_encrypt(SSL_CIPHER_STATE *scs,
                             uint8_t *out, size_t *out_len,
                             uint8_t type, uint16_t wire_version,
                             const uint8_t seqnum[8],
                             const uint8_t *in, size_t in_len);

/* SSL_CIPHER_STATE_decrypt decrypts |in_len| bytes starting at |in|
 * using |scs|. It writes the output to |out| and sets |*out_len| to
 * the number of bytes written. |type|, |wire_version|, and |seqnum|
 * are the record-layer content type, the wire form of the version,
 * and the sequence number, respectively. It returns one on success
 * and zero on failure. |scs| must have been allocated for
 * decrypting. */
int SSL_CIPHER_STATE_decrypt(SSL_CIPHER_STATE *scs,
                             uint8_t *out, size_t *out_len,
                             uint8_t type, uint16_t wire_version,
                             const uint8_t seqnum[8],
                             const uint8_t *in, size_t in_len);


/* As the SSL implementation is reorganized bottom-up, structures will
 * move from ssl_locl.h to here. */

#if defined(__cplusplus)
} /* extern C */
#endif

/* Compatibility include until all internal structures are moved and
 * cleaned up from ssl_locl.h to internal.h */
#include "ssl_locl.h"

#endif /* OPENSSL_HEADER_SSL_INTERNAL_H */
