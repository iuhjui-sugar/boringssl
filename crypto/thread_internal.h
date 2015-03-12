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

#ifndef OPENSSL_HEADER_THREAD_INTERNAL_H
#define OPENSSL_HEADER_THREAD_INTERNAL_H

#include "openssl/thread.h"

/* Lock IDs start from 1. CRYPTO_LOCK_INVALID_LOCK is an unused placeholder
 * used to ensure no lock has ID 0. */
#define CRYPTO_LOCK_LIST \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_INVALID_LOCK), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_BIO), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_DH), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_DSA), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_EC), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_EC_PRE_COMP), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_ERR), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_EVP_PKEY), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_EX_DATA), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_OBJ), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_RAND), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_READDIR), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_RSA), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_RSA_BLINDING), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_SSL_CTX), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_SSL_SESSION), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509_INFO), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509_PKEY), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509_CRL), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509_REQ), \
  CRYPTO_LOCK_ITEM(CRYPTO_LOCK_X509_STORE), \

#define CRYPTO_LOCK_ITEM(x) x

enum {
  CRYPTO_LOCK_LIST
};

#undef CRYPTO_LOCK_ITEM

#endif /* OPENSSL_HEADER_THREAD_INTERNAL_H */
