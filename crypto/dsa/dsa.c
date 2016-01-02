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
 *
 * The DSS routines are based on patches supplied by
 * Steven Schoch <schoch@sheba.arc.nasa.gov>. */

#include <openssl/dsa.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../internal.h"


static CRYPTO_EX_DATA_CLASS g_ex_data_class = CRYPTO_EX_DATA_CLASS_INIT;

DSA *DSA_new(void) {
  DSA *dsa = (DSA *)OPENSSL_malloc(sizeof(DSA));
  if (dsa == NULL) {
    OPENSSL_PUT_ERROR(DSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  memset(dsa, 0, sizeof(DSA));

  dsa->references = 1;

  CRYPTO_MUTEX_init(&dsa->method_mont_p_lock);
  CRYPTO_new_ex_data(&dsa->ex_data);

  return dsa;
}

void DSA_free(DSA *dsa) {
  if (dsa == NULL) {
    return;
  }

  if (!CRYPTO_refcount_dec_and_test_zero(&dsa->references)) {
    return;
  }

  CRYPTO_free_ex_data(&g_ex_data_class, dsa, &dsa->ex_data);

  BN_clear_free(dsa->p);
  BN_clear_free(dsa->q);
  BN_clear_free(dsa->g);
  BN_clear_free(dsa->pub_key);
  BN_clear_free(dsa->priv_key);
  BN_clear_free(dsa->kinv);
  BN_clear_free(dsa->r);
  BN_MONT_CTX_free(dsa->method_mont_p);
  CRYPTO_MUTEX_cleanup(&dsa->method_mont_p_lock);
  OPENSSL_free(dsa);
}

int DSA_up_ref(DSA *dsa) {
  CRYPTO_refcount_inc(&dsa->references);
  return 1;
}

/* der_len_len returns the number of bytes needed to represent a length of |len|
 * in DER. */
static size_t der_len_len(size_t len) {
  if (len < 0x80) {
    return 1;
  }
  size_t ret = 1;
  while (len > 0) {
    ret++;
    len >>= 8;
  }
  return ret;
}

int DSA_size(const DSA *dsa) {
  size_t order_len = BN_num_bytes(dsa->q);
  /* Compute the maximum length of an |order_len| byte integer. Defensively
   * assume that the leading 0x00 is included. */
  size_t integer_len = 1 /* tag */ + der_len_len(order_len + 1) + 1 + order_len;
  if (integer_len < order_len) {
    return 0;
  }
  /* A DSA signature is two INTEGERs. */
  size_t value_len = 2 * integer_len;
  if (value_len < integer_len) {
    return 0;
  }
  /* Add the header. */
  size_t ret = 1 /* tag */ + der_len_len(value_len) + value_len;
  if (ret < value_len) {
    return 0;
  }
  return ret;
}

int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class, &index, argl, argp, dup_func,
                               free_func)) {
    return -1;
  }
  return index;
}

int DSA_set_ex_data(DSA *d, int idx, void *arg) {
  return CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *DSA_get_ex_data(const DSA *d, int idx) {
  return CRYPTO_get_ex_data(&d->ex_data, idx);
}
