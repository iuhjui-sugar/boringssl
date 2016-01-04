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

#include <openssl/evp.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>


static EVP_PKEY *old_priv_decode(int type, const uint8_t **inp, long len) {
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL) {
    return NULL;
  }

  switch (type) {
    case EVP_PKEY_EC: {
      EC_KEY *ec_key = d2i_ECPrivateKey(NULL, inp, len);
      if (ec_key == NULL || !EVP_PKEY_assign_EC_KEY(ret, ec_key)) {
        EC_KEY_free(ec_key);
        goto err;
      }
      return ret;
    }
    case EVP_PKEY_DSA: {
      DSA *dsa = d2i_DSAPrivateKey(NULL, inp, len);
      if (dsa == NULL || !EVP_PKEY_assign_DSA(ret, dsa)) {
        DSA_free(dsa);
        goto err;
      }
      return ret;
    }
    case EVP_PKEY_RSA: {
      RSA *rsa = d2i_RSAPrivateKey(NULL, inp, len);
      if (rsa == NULL || !EVP_PKEY_assign_RSA(ret, rsa)) {
        RSA_free(rsa);
        goto err;
      }
      return ret;
    }
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_PUBLIC_KEY_TYPE);
      goto err;
  }

err:
  EVP_PKEY_free(ret);
  return NULL;
}

EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **out, const uint8_t **inp,
                         long len) {
  /* Parse with the legacy format. */
  const uint8_t *in = *inp;
  EVP_PKEY *ret = old_priv_decode(type, &in, len);

  if (ret == NULL) {
    /* Reset |in| in case |old_priv_decode| advanced it on error. */
    in = *inp;

    /* Try again with PKCS#8. */
    PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &in, len);
    if (p8 == NULL) {
      return NULL;
    }
    EVP_PKEY_free(ret);
    ret = EVP_PKCS82PKEY(p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (ret == NULL) {
      return NULL;
    }
  }

  if (out != NULL) {
    EVP_PKEY_free(*out);
    *out = ret;
  }
  *inp = in;
  return ret;
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **out, const uint8_t **inp, long len) {
  STACK_OF(ASN1_TYPE) *inkey;
  const uint8_t *p;
  int keytype;
  p = *inp;

  /* Dirty trick: read in the ASN1 data into out STACK_OF(ASN1_TYPE):
   * by analyzing it we can determine the passed structure: this
   * assumes the input is surrounded by an ASN1 SEQUENCE. */
  inkey = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len);
  /* Since we only need to discern "traditional format" RSA and DSA
   * keys we can just count the elements. */
  if (sk_ASN1_TYPE_num(inkey) == 6) {
    keytype = EVP_PKEY_DSA;
  } else if (sk_ASN1_TYPE_num(inkey) == 4) {
    keytype = EVP_PKEY_EC;
  } else if (sk_ASN1_TYPE_num(inkey) == 3) {
    /* This seems to be PKCS8, not traditional format */
    p = *inp;
    PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
    EVP_PKEY *ret;

    sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
    if (!p8) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      return NULL;
    }
    ret = EVP_PKCS82PKEY(p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (ret == NULL) {
      return NULL;
    }

    *inp = p;
    if (out) {
      *out = ret;
    }
    return ret;
  } else {
    keytype = EVP_PKEY_RSA;
  }

  sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
  return d2i_PrivateKey(keytype, out, inp, len);
}

int i2d_PublicKey(EVP_PKEY *key, uint8_t **outp) {
  switch (key->type) {
    case EVP_PKEY_RSA:
      return i2d_RSAPublicKey(key->pkey.rsa, outp);
    case EVP_PKEY_DSA:
      return i2d_DSAPublicKey(key->pkey.dsa, outp);
    case EVP_PKEY_EC:
      return i2o_ECPublicKey(key->pkey.ec, outp);
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      return -1;
  }
}
