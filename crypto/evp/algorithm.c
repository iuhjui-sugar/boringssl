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

#include <assert.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

#include "internal.h"


/* Given an MGF1 Algorithm ID decode to an Algorithm Identifier */
static X509_ALGOR *rsa_mgf1_decode(X509_ALGOR *alg) {
  const uint8_t *p;
  int plen;

  if (alg == NULL || alg->parameter == NULL ||
      OBJ_obj2nid(alg->algorithm) != NID_mgf1 ||
      alg->parameter->type != V_ASN1_SEQUENCE) {
    return NULL;
  }

  p = alg->parameter->value.sequence->data;
  plen = alg->parameter->value.sequence->length;
  return d2i_X509_ALGOR(NULL, &p, plen);
}

RSA_PSS_PARAMS *rsa_pss_decode(const X509_ALGOR *alg, X509_ALGOR **pmaskHash) {
  const uint8_t *p;
  int plen;
  RSA_PSS_PARAMS *pss;

  *pmaskHash = NULL;

  if (!alg->parameter || alg->parameter->type != V_ASN1_SEQUENCE) {
    return NULL;
  }
  p = alg->parameter->value.sequence->data;
  plen = alg->parameter->value.sequence->length;
  pss = d2i_RSA_PSS_PARAMS(NULL, &p, plen);

  if (!pss) {
    return NULL;
  }

  *pmaskHash = rsa_mgf1_decode(pss->maskGenAlgorithm);

  return pss;
}

/* allocate and set algorithm ID from EVP_MD, default SHA1 */
static int rsa_md_to_algor(X509_ALGOR **palg, const EVP_MD *md) {
  if (EVP_MD_type(md) == NID_sha1) {
    return 1;
  }
  *palg = X509_ALGOR_new();
  if (!*palg) {
    return 0;
  }
  X509_ALGOR_set_md(*palg, md);
  return 1;
}

/* Allocate and set MGF1 algorithm ID from EVP_MD */
static int rsa_md_to_mgf1(X509_ALGOR **palg, const EVP_MD *mgf1md) {
  X509_ALGOR *algtmp = NULL;
  ASN1_STRING *stmp = NULL;
  *palg = NULL;

  if (EVP_MD_type(mgf1md) == NID_sha1) {
    return 1;
  }
  /* need to embed algorithm ID inside another */
  if (!rsa_md_to_algor(&algtmp, mgf1md) ||
      !ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp)) {
    goto err;
  }
  *palg = X509_ALGOR_new();
  if (!*palg) {
    goto err;
  }
  X509_ALGOR_set0(*palg, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, stmp);
  stmp = NULL;

err:
  ASN1_STRING_free(stmp);
  X509_ALGOR_free(algtmp);
  if (*palg) {
    return 1;
  }

  return 0;
}

/* convert algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_algor_to_md(X509_ALGOR *alg) {
  const EVP_MD *md;
  if (!alg) {
    return EVP_sha1();
  }
  md = EVP_get_digestbyobj(alg->algorithm);
  if (md == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_DIGEST);
  }
  return md;
}

/* convert MGF1 algorithm ID to EVP_MD, default SHA1 */
static const EVP_MD *rsa_mgf1_to_md(X509_ALGOR *alg, X509_ALGOR *maskHash) {
  const EVP_MD *md;
  if (!alg) {
    return EVP_sha1();
  }
  /* Check mask and lookup mask hash algorithm */
  if (OBJ_obj2nid(alg->algorithm) != NID_mgf1) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_MASK_ALGORITHM);
    return NULL;
  }
  if (!maskHash) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_MASK_PARAMETER);
    return NULL;
  }
  md = EVP_get_digestbyobj(maskHash->algorithm);
  if (md == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_MASK_DIGEST);
    return NULL;
  }
  return md;
}

/* rsa_ctx_to_pss converts EVP_PKEY_CTX in PSS mode into corresponding
 * algorithm parameter, suitable for setting as an AlgorithmIdentifier. */
static ASN1_STRING *rsa_ctx_to_pss(EVP_PKEY_CTX *pkctx) {
  const EVP_MD *sigmd, *mgf1md;
  RSA_PSS_PARAMS *pss = NULL;
  ASN1_STRING *os = NULL;
  EVP_PKEY *pk = EVP_PKEY_CTX_get0_pkey(pkctx);
  int saltlen, rv = 0;

  if (!EVP_PKEY_CTX_get_signature_md(pkctx, &sigmd) ||
      !EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) ||
      !EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &saltlen)) {
    goto err;
  }

  if (saltlen == -1) {
    saltlen = EVP_MD_size(sigmd);
  } else if (saltlen == -2) {
    saltlen = EVP_PKEY_size(pk) - EVP_MD_size(sigmd) - 2;
    if (((EVP_PKEY_bits(pk) - 1) & 0x7) == 0) {
      saltlen--;
    }
  } else {
    goto err;
  }

  pss = RSA_PSS_PARAMS_new();
  if (!pss) {
    goto err;
  }

  if (saltlen != 20) {
    pss->saltLength = ASN1_INTEGER_new();
    if (!pss->saltLength ||
        !ASN1_INTEGER_set(pss->saltLength, saltlen)) {
      goto err;
    }
  }

  if (!rsa_md_to_algor(&pss->hashAlgorithm, sigmd) ||
      !rsa_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md)) {
    goto err;
  }

  /* Finally create string with pss parameter encoding. */
  if (!ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &os)) {
    goto err;
  }
  rv = 1;

err:
  if (pss) {
    RSA_PSS_PARAMS_free(pss);
  }
  if (rv) {
    return os;
  }
  if (os) {
    ASN1_STRING_free(os);
  }
  return NULL;
}

/* From PSS AlgorithmIdentifier set public key parameters. */
static int rsa_pss_to_ctx(EVP_MD_CTX *ctx, X509_ALGOR *sigalg, EVP_PKEY *pkey) {
  int ret = 0;
  int saltlen;
  const EVP_MD *mgf1md = NULL, *md = NULL;
  RSA_PSS_PARAMS *pss;
  X509_ALGOR *maskHash;
  EVP_PKEY_CTX *pkctx;

  /* Sanity check: make sure it is PSS */
  if (OBJ_obj2nid(sigalg->algorithm) != NID_rsassaPss) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_SIGNATURE_TYPE);
    return 0;
  }
  /* Decode PSS parameters */
  pss = rsa_pss_decode(sigalg, &maskHash);
  if (pss == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_PSS_PARAMETERS);
    goto err;
  }

  mgf1md = rsa_mgf1_to_md(pss->maskGenAlgorithm, maskHash);
  if (!mgf1md) {
    goto err;
  }
  md = rsa_algor_to_md(pss->hashAlgorithm);
  if (!md) {
    goto err;
  }

  saltlen = 20;
  if (pss->saltLength) {
    saltlen = ASN1_INTEGER_get(pss->saltLength);

    /* Could perform more salt length sanity checks but the main
     * RSA routines will trap other invalid values anyway. */
    if (saltlen < 0) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_SALT_LENGTH);
      goto err;
    }
  }

  /* low-level routines support only trailer field 0xbc (value 1)
   * and PKCS#1 says we should reject any other value anyway. */
  if (pss->trailerField && ASN1_INTEGER_get(pss->trailerField) != 1) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_TRAILER);
    goto err;
  }

  if (!EVP_DigestVerifyInit(ctx, &pkctx, md, NULL, pkey) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) ||
      !EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md)) {
    goto err;
  }

  ret = 1;

err:
  RSA_PSS_PARAMS_free(pss);
  if (maskHash) {
    X509_ALGOR_free(maskHash);
  }
  return ret;
}

int EVP_DigestSignAlgorithm(EVP_MD_CTX *ctx, X509_ALGOR *algor) {
  const EVP_MD *digest;
  EVP_PKEY *pkey;
  int sign_nid, paramtype;

  digest = EVP_MD_CTX_md(ctx);
  pkey = EVP_PKEY_CTX_get0_pkey(ctx->pctx);
  if (!digest || !pkey) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_CONTEXT_NOT_INITIALISED);
    return 0;
  }

  if (pkey->type == EVP_PKEY_RSA) {
    int pad_mode;
    if (!EVP_PKEY_CTX_get_rsa_padding(ctx->pctx, &pad_mode)) {
      return 0;
    }
    /* RSA-PSS has special signature algorithm logic. */
    if (pad_mode == RSA_PKCS1_PSS_PADDING) {
      ASN1_STRING *os1 = rsa_ctx_to_pss(ctx->pctx);
      if (!os1) {
        return 0;
      }
      X509_ALGOR_set0(algor, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, os1);
      return 1;
    }
  }

  /* Default behavior: look up the OID for the algorithm/hash pair and encode
   * that. */
  if (!OBJ_find_sigid_by_algs(&sign_nid, EVP_MD_type(digest),
                              pkey->ameth->pkey_id)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
    return 0;
  }

  if (pkey->ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL) {
    paramtype = V_ASN1_NULL;
  } else {
    paramtype = V_ASN1_UNDEF;
  }

  X509_ALGOR_set0(algor, OBJ_nid2obj(sign_nid), paramtype, NULL);
  return 1;
}

int EVP_DigestVerifyInitFromAlgorithm(EVP_MD_CTX *ctx,
                                      X509_ALGOR *algor,
                                      EVP_PKEY *pkey) {
  int digest_nid, pkey_nid;
  const EVP_PKEY_ASN1_METHOD *ameth;
  const EVP_MD *digest;

  /* Convert signature OID into digest and public key OIDs */
  if (!OBJ_find_sigid_algs(OBJ_obj2nid(algor->algorithm), &digest_nid,
                           &pkey_nid)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_SIGNATURE_ALGORITHM);
    return 0;
  }

  /* Check public key OID matches public key type */
  ameth = EVP_PKEY_asn1_find(NULL, pkey_nid);
  if (ameth == NULL || ameth->pkey_id != pkey->type) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_WRONG_PUBLIC_KEY_TYPE);
    return 0;
  }

  /* NID_undef signals that there are custom parameters to set. */
  if (digest_nid == NID_undef) {
    if (pkey->type != EVP_PKEY_RSA ||
        OBJ_obj2nid(algor->algorithm) != NID_rsassaPss) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_SIGNATURE_ALGORITHM);
      return 0;
    }

    return rsa_pss_to_ctx(ctx, algor, pkey);
  }

  /* Otherwise, initialize with the digest from the OID. */
  digest = EVP_get_digestbynid(digest_nid);
  if (digest == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
    return 0;
  }

  return EVP_DigestVerifyInit(ctx, NULL, digest, NULL, pkey);
}
