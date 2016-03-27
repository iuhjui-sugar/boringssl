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
#include <openssl/dh.h>
#include <openssl/digest.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ex_data.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/thread.h>

#include "../internal.h"


#define OPENSSL_DSA_MAX_MODULUS_BITS 10000

/* Primality test according to FIPS PUB 186[-1], Appendix 2.1: 50 rounds of
 * Rabin-Miller */
#define DSS_prime_checks 50

static CRYPTO_EX_DATA_CLASS g_ex_data_class = CRYPTO_EX_DATA_CLASS_INIT;

DSA *DSA_new(void) {
  DSA *dsa = OPENSSL_malloc(sizeof(DSA));
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

int DSA_generate_parameters_ex(DSA *dsa, unsigned bits, const uint8_t *seed_in,
                               size_t seed_len, int *out_counter,
                               unsigned long *out_h, BN_GENCB *cb) {
  int ok = 0;
  unsigned char seed[SHA256_DIGEST_LENGTH];
  unsigned char md[SHA256_DIGEST_LENGTH];
  unsigned char buf[SHA256_DIGEST_LENGTH], buf2[SHA256_DIGEST_LENGTH];
  BIGNUM *r0, *W, *X, *c, *test;
  BIGNUM *g = NULL, *q = NULL, *p = NULL;
  BN_MONT_CTX *mont = NULL;
  int k, n = 0, m = 0;
  unsigned i;
  int counter = 0;
  int r = 0;
  BN_CTX *ctx = NULL;
  unsigned int h = 2;
  unsigned qsize;
  const EVP_MD *evpmd;

  evpmd = (bits >= 2048) ? EVP_sha256() : EVP_sha1();
  qsize = EVP_MD_size(evpmd);

  if (bits < 512) {
    bits = 512;
  }

  bits = (bits + 63) / 64 * 64;

  if (seed_in != NULL) {
    if (seed_len < (size_t)qsize) {
      return 0;
    }
    if (seed_len > (size_t)qsize) {
      /* Only consume as much seed as is expected. */
      seed_len = qsize;
    }
    memcpy(seed, seed_in, seed_len);
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }
  BN_CTX_start(ctx);

  mont = BN_MONT_CTX_new();
  if (mont == NULL) {
    goto err;
  }

  r0 = BN_CTX_get(ctx);
  g = BN_CTX_get(ctx);
  W = BN_CTX_get(ctx);
  q = BN_CTX_get(ctx);
  X = BN_CTX_get(ctx);
  c = BN_CTX_get(ctx);
  p = BN_CTX_get(ctx);
  test = BN_CTX_get(ctx);

  if (test == NULL || !BN_lshift(test, BN_value_one(), bits - 1)) {
    goto err;
  }

  for (;;) {
    /* Find q. */
    for (;;) {
      /* step 1 */
      if (!BN_GENCB_call(cb, 0, m++)) {
        goto err;
      }

      int use_random_seed = (seed_in == NULL);
      if (use_random_seed) {
        if (!RAND_bytes(seed, qsize)) {
          goto err;
        }
      } else {
        /* If we come back through, use random seed next time. */
        seed_in = NULL;
      }
      memcpy(buf, seed, qsize);
      memcpy(buf2, seed, qsize);
      /* precompute "SEED + 1" for step 7: */
      for (i = qsize - 1; i < qsize; i--) {
        buf[i]++;
        if (buf[i] != 0) {
          break;
        }
      }

      /* step 2 */
      if (!EVP_Digest(seed, qsize, md, NULL, evpmd, NULL) ||
          !EVP_Digest(buf, qsize, buf2, NULL, evpmd, NULL)) {
        goto err;
      }
      for (i = 0; i < qsize; i++) {
        md[i] ^= buf2[i];
      }

      /* step 3 */
      md[0] |= 0x80;
      md[qsize - 1] |= 0x01;
      if (!BN_bin2bn(md, qsize, q)) {
        goto err;
      }

      /* step 4 */
      r = BN_is_prime_fasttest_ex(q, DSS_prime_checks, ctx, use_random_seed, cb);
      if (r > 0) {
        break;
      }
      if (r != 0) {
        goto err;
      }

      /* do a callback call */
      /* step 5 */
    }

    if (!BN_GENCB_call(cb, 2, 0) || !BN_GENCB_call(cb, 3, 0)) {
      goto err;
    }

    /* step 6 */
    counter = 0;
    /* "offset = 2" */

    n = (bits - 1) / 160;

    for (;;) {
      if ((counter != 0) && !BN_GENCB_call(cb, 0, counter)) {
        goto err;
      }

      /* step 7 */
      BN_zero(W);
      /* now 'buf' contains "SEED + offset - 1" */
      for (k = 0; k <= n; k++) {
        /* obtain "SEED + offset + k" by incrementing: */
        for (i = qsize - 1; i < qsize; i--) {
          buf[i]++;
          if (buf[i] != 0) {
            break;
          }
        }

        if (!EVP_Digest(buf, qsize, md, NULL, evpmd, NULL)) {
          goto err;
        }

        /* step 8 */
        if (!BN_bin2bn(md, qsize, r0) ||
            !BN_lshift(r0, r0, (qsize << 3) * k) ||
            !BN_add(W, W, r0)) {
          goto err;
        }
      }

      /* more of step 8 */
      if (!BN_mask_bits(W, bits - 1) ||
          !BN_copy(X, W) ||
          !BN_add(X, X, test)) {
        goto err;
      }

      /* step 9 */
      if (!BN_lshift1(r0, q) ||
          !BN_mod(c, X, r0, ctx) ||
          !BN_sub(r0, c, BN_value_one()) ||
          !BN_sub(p, X, r0)) {
        goto err;
      }

      /* step 10 */
      if (BN_cmp(p, test) >= 0) {
        /* step 11 */
        r = BN_is_prime_fasttest_ex(p, DSS_prime_checks, ctx, 1, cb);
        if (r > 0) {
          goto end; /* found it */
        }
        if (r != 0) {
          goto err;
        }
      }

      /* step 13 */
      counter++;
      /* "offset = offset + n + 1" */

      /* step 14 */
      if (counter >= 4096) {
        break;
      }
    }
  }
end:
  if (!BN_GENCB_call(cb, 2, 1)) {
    goto err;
  }

  /* We now need to generate g */
  /* Set r0=(p-1)/q */
  if (!BN_sub(test, p, BN_value_one()) ||
      !BN_div(r0, NULL, test, q, ctx)) {
    goto err;
  }

  if (!BN_set_word(test, h) ||
      !BN_MONT_CTX_set(mont, p, ctx)) {
    goto err;
  }

  for (;;) {
    /* g=test^r0%p */
    if (!BN_mod_exp_mont(g, test, r0, p, ctx, mont)) {
      goto err;
    }
    if (!BN_is_one(g)) {
      break;
    }
    if (!BN_add(test, test, BN_value_one())) {
      goto err;
    }
    h++;
  }

  if (!BN_GENCB_call(cb, 3, 1)) {
    goto err;
  }

  ok = 1;

err:
  if (ok) {
    BN_free(dsa->p);
    BN_free(dsa->q);
    BN_free(dsa->g);
    dsa->p = BN_dup(p);
    dsa->q = BN_dup(q);
    dsa->g = BN_dup(g);
    if (dsa->p == NULL || dsa->q == NULL || dsa->g == NULL) {
      ok = 0;
      goto err;
    }
    if (out_counter != NULL) {
      *out_counter = counter;
    }
    if (out_h != NULL) {
      *out_h = h;
    }
  }

  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }

  BN_MONT_CTX_free(mont);

  return ok;
}

DSA *DSAparams_dup(const DSA *dsa) {
  DSA *ret = DSA_new();
  if (ret == NULL) {
    return NULL;
  }
  ret->p = BN_dup(dsa->p);
  ret->q = BN_dup(dsa->q);
  ret->g = BN_dup(dsa->g);
  if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
    DSA_free(ret);
    return NULL;
  }
  return ret;
}

int DSA_generate_key(DSA *dsa) {
  int ok = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *pub_key = NULL, *priv_key = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

  priv_key = dsa->priv_key;
  if (priv_key == NULL) {
    priv_key = BN_new();
    if (priv_key == NULL) {
      goto err;
    }
  }

  do {
    if (!BN_rand_range(priv_key, dsa->q)) {
      goto err;
    }
  } while (BN_is_zero(priv_key));

  pub_key = dsa->pub_key;
  if (pub_key == NULL) {
    pub_key = BN_new();
    if (pub_key == NULL) {
      goto err;
    }
  }

  BIGNUM prk;
  BN_with_flags(&prk, priv_key, BN_FLG_CONSTTIME);
  if (!BN_mod_exp(pub_key, dsa->g, &prk, dsa->p, ctx)) {
    goto err;
  }

  dsa->priv_key = priv_key;
  dsa->pub_key = pub_key;
  ok = 1;

err:
  if (dsa->pub_key == NULL) {
    BN_free(pub_key);
  }
  if (dsa->priv_key == NULL) {
    BN_free(priv_key);
  }
  BN_CTX_free(ctx);

  return ok;
}

DSA_SIG *DSA_SIG_new(void) {
  DSA_SIG *sig;
  sig = OPENSSL_malloc(sizeof(DSA_SIG));
  if (!sig) {
    return NULL;
  }
  sig->r = NULL;
  sig->s = NULL;
  return sig;
}

void DSA_SIG_free(DSA_SIG *sig) {
  if (!sig) {
    return;
  }

  BN_free(sig->r);
  BN_free(sig->s);
  OPENSSL_free(sig);
}

DSA_SIG *DSA_do_sign(const uint8_t *digest, size_t digest_len, DSA *dsa) {
  BIGNUM *kinv = NULL, *r = NULL, *s = NULL;
  BIGNUM m;
  BIGNUM xr;
  BN_CTX *ctx = NULL;
  int reason = ERR_R_BN_LIB;
  DSA_SIG *ret = NULL;
  int noredo = 0;

  BN_init(&m);
  BN_init(&xr);

  if (!dsa->p || !dsa->q || !dsa->g) {
    reason = DSA_R_MISSING_PARAMETERS;
    goto err;
  }

  s = BN_new();
  if (s == NULL) {
    goto err;
  }
  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

redo:
  if (dsa->kinv == NULL || dsa->r == NULL) {
    if (!DSA_sign_setup(dsa, ctx, &kinv, &r)) {
      goto err;
    }
  } else {
    kinv = dsa->kinv;
    dsa->kinv = NULL;
    r = dsa->r;
    dsa->r = NULL;
    noredo = 1;
  }

  if (digest_len > BN_num_bytes(dsa->q)) {
    /* if the digest length is greater than the size of q use the
     * BN_num_bits(dsa->q) leftmost bits of the digest, see
     * fips 186-3, 4.2 */
    digest_len = BN_num_bytes(dsa->q);
  }

  if (BN_bin2bn(digest, digest_len, &m) == NULL) {
    goto err;
  }

  /* Compute  s = inv(k) (m + xr) mod q */
  if (!BN_mod_mul(&xr, dsa->priv_key, r, dsa->q, ctx)) {
    goto err; /* s = xr */
  }
  if (!BN_add(s, &xr, &m)) {
    goto err; /* s = m + xr */
  }
  if (BN_cmp(s, dsa->q) > 0) {
    if (!BN_sub(s, s, dsa->q)) {
      goto err;
    }
  }
  if (!BN_mod_mul(s, s, kinv, dsa->q, ctx)) {
    goto err;
  }

  /* Redo if r or s is zero as required by FIPS 186-3: this is
   * very unlikely. */
  if (BN_is_zero(r) || BN_is_zero(s)) {
    if (noredo) {
      reason = DSA_R_NEED_NEW_SETUP_VALUES;
      goto err;
    }
    goto redo;
  }
  ret = DSA_SIG_new();
  if (ret == NULL) {
    goto err;
  }
  ret->r = r;
  ret->s = s;

err:
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(DSA, reason);
    BN_free(r);
    BN_free(s);
  }
  BN_CTX_free(ctx);
  BN_clear_free(&m);
  BN_clear_free(&xr);
  BN_clear_free(kinv);

  return ret;
}

int DSA_do_verify(const uint8_t *digest, size_t digest_len, DSA_SIG *sig,
                  const DSA *dsa) {
  int valid;
  if (!DSA_do_check_signature(&valid, digest, digest_len, sig, dsa)) {
    return -1;
  }
  return valid;
}

int DSA_do_check_signature(int *out_valid, const uint8_t *digest,
                           size_t digest_len, DSA_SIG *sig, const DSA *dsa) {
  BN_CTX *ctx;
  BIGNUM u1, u2, t1;
  int ret = 0;
  unsigned i;

  *out_valid = 0;

  if (!dsa->p || !dsa->q || !dsa->g) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_MISSING_PARAMETERS);
    return 0;
  }

  i = BN_num_bits(dsa->q);
  /* fips 186-3 allows only different sizes for q */
  if (i != 160 && i != 224 && i != 256) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_BAD_Q_VALUE);
    return 0;
  }

  if (BN_num_bits(dsa->p) > OPENSSL_DSA_MAX_MODULUS_BITS) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_MODULUS_TOO_LARGE);
    return 0;
  }

  BN_init(&u1);
  BN_init(&u2);
  BN_init(&t1);

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

  if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
      BN_ucmp(sig->r, dsa->q) >= 0) {
    ret = 1;
    goto err;
  }
  if (BN_is_zero(sig->s) || BN_is_negative(sig->s) ||
      BN_ucmp(sig->s, dsa->q) >= 0) {
    ret = 1;
    goto err;
  }

  /* Calculate W = inv(S) mod Q
   * save W in u2 */
  if (BN_mod_inverse(&u2, sig->s, dsa->q, ctx) == NULL) {
    goto err;
  }

  /* save M in u1 */
  if (digest_len > (i >> 3)) {
    /* if the digest length is greater than the size of q use the
     * BN_num_bits(dsa->q) leftmost bits of the digest, see
     * fips 186-3, 4.2 */
    digest_len = (i >> 3);
  }

  if (BN_bin2bn(digest, digest_len, &u1) == NULL) {
    goto err;
  }

  /* u1 = M * w mod q */
  if (!BN_mod_mul(&u1, &u1, &u2, dsa->q, ctx)) {
    goto err;
  }

  /* u2 = r * w mod q */
  if (!BN_mod_mul(&u2, sig->r, &u2, dsa->q, ctx)) {
    goto err;
  }

  if (!BN_MONT_CTX_set_locked((BN_MONT_CTX **)&dsa->method_mont_p,
                              (CRYPTO_MUTEX *)&dsa->method_mont_p_lock, dsa->p,
                              ctx)) {
    goto err;
  }

  if (!BN_mod_exp2_mont(&t1, dsa->g, &u1, dsa->pub_key, &u2, dsa->p, ctx,
                        dsa->method_mont_p)) {
    goto err;
  }

  /* BN_copy(&u1,&t1); */
  /* let u1 = u1 mod q */
  if (!BN_mod(&u1, &t1, dsa->q, ctx)) {
    goto err;
  }

  /* V is now in u1.  If the signature is correct, it will be
   * equal to R. */
  *out_valid = BN_ucmp(&u1, sig->r) == 0;
  ret = 1;

err:
  if (ret != 1) {
    OPENSSL_PUT_ERROR(DSA, ERR_R_BN_LIB);
  }
  BN_CTX_free(ctx);
  BN_free(&u1);
  BN_free(&u2);
  BN_free(&t1);

  return ret;
}

int DSA_sign(int type, const uint8_t *digest, size_t digest_len,
             uint8_t *out_sig, unsigned int *out_siglen, DSA *dsa) {
  DSA_SIG *s;

  s = DSA_do_sign(digest, digest_len, dsa);
  if (s == NULL) {
    *out_siglen = 0;
    return 0;
  }

  *out_siglen = i2d_DSA_SIG(s, &out_sig);
  DSA_SIG_free(s);
  return 1;
}

int DSA_verify(int type, const uint8_t *digest, size_t digest_len,
               const uint8_t *sig, size_t sig_len, const DSA *dsa) {
  int valid;
  if (!DSA_check_signature(&valid, digest, digest_len, sig, sig_len, dsa)) {
    return -1;
  }
  return valid;
}

int DSA_check_signature(int *out_valid, const uint8_t *digest,
                        size_t digest_len, const uint8_t *sig, size_t sig_len,
                        const DSA *dsa) {
  DSA_SIG *s = NULL;
  int ret = 0;
  uint8_t *der = NULL;

  s = DSA_SIG_new();
  if (s == NULL) {
    goto err;
  }

  const uint8_t *sigp = sig;
  if (d2i_DSA_SIG(&s, &sigp, sig_len) == NULL || sigp != sig + sig_len) {
    goto err;
  }

  /* Ensure that the signature uses DER and doesn't have trailing garbage. */
  int der_len = i2d_DSA_SIG(s, &der);
  if (der_len < 0 || (size_t)der_len != sig_len || memcmp(sig, der, sig_len)) {
    goto err;
  }

  ret = DSA_do_check_signature(out_valid, digest, digest_len, s, dsa);

err:
  OPENSSL_free(der);
  DSA_SIG_free(s);
  return ret;
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

int DSA_sign_setup(const DSA *dsa, BN_CTX *ctx_in, BIGNUM **out_kinv,
                   BIGNUM **out_r) {
  BN_CTX *ctx;
  BIGNUM k, kq, *K, *kinv = NULL, *r = NULL;
  int ret = 0;

  if (!dsa->p || !dsa->q || !dsa->g) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_MISSING_PARAMETERS);
    return 0;
  }

  BN_init(&k);
  BN_init(&kq);

  ctx = ctx_in;
  if (ctx == NULL) {
    ctx = BN_CTX_new();
    if (ctx == NULL) {
      goto err;
    }
  }

  r = BN_new();
  if (r == NULL) {
    goto err;
  }

  /* Get random k */
  do {
    if (!BN_rand_range(&k, dsa->q)) {
      goto err;
    }
  } while (BN_is_zero(&k));

  BN_set_flags(&k, BN_FLG_CONSTTIME);

  if (!BN_MONT_CTX_set_locked((BN_MONT_CTX **)&dsa->method_mont_p,
                              (CRYPTO_MUTEX *)&dsa->method_mont_p_lock, dsa->p,
                              ctx)) {
    goto err;
  }

  /* Compute r = (g^k mod p) mod q */
  if (!BN_copy(&kq, &k)) {
    goto err;
  }

  /* We do not want timing information to leak the length of k,
   * so we compute g^k using an equivalent exponent of fixed length.
   *
   * (This is a kludge that we need because the BN_mod_exp_mont()
   * does not let us specify the desired timing behaviour.) */

  if (!BN_add(&kq, &kq, dsa->q)) {
    goto err;
  }
  if (BN_num_bits(&kq) <= BN_num_bits(dsa->q) && !BN_add(&kq, &kq, dsa->q)) {
    goto err;
  }

  BN_set_flags(&kq, BN_FLG_CONSTTIME);
  K = &kq;

  if (!BN_mod_exp_mont(r, dsa->g, K, dsa->p, ctx, dsa->method_mont_p)) {
    goto err;
  }
  if (!BN_mod(r, r, dsa->q, ctx)) {
    goto err;
  }

  /* Compute  part of 's = inv(k) (m + xr) mod q' */
  kinv = BN_mod_inverse(NULL, &k, dsa->q, ctx);
  if (kinv == NULL) {
    goto err;
  }

  BN_clear_free(*out_kinv);
  *out_kinv = kinv;
  kinv = NULL;
  BN_clear_free(*out_r);
  *out_r = r;
  ret = 1;

err:
  if (!ret) {
    OPENSSL_PUT_ERROR(DSA, ERR_R_BN_LIB);
    if (r != NULL) {
      BN_clear_free(r);
    }
  }

  if (ctx_in == NULL) {
    BN_CTX_free(ctx);
  }
  BN_clear_free(&k);
  BN_clear_free(&kq);
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

DH *DSA_dup_DH(const DSA *r) {
  DH *ret = NULL;

  if (r == NULL) {
    goto err;
  }
  ret = DH_new();
  if (ret == NULL) {
    goto err;
  }
  if (r->q != NULL) {
    ret->priv_length = BN_num_bits(r->q);
    if ((ret->q = BN_dup(r->q)) == NULL) {
      goto err;
    }
  }
  if ((r->p != NULL && (ret->p = BN_dup(r->p)) == NULL) ||
      (r->g != NULL && (ret->g = BN_dup(r->g)) == NULL) ||
      (r->pub_key != NULL && (ret->pub_key = BN_dup(r->pub_key)) == NULL) ||
      (r->priv_key != NULL && (ret->priv_key = BN_dup(r->priv_key)) == NULL)) {
      goto err;
  }

  return ret;

err:
  DH_free(ret);
  return NULL;
}
