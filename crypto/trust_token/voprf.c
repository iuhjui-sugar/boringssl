/* Copyright (c) 2020, Google Inc.
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

#include <openssl/trust_token.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "../ec_extra/internal.h"
#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"

#include "internal.h"


typedef int (*hash_t_func_t)(const EC_GROUP *group, EC_RAW_POINT *out,
                             const uint8_t t[TRUST_TOKEN_NONCE_SIZE]);
typedef int (*hash_c_func_t)(const EC_GROUP *group, EC_SCALAR *out,
                             uint8_t *buf, size_t len);

typedef struct {
  const EC_GROUP *group;
  EC_RAW_POINT g;

  // hash_t implements the H_t operation for VOPRFs. It returns one on success
  // and zero on error.
  hash_t_func_t hash_t;
  // hash_c implements the H_c operation for VOPRFs. It returns one on success
  // and zero on error.
  hash_c_func_t hash_c;
} VOPRF_METHOD;

static const uint8_t kDefaultAdditionalData[32] = {0};

static int voprf_init_method(VOPRF_METHOD *method, int curve_nid,
                             const uint8_t *g_bytes, size_t g_len,
                             hash_t_func_t hash_t, hash_c_func_t hash_c) {
  method->group = EC_GROUP_new_by_curve_name(curve_nid);
  if (method->group == NULL) {
    return 0;
  }

  method->hash_t = hash_t;
  method->hash_c = hash_c;

  EC_AFFINE g;
  if (!ec_point_from_uncompressed(method->group, &g, g_bytes, g_len)) {
    return 0;
  }
  ec_affine_to_jacobian(method->group, &method->g, &g);
  return 1;
}

static int cbb_add_point(CBB *out, const EC_GROUP *group,
                         const EC_AFFINE *point) {
  size_t len =
      ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0);
  if (len == 0) {
    return 0;
  }

  uint8_t *p;
  return CBB_add_space(out, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p,
                           len) == len &&
      CBB_flush(out);
}
static int cbs_get_point(CBS *cbs, const EC_GROUP *group, EC_AFFINE *out) {
  CBS child;
  size_t plen = 1 + 2 * BN_num_bytes(&group->field);
  if (!CBS_get_bytes(cbs, &child, plen) ||
      !ec_point_from_uncompressed(group, out, CBS_data(&child),
                                  CBS_len(&child))) {
    return 0;
  }
  return 1;
}

static int voprf_generate_key(const VOPRF_METHOD *method, CBB *out_private,
                              CBB *out_public) {
  const EC_GROUP *group = method->group;
  EC_RAW_POINT pub;
  EC_SCALAR priv;
  if (!ec_random_nonzero_scalar(group, &priv, kDefaultAdditionalData) ||
      !ec_point_mul_scalar(group, &pub, &method->g, &priv)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  size_t scalar_len = BN_num_bytes(&group->order);
  uint8_t *buf;
  if (!CBB_add_space(out_private, &buf, scalar_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    return 0;
  }
  ec_scalar_to_bytes(group, buf, &scalar_len, &priv);

  EC_AFFINE pub_affine;
  if (!ec_jacobian_to_affine(group, &pub_affine, &pub)) {
    return 0;
  }

  if (!cbb_add_point(out_public, group, &pub_affine)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    return 0;
  }

  return 1;
}

static int voprf_client_key_from_bytes(const VOPRF_METHOD *method,
                                       TRUST_TOKEN_CLIENT_KEY *key,
                                       const uint8_t *in, size_t len) {
  CBS cbs;
  CBS_init(&cbs, in, len);
  if (!cbs_get_point(&cbs, method->group, &key->pubs)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  return 1;
}

static int voprf_issuer_key_from_bytes(const VOPRF_METHOD *method,
                                       TRUST_TOKEN_ISSUER_KEY *key,
                                       const uint8_t *in, size_t len) {
  const EC_GROUP *group = method->group;
  CBS cbs, tmp;
  CBS_init(&cbs, in, len);
  size_t scalar_len = BN_num_bytes(&group->order);
  if (!CBS_get_bytes(&cbs, &tmp, scalar_len) ||
      !ec_scalar_from_bytes(group, &key->xs, CBS_data(&tmp), CBS_len(&tmp))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  // Recompute the public key.
  EC_RAW_POINT pub;
  if (!ec_point_mul_scalar(group, &pub, &method->g, &key->xs) ||
      !ec_jacobian_to_affine(group, &key->pubs, &pub)) {
    return 0;
  }

  return 1;
}

static STACK_OF(TRUST_TOKEN_PRETOKEN) *
    voprf_blind(const VOPRF_METHOD *method, CBB *cbb, size_t count) {
  const EC_GROUP *group = method->group;
  STACK_OF(TRUST_TOKEN_PRETOKEN) *pretokens = sk_TRUST_TOKEN_PRETOKEN_new_null();
  if (pretokens == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    // Insert |pretoken| into |pretokens| early to simplify error-handling.
    TRUST_TOKEN_PRETOKEN *pretoken = OPENSSL_malloc(sizeof(TRUST_TOKEN_PRETOKEN));
    if (pretoken == NULL ||
        !sk_TRUST_TOKEN_PRETOKEN_push(pretokens, pretoken)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      TRUST_TOKEN_PRETOKEN_free(pretoken);
      goto err;
    }

    RAND_bytes(pretoken->t, sizeof(pretoken->t));

    // We sample |pretoken->r| in Montgomery form to simplify inverting.
    if (!ec_random_nonzero_scalar(group, &pretoken->r,
                                  kDefaultAdditionalData)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    EC_SCALAR rinv;
    ec_scalar_inv0_montgomery(group, &rinv, &pretoken->r);
    // Convert both out of Montgomery form.
    ec_scalar_from_montgomery(group, &pretoken->r, &pretoken->r);
    ec_scalar_from_montgomery(group, &rinv, &rinv);

    EC_RAW_POINT T, Tp;
    if (!method->hash_t(group, &T, pretoken->t) ||
        !ec_point_mul_scalar(group, &Tp, &T, &rinv) ||
        !ec_jacobian_to_affine(group, &pretoken->Tp, &Tp)) {
      goto err;
    }

    if (!cbb_add_point(cbb, group, &pretoken->Tp)) {
      goto err;
    }
  }

  return pretokens;

err:
  sk_TRUST_TOKEN_PRETOKEN_pop_free(pretokens, TRUST_TOKEN_PRETOKEN_free);
  return NULL;
}

static int scalar_to_cbb(CBB *out, const EC_GROUP *group,
                         const EC_SCALAR *scalar) {
  uint8_t *buf;
  size_t scalar_len = BN_num_bytes(&group->order);
  if (!CBB_add_space(out, &buf, scalar_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  ec_scalar_to_bytes(group, buf, &scalar_len, scalar);
  return 1;
}

static int scalar_from_cbs(CBS *cbs, const EC_GROUP *group, EC_SCALAR *out) {
  size_t scalar_len = BN_num_bytes(&group->order);
  CBS tmp;
  if (!CBS_get_bytes(cbs, &tmp, scalar_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  ec_scalar_from_bytes(group, out, CBS_data(&tmp), CBS_len(&tmp));
  return 1;
}

static int hash_c_dleq(const VOPRF_METHOD *method, EC_SCALAR *out,
                       const EC_AFFINE *X, const EC_AFFINE *T,
                       const EC_AFFINE *W, const EC_AFFINE *K0,
                       const EC_AFFINE *K1) {
  static const uint8_t kDLEQ2Label[] = "DLEQ";

  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = NULL;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, kDLEQ2Label, sizeof(kDLEQ2Label)) ||
      !cbb_add_point(&cbb, method->group, X) ||
      !cbb_add_point(&cbb, method->group, T) ||
      !cbb_add_point(&cbb, method->group, W) ||
      !cbb_add_point(&cbb, method->group, K0) ||
      !cbb_add_point(&cbb, method->group, K1) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !method->hash_c(method->group, out, buf, len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}

static int hash_c_batch(const VOPRF_METHOD *method, EC_SCALAR *out,
                        const CBB *points, size_t index) {
  static const uint8_t kDLEQBatchLabel[] = "DLEQ BATCH";
  if (index > 0xffff) {
    // The protocol supports only two-byte batches.
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_OVERFLOW);
    return 0;
  }

  int ok = 0;
  CBB cbb;
  CBB_zero(&cbb);
  uint8_t *buf = NULL;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !CBB_add_bytes(&cbb, kDLEQBatchLabel, sizeof(kDLEQBatchLabel)) ||
      !CBB_add_bytes(&cbb, CBB_data(points), CBB_len(points)) ||
      !CBB_add_u16(&cbb, (uint16_t)index) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !method->hash_c(method->group, out, buf, len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ok;
}

static int dleq_generate(const VOPRF_METHOD *method, CBB *cbb,
                         const TRUST_TOKEN_ISSUER_KEY *priv, const EC_RAW_POINT *T, const EC_RAW_POINT *W) {
  const EC_GROUP *group = method->group;

  enum {
    idx_T,
    idx_W,
    idx_k0,
    idx_k1,
    num_idx,
  };
  EC_RAW_POINT jacobians[num_idx];

  // Setup the DLEQ proof.
  EC_SCALAR r;
  if (// r <- Zp
      !ec_random_nonzero_scalar(group, &r, kDefaultAdditionalData) ||
      // k0;k1 = r*(G;T)
      !ec_point_mul_scalar(group, &jacobians[idx_k0], &method->g, &r) ||
      !ec_point_mul_scalar(group, &jacobians[idx_k1], T, &r))  {
    return 0;
  }

  EC_AFFINE affines[num_idx];
  jacobians[idx_T] = *T;
  jacobians[idx_W] = *W;
  if (!ec_jacobian_to_affine_batch(group, affines, jacobians, num_idx)) {
    return 0;
  }

  // Compute c = Hc(...).
  EC_SCALAR c;
  if (!hash_c_dleq(method, &c, &priv->pubs, &affines[idx_T], &affines[idx_W],
                   &affines[idx_k0], &affines[idx_k1])) {
    return 0;
  }


  EC_SCALAR c_mont;
  ec_scalar_to_montgomery(group, &c_mont, &c);

  // u = r + c*xs
  EC_SCALAR u;
  ec_scalar_mul_montgomery(group, &u, &priv->xs, &c_mont);
  ec_scalar_add(group, &u, &r, &u);

  // Store DLEQ proof in transcript.
  if (!scalar_to_cbb(cbb, group, &c) ||
      !scalar_to_cbb(cbb, group, &u)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  return 1;
}

static int mul_public_2(const EC_GROUP *group, EC_RAW_POINT *out,
                        const EC_RAW_POINT *p0, const EC_SCALAR *scalar0,
                        const EC_RAW_POINT *p1, const EC_SCALAR *scalar1) {
  EC_RAW_POINT points[2] = {*p0, *p1};
  EC_SCALAR scalars[2] = {*scalar0, *scalar1};
  return ec_point_mul_scalar_public_batch(group, out, /*g_scalar=*/NULL, points,
                                          scalars, 2);
}

static int dleq_verify(const VOPRF_METHOD *method, CBS *cbs,
                       const TRUST_TOKEN_CLIENT_KEY *pub, const EC_RAW_POINT *T,
                       const EC_RAW_POINT *W) {
  const EC_GROUP *group = method->group;


  enum {
    idx_T,
    idx_W,
    idx_k0,
    idx_k1,
    num_idx,
  };
  EC_RAW_POINT jacobians[num_idx];

  // Decode the DLEQ proof.
  EC_SCALAR c, u;
  if (!scalar_from_cbs(cbs, group, &c) ||
      !scalar_from_cbs(cbs, group, &u)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  // k0;k1 = u*(G;T) - c*(pub;W)
  EC_RAW_POINT pubs;
  ec_affine_to_jacobian(group, &pubs, &pub->pubs);
  EC_SCALAR minus_c;
  ec_scalar_neg(group, &minus_c, &c);
  if (!mul_public_2(group, &jacobians[idx_k0], &method->g, &u, &pubs, &minus_c) ||
      !mul_public_2(group, &jacobians[idx_k1], T, &u, W, &minus_c)) {
    return 0;
  }

  // Check the DLEQ proof.
  EC_AFFINE affines[num_idx];
  jacobians[idx_T] = *T;
  jacobians[idx_W] = *W;
  if (!ec_jacobian_to_affine_batch(group, affines, jacobians, num_idx)) {
    return 0;
  }

  // Compute c = Hc(...).
  EC_SCALAR calculated;
  if (!hash_c_dleq(method, &calculated, &pub->pubs, &affines[idx_T], &affines[idx_W],
                   &affines[idx_k0], &affines[idx_k1])) {
    return 0;
  }

  // c == calculated
  if (!ec_scalar_equal_vartime(group, &c, &calculated)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_PROOF);
    return 0;
  }

  return 1;
}

static int voprf_sign(const VOPRF_METHOD *method, const TRUST_TOKEN_ISSUER_KEY *key,
                      CBB *cbb, CBS *cbs, size_t num_requested,
                      size_t num_to_issue) {
  const EC_GROUP *group = method->group;
  if (num_requested < num_to_issue) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  if (num_to_issue > ((size_t)-1) / sizeof(EC_RAW_POINT) ||
      num_to_issue > ((size_t)-1) / sizeof(EC_SCALAR)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_OVERFLOW);
    return 0;
  }

  int ret = 0;
  EC_RAW_POINT *Tps = OPENSSL_malloc(num_to_issue * sizeof(EC_RAW_POINT));
  EC_RAW_POINT *Wps = OPENSSL_malloc(num_to_issue * sizeof(EC_RAW_POINT));
  EC_SCALAR *es = OPENSSL_malloc(num_to_issue * sizeof(EC_SCALAR));
  CBB batch_cbb;
  CBB_zero(&batch_cbb);
  if (!Tps ||
      !Wps ||
      !es ||
      !CBB_init(&batch_cbb, 0) ||
      !cbb_add_point(&batch_cbb, method->group, &key->pubs)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  for (size_t i = 0; i < num_to_issue; i++) {
    EC_AFFINE Tp_affine, Wp_affine;
    EC_RAW_POINT Tp, Wp;
    if (!cbs_get_point(cbs, group, &Tp_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }
    ec_affine_to_jacobian(group, &Tp, &Tp_affine);
    if (!ec_point_mul_scalar(group, &Wp, &Tp, &key->xs) ||
        !ec_jacobian_to_affine(group, &Wp_affine, &Wp) ||
        !cbb_add_point(cbb, group, &Wp_affine)) {
      goto err;
    }

    if (!cbb_add_point(&batch_cbb, group, &Tp_affine) ||
        !cbb_add_point(&batch_cbb, group, &Wp_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    Tps[i] = Tp;
    Wps[i] = Wp;

    if (!CBB_flush(cbb)) {
      goto err;
    }
  }

  // The DLEQ batching construction is described in appendix B of
  // https://eprint.iacr.org/2020/072/20200324:214215. Note the additional
  // computations all act on public inputs.
  for (size_t i = 0; i < num_to_issue; i++) {
    if (!hash_c_batch(method, &es[i], &batch_cbb, i)) {
      goto err;
    }
  }

  EC_RAW_POINT Tp_batch, Wp_batch;
  if (!ec_point_mul_scalar_public_batch(group, &Tp_batch,
                                        /*g_scalar=*/NULL, Tps, es,
                                        num_to_issue) ||
      !ec_point_mul_scalar_public_batch(group, &Wp_batch,
                                        /*g_scalar=*/NULL, Wps, es,
                                        num_to_issue)) {
    goto err;
  }

  CBB proof;
  if (!CBB_add_u16_length_prefixed(cbb, &proof) ||
      !dleq_generate(method, &proof, key, &Tp_batch, &Wp_batch) ||
      !CBB_flush(cbb)) {
    goto err;
  }

  // Skip over any unused requests.
  size_t point_len = 1 + 2 * BN_num_bytes(&group->field);
  if (!CBS_skip(cbs, point_len * (num_requested - num_to_issue))) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    goto err;
  }

  ret = 1;

err:
  OPENSSL_free(Tps);
  OPENSSL_free(Wps);
  OPENSSL_free(es);
  CBB_cleanup(&batch_cbb);
  return ret;
}

static STACK_OF(TRUST_TOKEN) *
    voprf_unblind(const VOPRF_METHOD *method, const TRUST_TOKEN_CLIENT_KEY *key,
                  const STACK_OF(TRUST_TOKEN_PRETOKEN) * pretokens, CBS *cbs,
                  size_t count, uint32_t key_id) {
  const EC_GROUP *group = method->group;
  if (count > sk_TRUST_TOKEN_PRETOKEN_num(pretokens)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  int ok = 0;
  STACK_OF(TRUST_TOKEN) *ret = sk_TRUST_TOKEN_new_null();
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  if (count > ((size_t)-1) / sizeof(EC_RAW_POINT) ||
      count > ((size_t)-1) / sizeof(EC_SCALAR)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_OVERFLOW);
    return 0;
  }
  EC_RAW_POINT *Tps = OPENSSL_malloc(count * sizeof(EC_RAW_POINT));
  EC_RAW_POINT *Wps = OPENSSL_malloc(count * sizeof(EC_RAW_POINT));
  EC_SCALAR *es = OPENSSL_malloc(count * sizeof(EC_SCALAR));
  CBB batch_cbb;
  CBB_zero(&batch_cbb);
  if (!Tps ||
      !Wps ||
      !es ||
      !CBB_init(&batch_cbb, 0) ||
      !cbb_add_point(&batch_cbb, method->group, &key->pubs)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    const TRUST_TOKEN_PRETOKEN *pretoken = sk_TRUST_TOKEN_PRETOKEN_value(pretokens, i);

    EC_AFFINE Wp_affine;
    if (!cbs_get_point(cbs, group, &Wp_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    ec_affine_to_jacobian(group, &Tps[i], &pretoken->Tp);
    ec_affine_to_jacobian(group, &Wps[i], &Wp_affine);

    if (!cbb_add_point(&batch_cbb, group, &pretoken->Tp) ||
        !cbb_add_point(&batch_cbb, group, &Wp_affine)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    // Unblind the token.
    EC_RAW_POINT n;
    EC_AFFINE n_affine;
    if (!ec_point_mul_scalar(group, &n, &Wps[i], &pretoken->r) ||
        !ec_jacobian_to_affine(group, &n_affine, &n)) {
      goto err;
    }

    // Serialize the token. Include |key_id| to avoid an extra copy in the layer
    // above.
    CBB token_cbb;
    size_t point_len = 1 + 2 * BN_num_bytes(&group->field);
    if (!CBB_init(&token_cbb, 4 + TRUST_TOKEN_NONCE_SIZE + (2 + point_len)) ||
        !CBB_add_u32(&token_cbb, key_id) ||
        !CBB_add_bytes(&token_cbb, pretoken->t, TRUST_TOKEN_NONCE_SIZE) ||
        !cbb_add_point(&token_cbb, group, &n_affine) ||
        !CBB_flush(&token_cbb)) {
      CBB_cleanup(&token_cbb);
      goto err;
    }

    TRUST_TOKEN *token =
        TRUST_TOKEN_new(CBB_data(&token_cbb), CBB_len(&token_cbb));
    CBB_cleanup(&token_cbb);
    if (token == NULL ||
        !sk_TRUST_TOKEN_push(ret, token)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      TRUST_TOKEN_free(token);
      goto err;
    }
  }

  // The DLEQ batching construction is described in appendix B of
  // https://eprint.iacr.org/2020/072/20200324:214215. Note the additional
  // computations all act on public inputs.
  for (size_t i = 0; i < count; i++) {
    if (!hash_c_batch(method, &es[i], &batch_cbb, i)) {
      goto err;
    }
  }

  EC_RAW_POINT Tp_batch, Wp_batch;
  if (!ec_point_mul_scalar_public_batch(group, &Tp_batch,
                                        /*g_scalar=*/NULL, Tps, es, count) ||
      !ec_point_mul_scalar_public_batch(group, &Wp_batch,
                                        /*g_scalar=*/NULL, Wps, es, count)) {
    goto err;
  }

  CBS proof;
  if (!CBS_get_u16_length_prefixed(cbs, &proof) ||
      !dleq_verify(method, &proof, key, &Tp_batch, &Wp_batch) ||
      CBS_len(&proof) != 0) {
    goto err;
  }

  ok = 1;

err:
  OPENSSL_free(Tps);
  OPENSSL_free(Wps);
  OPENSSL_free(es);
  CBB_cleanup(&batch_cbb);
  if (!ok) {
    sk_TRUST_TOKEN_pop_free(ret, TRUST_TOKEN_free);
    ret = NULL;
  }
  return ret;
}

static int voprf_read(const VOPRF_METHOD *method,
                      const TRUST_TOKEN_ISSUER_KEY *key,
                      uint8_t out_nonce[TRUST_TOKEN_NONCE_SIZE],
                      const uint8_t *token, size_t token_len) {
  const EC_GROUP *group = method->group;
  CBS cbs;
  CBS_init(&cbs, token, token_len);
  EC_AFFINE Ws;
  if (!CBS_copy_bytes(&cbs, out_nonce, TRUST_TOKEN_NONCE_SIZE) ||
      !cbs_get_point(&cbs, group, &Ws) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }


  EC_RAW_POINT T;
  if (!method->hash_t(group, &T, out_nonce)) {
    return 0;
  }

  EC_RAW_POINT Ws_calculated;
  if (!ec_point_mul_scalar(group, &Ws_calculated, &T, &key->xs) ||
      !ec_affine_jacobian_equal(group, &Ws, &Ws_calculated)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BAD_VALIDITY_CHECK);
    return 0;
  }

  return 1;
}


// VOPRF experiment v2.

static int voprf_exp2_hash_t(const EC_GROUP *group, EC_RAW_POINT *out,
                                const uint8_t t[TRUST_TOKEN_NONCE_SIZE]) {
  const uint8_t kHashTLabel[] = "TrustToken VOPRF Experiment V2 HashT";
  return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
      group, out, kHashTLabel, sizeof(kHashTLabel), t, TRUST_TOKEN_NONCE_SIZE);
}

static int voprf_exp2_hash_c(const EC_GROUP *group, EC_SCALAR *out,
                             uint8_t *buf, size_t len) {
  const uint8_t kHashCLabel[] = "TrustToken VOPRF Experiment V2 HashC";
  return ec_hash_to_scalar_p384_xmd_sha512_draft07(
      group, out, kHashCLabel, sizeof(kHashCLabel), buf, len);
}

static int voprf_exp2_ok = 0;
static VOPRF_METHOD voprf_exp2_method;
static CRYPTO_once_t voprf_exp2_method_once = CRYPTO_ONCE_INIT;

static void voprf_exp2_init_method_impl(void) {
  // This is the output of |ec_hash_to_scalar_p384_xmd_sha512_draft07| with DST
  // "TrustToken VOPRF Experiment V2 HashH" and message "generator".
  static const uint8_t kG[] = {
      0x04, 0x7d, 0x76, 0x99, 0xf2, 0xa8, 0x3f, 0xc6, 0xfe, 0xf0, 0xc4,
      0x4f, 0xec, 0xff, 0xdf, 0xf7, 0xfb, 0xf6, 0xd5, 0x1e, 0xa5, 0xe1,
      0x06, 0xff, 0xd5, 0xfc, 0xd2, 0x0a, 0x92, 0xb8, 0xac, 0x43, 0x17,
      0xdf, 0xc2, 0x1e, 0x6a, 0x2b, 0xa0, 0xe4, 0x0e, 0xf7, 0x4b, 0x25,
      0x50, 0x13, 0x1c, 0xee, 0x4f, 0xe1, 0x13, 0x4d, 0x51, 0x8b, 0x5d,
      0x00, 0xe6, 0xbf, 0x0a, 0x80, 0xf7, 0x19, 0xb4, 0xd8, 0x6c, 0x64,
      0xee, 0xed, 0xa4, 0xd8, 0xb0, 0xe1, 0x13, 0x8b, 0xdc, 0x27, 0xfd,
      0x8e, 0xa2, 0x30, 0xc2, 0xf5, 0x1d, 0x88, 0x03, 0x3f, 0x06, 0x0e,
      0xdd, 0x84, 0xc4, 0x0c, 0x20, 0x06, 0xf5, 0xd2, 0x55,
  };

  voprf_exp2_ok =
      voprf_init_method(&voprf_exp2_method, NID_secp384r1, kG, sizeof(kG),
                        voprf_exp2_hash_t, voprf_exp2_hash_c);
}

static int voprf_exp2_init_method(void) {
  CRYPTO_once(&voprf_exp2_method_once, voprf_exp2_init_method_impl);
  if (!voprf_exp2_ok) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

int voprf_exp2_generate_key(CBB *out_private, CBB *out_public) {
  if (!voprf_exp2_init_method()) {
    return 0;
  }

  return voprf_generate_key(&voprf_exp2_method, out_private, out_public);
}

int voprf_exp2_client_key_from_bytes(TRUST_TOKEN_CLIENT_KEY *key,
                                     const uint8_t *in, size_t len) {
  if (!voprf_exp2_init_method()) {
    return 0;
  }
  return voprf_client_key_from_bytes(&voprf_exp2_method, key, in, len);
}

int voprf_exp2_issuer_key_from_bytes(TRUST_TOKEN_ISSUER_KEY *key,
                                     const uint8_t *in, size_t len) {
  if (!voprf_exp2_init_method()) {
    return 0;
  }
  return voprf_issuer_key_from_bytes(&voprf_exp2_method, key, in, len);
}

STACK_OF(TRUST_TOKEN_PRETOKEN) * voprf_exp2_blind(CBB *cbb, size_t count) {
  if (!voprf_exp2_init_method()) {
    return NULL;
  }
  return voprf_blind(&voprf_exp2_method, cbb, count);
}

int voprf_exp2_sign(const TRUST_TOKEN_ISSUER_KEY *key, CBB *cbb, CBS *cbs,
                    size_t num_requested, size_t num_to_issue,
                    uint8_t private_metadata) {
  if (!voprf_exp2_init_method() || private_metadata != 0) {
    return 0;
  }
  return voprf_sign(&voprf_exp2_method, key, cbb, cbs, num_requested,
                    num_to_issue);
}

STACK_OF(TRUST_TOKEN) *
    voprf_exp2_unblind(const TRUST_TOKEN_CLIENT_KEY *key,
                       const STACK_OF(TRUST_TOKEN_PRETOKEN) * pretokens,
                       CBS *cbs, size_t count, uint32_t key_id) {
  if (!voprf_exp2_init_method()) {
    return NULL;
  }
  return voprf_unblind(&voprf_exp2_method, key, pretokens, cbs, count,
                          key_id);
}

int voprf_exp2_read(const TRUST_TOKEN_ISSUER_KEY *key,
                    uint8_t out_nonce[TRUST_TOKEN_NONCE_SIZE],
                    uint8_t *out_private_metadata, const uint8_t *token,
                    size_t token_len) {
  if (!voprf_exp2_init_method()) {
    return 0;
  }
  return voprf_read(&voprf_exp2_method, key, out_nonce, token, token_len);
}

int voprf_exp2_get_g_for_testing(uint8_t out[97]) {
  if (!voprf_exp2_init_method()) {
    return 0;
  }
  EC_AFFINE g;
  return ec_jacobian_to_affine(voprf_exp2_method.group, &g,
                               &voprf_exp2_method.g) &&
         ec_point_to_bytes(voprf_exp2_method.group, &g,
                           POINT_CONVERSION_UNCOMPRESSED, out, 97) == 97;
}
