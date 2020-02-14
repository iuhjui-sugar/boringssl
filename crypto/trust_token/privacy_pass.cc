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

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/trust_token.h>

#include "internal.h"

int TRUST_TOKEN_generate_key(uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  int ok = 0;
  BIGNUM *x0, *x1, *xs, *y0, *y1, *ys;
  EC_POINT *pub0, *pub1, *pubs;
  EC_GROUP *group;
  CBB pub0_cbb, pub1_cbb, pubs_cbb;
  uint8_t *pub0_buf = NULL, *pub1_buf = NULL, *pubs_buf = NULL;
  size_t pub0_len, pub1_len, pubs_len;
  if (!VOPRF_Setup(&x0, &y0, &pub0, &x1, &y1, &pub1, &xs, &ys, &pubs, &group)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  CBB cbb;
  if (!CBB_init_fixed(&cbb, out_priv_key, max_priv_key_len) ||
      !BN_marshal_asn1(&cbb, x0) || !BN_marshal_asn1(&cbb, y0) ||
      !BN_marshal_asn1(&cbb, x1) || !BN_marshal_asn1(&cbb, y1) ||
      !BN_marshal_asn1(&cbb, xs) || !BN_marshal_asn1(&cbb, ys) ||
      !CBB_finish(&cbb, NULL, out_priv_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!CBB_init_fixed(&cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  pub0_len = EC_POINT_point2oct(group, pub0, POINT_CONVERSION_UNCOMPRESSED,
                                NULL, 0, NULL);
  pub1_len = EC_POINT_point2oct(group, pub1, POINT_CONVERSION_UNCOMPRESSED,
                                NULL, 0, NULL);
  pubs_len = EC_POINT_point2oct(group, pubs, POINT_CONVERSION_UNCOMPRESSED,
                                NULL, 0, NULL);
  if (!CBB_add_u16_length_prefixed(&cbb, &pub0_cbb) ||
      !CBB_add_space(&pub0_cbb, &pub0_buf, pub0_len) ||
      EC_POINT_point2oct(group, pub0, POINT_CONVERSION_UNCOMPRESSED, pub0_buf,
                         pub0_len, NULL) != pub0_len ||
      !CBB_add_u16_length_prefixed(&cbb, &pub1_cbb) ||
      !CBB_add_space(&pub1_cbb, &pub1_buf, pub1_len) ||
      EC_POINT_point2oct(group, pub1, POINT_CONVERSION_UNCOMPRESSED, pub1_buf,
                         pub1_len, NULL) != pub1_len ||
      !CBB_add_u16_length_prefixed(&cbb, &pubs_cbb) ||
      !CBB_add_space(&pubs_cbb, &pubs_buf, pubs_len) ||
      EC_POINT_point2oct(group, pubs, POINT_CONVERSION_UNCOMPRESSED, pubs_buf,
                         pubs_len, NULL) != pubs_len ||
      !CBB_finish(&cbb, NULL, out_pub_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ok = 1;

err:
  CBB_cleanup(&cbb);
  BN_free(x0);
  BN_free(y0);
  BN_free(x1);
  BN_free(y1);
  BN_free(xs);
  BN_free(ys);
  EC_POINT_free(pub0);
  EC_POINT_free(pub1);
  EC_POINT_free(pubs);
  return ok;
}
