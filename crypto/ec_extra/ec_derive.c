/* Copyright (c) 2019, Google Inc.
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

#include <openssl/ec_key.h>

#include <string.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>

#include "../fipsmodule/ec/internal.h"

#include "internal.h"


BIGNUM *ec_hash_to_scalar(const EC_GROUP *group, const uint8_t *dst,
                          size_t dst_len, const uint8_t *msg, size_t msg_len) {
  // Generate 128 bits beyond the group order so the bias is at most 2^-128.
#define EC_KEY_DERIVE_EXTRA_BITS 128
#define EC_KEY_DERIVE_EXTRA_BYTES (EC_KEY_DERIVE_EXTRA_BITS / 8)

  if (EC_GROUP_order_bits(group) <= EC_KEY_DERIVE_EXTRA_BITS + 8) {
    // The reduction strategy below requires the group order be large enough.
    // (The actual bound is a bit tighter, but our curves are much larger than
    // 128-bit.)
    OPENSSL_PUT_ERROR(EC, ERR_R_INTERNAL_ERROR);
    return NULL;
  }

  uint8_t derived[EC_KEY_DERIVE_EXTRA_BYTES + EC_MAX_BYTES];
  size_t derived_len = BN_num_bytes(&group->order) + EC_KEY_DERIVE_EXTRA_BYTES;
  assert(derived_len <= sizeof(derived));
  if (!HKDF(derived, derived_len, EVP_sha256(), msg, msg_len,
            /*salt=*/NULL, /*salt_len=*/0, dst, dst_len)) {
    return NULL;
  }

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *bn = BN_bin2bn(derived, derived_len, NULL);
  if (bn == NULL ||
      // Reduce |priv| with Montgomery reduction. First, convert "from"
      // Montgomery form to compute |priv| * R^-1 mod |order|. This requires
      // |priv| be under order * R, which is true if the group order is large
      // enough. 2^(num_bytes(order)) < 2^8 * order, so:
      //
      //    priv < 2^8 * order * 2^128 < order * order < order * R
      !BN_from_montgomery(bn, bn, group->order_mont, ctx) ||
      // Multiply by R^2 and do another Montgomery reduction to compute
      // priv * R^-1 * R^2 * R^-1 = priv mod order.
      !BN_to_montgomery(bn, bn, group->order_mont, ctx)) {
    OPENSSL_PUT_ERROR(EC, ERR_R_INTERNAL_ERROR);
    BN_free(bn);
    bn = NULL;
  }

  OPENSSL_cleanse(derived, sizeof(derived));
  BN_CTX_free(ctx);
  return bn;
}

EC_KEY *EC_KEY_derive_from_secret(const EC_GROUP *group, const uint8_t *secret,
                                  size_t secret_len) {
#define EC_KEY_DERIVE_MAX_NAME_LEN 16
  const char *name = EC_curve_nid2nist(EC_GROUP_get_curve_name(group));
  if (name == NULL || strlen(name) > EC_KEY_DERIVE_MAX_NAME_LEN) {
    OPENSSL_PUT_ERROR(EC, EC_R_UNKNOWN_GROUP);
    return NULL;
  }

  // Assemble a label string to provide some key separation in case |secret| is
  // misused, but ultimately it's on the caller to ensure |secret| is suitably
  // separated.
  static const char kLabel[] = "derive EC key ";
  char info[sizeof(kLabel) + EC_KEY_DERIVE_MAX_NAME_LEN];
  OPENSSL_strlcpy(info, kLabel, sizeof(info));
  OPENSSL_strlcat(info, name, sizeof(info));

  EC_KEY *key = EC_KEY_new();
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *priv = ec_hash_to_scalar(group, (const uint8_t *)info, sizeof(info),
                                   secret, secret_len);
  EC_POINT *pub = EC_POINT_new(group);
  if (key == NULL || ctx == NULL || pub == NULL ||
      !EC_POINT_mul(group, pub, priv, NULL, NULL, ctx) ||
      !EC_KEY_set_group(key, group) || !EC_KEY_set_public_key(key, pub) ||
      !EC_KEY_set_private_key(key, priv)) {
    EC_KEY_free(key);
    key = NULL;
    goto err;
  }

err:
  BN_CTX_free(ctx);
  BN_free(priv);
  EC_POINT_free(pub);
  return key;
}
