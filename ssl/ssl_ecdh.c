/* Copyright (c) 2015, Google Inc.
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

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "internal.h"


/* |EC_POINT| implementation. */

static void ssl_ec_point_cleanup(SSL *ssl) {
  BIGNUM *private_key = (BIGNUM *)ssl->s3->tmp.ecdh_data;
  if (private_key == NULL) {
    return;
  }
  BN_clear_free(private_key);
}

static int ssl_ec_point_generate_key(SSL *ssl, CBB *out) {
  assert(ssl->s3->tmp.ecdh_data == NULL);

  BIGNUM *private_key = BN_new();
  if (private_key == NULL) {
    return 0;
  }
  ssl->s3->tmp.ecdh_data = private_key;

  int ret = 0;
  EC_POINT *public_key = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(ssl->s3->tmp.ecdh_method->nid);
  if (group == NULL) {
    goto err;
  }

  /* Generate a private key. */
  const BIGNUM *order = EC_GROUP_get0_order(group);
  do {
    if (!BN_rand_range(private_key, order)) {
      goto err;
    }
  } while (BN_is_zero(private_key));

  /* Compute the corresponding public key and serialize it. */
  public_key = EC_POINT_new(group);
  if (public_key == NULL ||
      !EC_POINT_mul(group, public_key, private_key, NULL, NULL, NULL)) {
    goto err;
  }

  /* Serialize the public key. */
  size_t len = EC_POINT_point2oct(group, public_key,
                                  POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
  uint8_t *ptr;
  if (len == 0 ||
      !CBB_add_space(out, &ptr, len) ||
      EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED, ptr,
                         len, NULL) != len) {
    goto err;
  }

  ret = 1;

err:
  EC_GROUP_free(group);
  EC_POINT_free(public_key);
  return ret;
}

int ssl_ec_point_compute_premaster(SSL *ssl, uint8_t **out_premaster,
                                   size_t *out_premaster_len,
                                   uint8_t *out_alert, const uint8_t *peer_key,
                                   size_t peer_key_len) {
  BIGNUM *private_key = (BIGNUM *)ssl->s3->tmp.ecdh_data;
  assert(private_key != NULL);

  *out_alert = SSL_AD_INTERNAL_ERROR;

  EC_GROUP *group = EC_GROUP_new_by_curve_name(ssl->s3->tmp.ecdh_method->nid);
  if (group == NULL) {
    return 0;
  }

  /* Compute the x-coordinate of |peer_key| * |private_key|. */
  int ret = 0;
  EC_POINT *peer_point = EC_POINT_new(group);
  EC_POINT *result = EC_POINT_new(group);
  BN_CTX *bn_ctx = BN_CTX_new();
  uint8_t *premaster = NULL;
  if (peer_point == NULL || result == NULL || bn_ctx == NULL) {
    goto err;
  }
  BN_CTX_start(bn_ctx);
  BIGNUM *x = BN_CTX_get(bn_ctx);
  if (x == NULL) {
    goto err;
  }
  if (!EC_POINT_oct2point(group, peer_point, peer_key, peer_key_len, bn_ctx)) {
    *out_alert = SSL_AD_DECODE_ERROR;
    goto err;
  }
  if (!EC_POINT_mul(group, result, NULL, peer_point, private_key, bn_ctx) ||
      !EC_POINT_get_affine_coordinates_GFp(group, result, x, NULL, bn_ctx)) {
    goto err;
  }

  /* Encode the x-coordinate left-padded with zeros. */
  size_t premaster_len = (EC_GROUP_get_degree(group) + 7) / 8;
  premaster = OPENSSL_malloc(premaster_len);
  if (premaster == NULL || !BN_bn2bin_padded(premaster, premaster_len, x)) {
    goto err;
  }

  *out_premaster = premaster;
  *out_premaster_len = premaster_len;
  premaster = NULL;
  ret = 1;

err:
  EC_GROUP_free(group);
  EC_POINT_free(peer_point);
  EC_POINT_free(result);
  if (bn_ctx != NULL) {
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
  }
  OPENSSL_free(premaster);
  return ret;
}


/* X25119 implementation. */

static void ssl_x25519_cleanup(SSL *ssl) {
  if (ssl->s3->tmp.ecdh_data == NULL) {
    return;
  }
  OPENSSL_cleanse(ssl->s3->tmp.ecdh_data, 32);
  OPENSSL_free(ssl->s3->tmp.ecdh_data);
}

static int ssl_x25519_generate_key(SSL *ssl, CBB *out) {
  assert(ssl->s3->tmp.ecdh_data == NULL);

  ssl->s3->tmp.ecdh_data = OPENSSL_malloc(32);
  if (ssl->s3->tmp.ecdh_data == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  uint8_t public_key[32];
  X25519_keypair(public_key, (uint8_t *)ssl->s3->tmp.ecdh_data);
  return CBB_add_bytes(out, public_key, sizeof(public_key));
}

static int ssl_x25519_compute_premaster(SSL *ssl, uint8_t **out_premaster,
                                        size_t *out_premaster_len,
                                        uint8_t *out_alert,
                                        const uint8_t *peer_key,
                                        size_t peer_key_len) {
  assert(ssl->s3->tmp.ecdh_data != NULL);
  *out_alert = SSL_AD_INTERNAL_ERROR;

  /* X25519 public keys must be 32 bytes. In addition,
   * draft-ietf-tls-curve25519-01 section 2.3 recommends rejecting public keys
   * when the high order bit of last byte is set. */
  uint8_t premaster[32];
  if (peer_key_len != 32 || (peer_key[31] & 0x80) ||
      !X25519(premaster, (uint8_t *)ssl->s3->tmp.ecdh_data, peer_key)) {
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
    return 0;
  }

  uint8_t *premaster_copy = BUF_memdup(premaster, sizeof(premaster));
  if (premaster_copy == NULL) {
    return 0;
  }
  *out_premaster = premaster_copy;
  *out_premaster_len = sizeof(premaster);
  return 1;
}


static const SSL_ECDH_METHOD kMethods[] = {
    {
        NID_X9_62_prime256v1,
        SSL_CURVE_SECP256R1,
        "P-256",
        ssl_ec_point_cleanup,
        ssl_ec_point_generate_key,
        ssl_ec_point_compute_premaster,
    },
    {
        NID_secp384r1,
        SSL_CURVE_SECP384R1,
        "P-384",
        ssl_ec_point_cleanup,
        ssl_ec_point_generate_key,
        ssl_ec_point_compute_premaster,
    },
    {
        NID_secp521r1,
        SSL_CURVE_SECP521R1,
        "P-521",
        ssl_ec_point_cleanup,
        ssl_ec_point_generate_key,
        ssl_ec_point_compute_premaster,
    },
    {
        NID_x25519,
        SSL_CURVE_ECDH_X25519,
        "X25519",
        ssl_x25519_cleanup,
        ssl_x25519_generate_key,
        ssl_x25519_compute_premaster,
    },
};

static const SSL_ECDH_METHOD *method_from_curve_id(uint16_t curve_id) {
  size_t i;
  for (i = 0; i < sizeof(kMethods) / sizeof(kMethods[0]); i++) {
    if (kMethods[i].curve_id == curve_id) {
      return &kMethods[i];
    }
  }
  return NULL;
}

static const SSL_ECDH_METHOD *method_from_nid(int nid) {
  size_t i;
  for (i = 0; i < sizeof(kMethods) / sizeof(kMethods[0]); i++) {
    if (kMethods[i].nid == nid) {
      return &kMethods[i];
    }
  }
  return NULL;
}

const char* SSL_get_curve_name(uint16_t curve_id) {
  const SSL_ECDH_METHOD *method = method_from_curve_id(curve_id);
  if (method == NULL) {
    return NULL;
  }
  return method->name;
}

int ssl_nid_to_curve_id(uint16_t *out_curve_id, int nid) {
  const SSL_ECDH_METHOD *method = method_from_nid(nid);
  if (method == NULL) {
    return 0;
  }
  *out_curve_id = method->curve_id;
  return 1;
}

int ssl_init_ecdh(SSL *ssl, uint16_t curve_id) {
  ssl_free_ecdh(ssl);

  const SSL_ECDH_METHOD *method = method_from_curve_id(curve_id);
  if (method == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
    return 0;
  }
  ssl->s3->tmp.ecdh_method = method;
  return 1;
}

void ssl_free_ecdh(SSL *ssl) {
  if (ssl->s3->tmp.ecdh_method == NULL) {
    return;
  }
  ssl->s3->tmp.ecdh_method->cleanup(ssl);
  ssl->s3->tmp.ecdh_method = NULL;
  ssl->s3->tmp.ecdh_data = NULL;
}
