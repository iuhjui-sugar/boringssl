/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/evp.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#include "internal.h"


static int eckey_pub_encode(CBB *out, const EVP_PKEY *key) {
  const EC_KEY *ec_key = key->pkey.ec;
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  int curve_nid = EC_GROUP_get_curve_name(group);
  if (curve_nid == NID_undef) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_NID_FOR_CURVE);
    return 0;
  }
  const EC_POINT *public_key = EC_KEY_get0_public_key(ec_key);

  /* See RFC 5480, section 2. */
  CBB spki, algorithm, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_X9_62_id_ecPublicKey) ||
      !OBJ_nid2cbb(&algorithm, curve_nid) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !EC_POINT_point2cbb(&key_bitstring, group, public_key,
                          POINT_CONVERSION_UNCOMPRESSED, NULL) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int eckey_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* See RFC 5480, section 2. */

  /* The parameters are a named curve. */
  CBS named_curve;
  if (!CBS_get_asn1(params, &named_curve, CBS_ASN1_OBJECT) ||
      CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  EC_KEY *eckey = EC_KEY_new_by_curve_name(OBJ_cbs2nid(&named_curve));
  if (eckey == NULL) {
    return 0;
  }

  EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(eckey));
  if (point == NULL ||
      !EC_POINT_oct2point(EC_KEY_get0_group(eckey), point, CBS_data(key),
                          CBS_len(key), NULL) ||
      !EC_KEY_set_public_key(eckey, point)) {
    goto err;
  }

  EC_POINT_free(point);
  EVP_PKEY_assign_EC_KEY(out, eckey);
  return 1;

err:
  EC_POINT_free(point);
  EC_KEY_free(eckey);
  return 0;
}

static int eckey_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  int r;
  const EC_GROUP *group = EC_KEY_get0_group(b->pkey.ec);
  const EC_POINT *pa = EC_KEY_get0_public_key(a->pkey.ec),
                 *pb = EC_KEY_get0_public_key(b->pkey.ec);
  r = EC_POINT_cmp(group, pa, pb, NULL);
  if (r == 0) {
    return 1;
  } else if (r == 1) {
    return 0;
  } else {
    return -2;
  }
}

static int eckey_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* See RFC 5915. */
  EC_GROUP *group = EC_KEY_parse_parameters(params);
  if (group == NULL || CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    EC_GROUP_free(group);
    return 0;
  }

  EC_KEY *ec_key = EC_KEY_parse_private_key(key, group);
  if (ec_key == NULL || CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    return 0;
  }

  EC_GROUP_free(group);
  EVP_PKEY_assign_EC_KEY(out, ec_key);
  return 1;
}

static int eckey_priv_encode(CBB *out, const EVP_PKEY *key) {
  const EC_KEY *ec_key = key->pkey.ec;
  int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
  if (curve_nid == NID_undef) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_NO_NID_FOR_CURVE);
    return 0;
  }

  /* See RFC 5915. */
  CBB pkcs8, algorithm, private_key;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_X9_62_id_ecPublicKey) ||
      !OBJ_nid2cbb(&algorithm, curve_nid) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      /* Omit the redundant copy of the curve name. This contradicts RFC 5915
       * but aligns with PKCS #11. SEC 1 only says they may be omitted if known
       * by other means. Both OpenSSL and NSS omit the redundant parameters, so
       * we omit them as well. */
      !EC_KEY_marshal_private_key(&private_key, ec_key,
                                  EC_PKEY_NO_PARAMETERS) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int int_ec_size(const EVP_PKEY *pkey) {
  return ECDSA_size(pkey->pkey.ec);
}

static int ec_bits(const EVP_PKEY *pkey) {
  const EC_GROUP *group = EC_KEY_get0_group(pkey->pkey.ec);
  if (group == NULL) {
    ERR_clear_error();
    return 0;
  }
  return BN_num_bits(EC_GROUP_get0_order(group));
}

static int ec_missing_parameters(const EVP_PKEY *pkey) {
  return EC_KEY_get0_group(pkey->pkey.ec) == NULL;
}

static int ec_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from) {
  EC_GROUP *group = EC_GROUP_dup(EC_KEY_get0_group(from->pkey.ec));
  if (group == NULL ||
      EC_KEY_set_group(to->pkey.ec, group) == 0) {
    return 0;
  }
  EC_GROUP_free(group);
  return 1;
}

static int ec_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b) {
  const EC_GROUP *group_a = EC_KEY_get0_group(a->pkey.ec),
                 *group_b = EC_KEY_get0_group(b->pkey.ec);
  if (EC_GROUP_cmp(group_a, group_b, NULL) != 0) {
    /* mismatch */
    return 0;
  }
  return 1;
}

static void int_ec_free(EVP_PKEY *pkey) { EC_KEY_free(pkey->pkey.ec); }

static int eckey_opaque(const EVP_PKEY *pkey) {
  return EC_KEY_is_opaque(pkey->pkey.ec);
}

static int old_ec_priv_decode(EVP_PKEY *pkey, const uint8_t **pder,
                              int derlen) {
  EC_KEY *ec;
  if (!(ec = d2i_ECPrivateKey(NULL, pder, derlen))) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  return 1;
}

const EVP_PKEY_ASN1_METHOD ec_asn1_meth = {
  EVP_PKEY_EC,
  0,

  eckey_pub_decode,
  eckey_pub_encode,
  eckey_pub_cmp,

  eckey_priv_decode,
  eckey_priv_encode,

  eckey_opaque,
  0 /* pkey_supports_digest */,

  int_ec_size,
  ec_bits,

  ec_missing_parameters,
  ec_copy_parameters,
  ec_cmp_parameters,

  int_ec_free,
  old_ec_priv_decode,
};
