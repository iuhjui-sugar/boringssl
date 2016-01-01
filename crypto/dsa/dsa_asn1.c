/* Copyright (c) 2016, Google Inc.
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

#include <openssl/dsa.h>

#include <assert.h>
#include <limits.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>


static int parse_integer(CBS *cbs, BIGNUM **out) {
  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return BN_parse_asn1_unsigned(cbs, *out);
}

static int marshal_integer(CBB *cbb, BIGNUM *bn) {
  if (bn == NULL) {
    /* A DSA object may be missing some components. */
    OPENSSL_PUT_ERROR(DSA, DSA_R_VALUE_MISSING);
    return 0;
  }
  return BN_marshal_asn1(cbb, bn);
}

DSA *DSA_parse_parameters(CBS *cbs) {
  DSA *ret = DSA_new();
  if (ret == NULL) {
    return NULL;
  }
  CBS child;
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE) ||
      !parse_integer(&child, &ret->p) ||
      !parse_integer(&child, &ret->q) ||
      !parse_integer(&child, &ret->g) ||
      CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_DECODE_ERROR);
    DSA_free(ret);
    return NULL;
  }
  return ret;
}

int DSA_marshal_parameters(CBB *cbb, const DSA *params) {
  CBB child;
  if (!CBB_add_asn1(cbb, &child, CBS_ASN1_SEQUENCE) ||
      !marshal_integer(&child, params->p) ||
      !marshal_integer(&child, params->q) ||
      !marshal_integer(&child, params->g) ||
      !CBB_flush(cbb)) {
    OPENSSL_PUT_ERROR(DSA, DSA_R_ENCODE_ERROR);
    return 0;
  }
  return 1;
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
