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

#ifndef OPENSSL_HEADER_ASN1_INTERNAL_H
#define OPENSSL_HEADER_ASN1_INTERNAL_H

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* ASN1_DEFINE_LEGACY_D2I defines a legacy ASN.1 parsing function for |type|
 * named |name|. |parse_func| much be a |CBS|-based parsing function of type
 *
 *   type *parse_func(CBS *cbs);
 *
 * and |free_func| a function to release newly-allocated |type| objects returned
 * by |parse_func|. It must have type
 *
 *   void free_func(type *obj); */
#define ASN1_DEFINE_LEGACY_D2I(type, name, parse_func, free_func) \
  type *name(type **out, const uint8_t **inp, long len) {         \
    if (len < 0) {                                                \
      OPENSSL_PUT_ERROR(ASN1, ERR_R_OVERFLOW);                    \
      return 0;                                                   \
    }                                                             \
    CBS cbs;                                                      \
    CBS_init(&cbs, *inp, (size_t)len);                            \
    type *ret = parse_func(&cbs);                                 \
    if (ret == NULL) {                                            \
      return NULL;                                                \
    }                                                             \
    if (out != NULL) {                                            \
      free_func(*out);                                            \
      *out = ret;                                                 \
    }                                                             \
    *inp = CBS_data(&cbs);                                        \
    return ret;                                                   \
  }

/* ASN1_DEFINE_LEGACY_I2D defines a legacy ASN.1 serialization function for
 * |type| named |name|. |marshal_func| much be a |CBB|-based serialization
 * function of type
 *
 *   int marshal_func(CBB *cbb, const type *obj); */
#define ASN1_DEFINE_LEGACY_I2D(type, name, marshal_func) \
  int name(const type *obj, uint8_t **outp) {            \
    CBB cbb;                                             \
    if (!CBB_init(&cbb, 0) ||                            \
        !marshal_func(&cbb, obj)) {                      \
      CBB_cleanup(&cbb);                                 \
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_ENCODE_ERROR);      \
      return -1;                                         \
    }                                                    \
    return ASN1_cbb_to_i2d(&cbb, outp);                  \
  }

/* ASN1_cbb_to_i2d calls |CBB_finish| on |cbb|. If |outp| is not NULL then the
 * result is written to |*outp| and |*outp| is advanced just past the output. It
 * returns the number of bytes in the result, whether written or not, or a
 * negative value on error. It takes ownership of |cbb|.
 *
 * This function may be used in compatibility implementations of OpenSSL's
 * legacy i2d functions where the marshal function does not quite align with
 * |ASN1_DEFINE_LEGACY_I2D|. */
int ASN1_cbb_to_i2d(CBB *cbb, uint8_t **outp);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_ASN1_INTERNAL_H */
