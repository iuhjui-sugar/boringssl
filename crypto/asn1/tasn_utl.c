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

#include <openssl/asn1.h>

#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/err.h>
#include <openssl/thread.h>


/* Utility functions for manipulating fields and offsets */

/* Add 'offset' to 'addr' */
#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

/* Given an ASN1_ITEM CHOICE type return the selector value */
int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  int *sel = offset2ptr(*pval, it->utype);
  return *sel;
}

/* Given an ASN1_ITEM CHOICE type set the selector value, return old value. */
int asn1_set_choice_selector(ASN1_VALUE **pval, int value,
                             const ASN1_ITEM *it) {
  int *sel, ret;
  sel = offset2ptr(*pval, it->utype);
  ret = *sel;
  *sel = value;
  return ret;
}

/* Do reference counting. The value 'op' decides what to do. if it is +1 then
 * the count is incremented. If op is 0 count is set to 1. If op is -1 count is
 * decremented and the return value is the current refrence count or 0 if no
 * reference count exists. */
int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it) {
  const ASN1_AUX *aux;
  int *lck, ret;
  if (it->itype != ASN1_ITYPE_SEQUENCE &&
      it->itype != ASN1_ITYPE_NDEF_SEQUENCE) {
    return 0;
  }
  aux = it->funcs;
  if (!aux || !(aux->flags & ASN1_AFLG_REFCOUNT)) {
    return 0;
  }
  lck = offset2ptr(*pval, aux->ref_offset);
  if (op == 0) {
    *lck = 1;
    return 1;
  }
  ret = CRYPTO_add(lck, op, aux->ref_lock);
  return ret;
}

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  const ASN1_AUX *aux;
  if (!pval || !*pval) {
    return NULL;
  }
  aux = it->funcs;
  if (!aux || !(aux->flags & ASN1_AFLG_ENCODING)) {
    return NULL;
  }
  return offset2ptr(*pval, aux->enc_offset);
}

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  ASN1_ENCODING *enc;
  enc = asn1_get_enc_ptr(pval, it);
  if (enc) {
    enc->enc = NULL;
    enc->len = 0;
    enc->modified = 1;
  }
}

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it) {
  ASN1_ENCODING *enc;
  enc = asn1_get_enc_ptr(pval, it);
  if (enc) {
    if (enc->enc) {
      OPENSSL_free(enc->enc);
    }
    enc->enc = NULL;
    enc->len = 0;
    enc->modified = 1;
  }
}

int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
                  const ASN1_ITEM *it) {
  ASN1_ENCODING *enc;
  enc = asn1_get_enc_ptr(pval, it);
  if (!enc) {
    return 1;
  }

  if (enc->enc) {
    OPENSSL_free(enc->enc);
  }
  enc->enc = OPENSSL_malloc(inlen);
  if (!enc->enc) {
    return 0;
  }
  memcpy(enc->enc, in, inlen);
  enc->len = inlen;
  enc->modified = 0;

  return 1;
}

int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
                     const ASN1_ITEM *it) {
  ASN1_ENCODING *enc;
  enc = asn1_get_enc_ptr(pval, it);
  if (!enc || enc->modified) {
    return 0;
  }
  if (out) {
    memcpy(*out, enc->enc, enc->len);
    *out += enc->len;
  }
  if (len) {
    *len = enc->len;
  }
  return 1;
}

/* Given an ASN1_TEMPLATE get a pointer to a field */
ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt) {
  ASN1_VALUE **pvaltmp;
  if (tt->flags & ASN1_TFLG_COMBINE) {
    return pval;
  }
  pvaltmp = offset2ptr(*pval, tt->offset);
  /* NOTE for BOOLEAN types the field is just a plain int so we can't return
   * int **, so settle for (int *). */
  return pvaltmp;
}

/* Handle ANY DEFINED BY template, find the selector, look up the relevant
 * ASN1_TEMPLATE in the table and return it. */
const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,
                                 int nullerr) {
  const ASN1_ADB *adb;
  const ASN1_ADB_TABLE *atbl;
  long selector;
  ASN1_VALUE **sfld;
  int i;
  if (!(tt->flags & ASN1_TFLG_ADB_MASK)) {
    return tt;
  }

  /* Else ANY DEFINED BY ... get the table */
  adb = ASN1_ADB_ptr(tt->item);

  /* Get the selector field */
  sfld = offset2ptr(*pval, adb->offset);

  /* Check if NULL */
  if (!sfld) {
    if (!adb->null_tt) {
      goto err;
    }
    return adb->null_tt;
  }

  /* Convert type to a long:
   * NB: don't check for NID_undef here because it
   * might be a legitimate value in the table */
  if (tt->flags & ASN1_TFLG_ADB_OID) {
    selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
  } else {
    selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);
  }

  /* Try to find matching entry in table Maybe should check application types
   * first to allow application override? Might also be useful to have a flag
   * which indicates table is sorted and we can do a binary search. For now
   * stick to a linear search. */

  for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++) {
    if (atbl->value == selector) {
      return &atbl->tt;
    }
  }

  /* FIXME: need to search application table too */

  /* No match, return default type */
  if (!adb->default_tt) {
    goto err;
  }
  return adb->default_tt;

err:
  /* FIXME: should log the value or OID of unsupported type */
  if (nullerr) {
    OPENSSL_PUT_ERROR(ASN1, asn1_do_adb,
                      ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
  }
  return NULL;
}
