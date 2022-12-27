/* v3_cpols.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/stack.h>
#include <openssl/x509v3.h>

#include "internal.h"

// Certificate policies extension support: this one is a bit complex...

static int i2r_certpol(const X509V3_EXT_METHOD *method, void *ext, BIO *out,
                       int indent);
static void *r2i_certpol(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                         const char *value);
static void print_qualifiers(BIO *out, const STACK_OF(POLICYQUALINFO) *quals,
                             int indent);
static void print_notice(BIO *out, const USERNOTICE *notice, int indent);
static POLICYINFO *policy_section(X509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *polstrs, int ia5org);
static POLICYQUALINFO *notice_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *unot, int ia5org);
static int nref_nos(STACK_OF(ASN1_INTEGER) *nnums, STACK_OF(CONF_VALUE) *nos);

const X509V3_EXT_METHOD v3_cpols = {
    NID_certificate_policies,
    0,
    ASN1_ITEM_ref(CERTIFICATEPOLICIES),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    i2r_certpol,
    r2i_certpol,
    NULL,
};

ASN1_ITEM_TEMPLATE(CERTIFICATEPOLICIES) = ASN1_EX_TEMPLATE_TYPE(
    ASN1_TFLG_SEQUENCE_OF, 0, CERTIFICATEPOLICIES, POLICYINFO)
ASN1_ITEM_TEMPLATE_END(CERTIFICATEPOLICIES)

IMPLEMENT_ASN1_FUNCTIONS_const(CERTIFICATEPOLICIES)

ASN1_SEQUENCE(POLICYINFO) = {
    ASN1_SIMPLE(POLICYINFO, policyid, ASN1_OBJECT),
    ASN1_SEQUENCE_OF_OPT(POLICYINFO, qualifiers, POLICYQUALINFO),
} ASN1_SEQUENCE_END(POLICYINFO)

IMPLEMENT_ASN1_FUNCTIONS_const(POLICYINFO)

ASN1_ADB_TEMPLATE(policydefault) = ASN1_SIMPLE(POLICYQUALINFO, d.other,
                                               ASN1_ANY);

ASN1_ADB(POLICYQUALINFO) = {
    ADB_ENTRY(NID_id_qt_cps,
              ASN1_SIMPLE(POLICYQUALINFO, d.cpsuri, ASN1_IA5STRING)),
    ADB_ENTRY(NID_id_qt_unotice,
              ASN1_SIMPLE(POLICYQUALINFO, d.usernotice, USERNOTICE)),
} ASN1_ADB_END(POLICYQUALINFO, 0, pqualid, 0, &policydefault_tt, NULL);

ASN1_SEQUENCE(POLICYQUALINFO) = {
    ASN1_SIMPLE(POLICYQUALINFO, pqualid, ASN1_OBJECT),
    ASN1_ADB_OBJECT(POLICYQUALINFO),
} ASN1_SEQUENCE_END(POLICYQUALINFO)

IMPLEMENT_ASN1_FUNCTIONS_const(POLICYQUALINFO)

ASN1_SEQUENCE(USERNOTICE) = {
    ASN1_OPT(USERNOTICE, noticeref, NOTICEREF),
    ASN1_OPT(USERNOTICE, exptext, DISPLAYTEXT),
} ASN1_SEQUENCE_END(USERNOTICE)

IMPLEMENT_ASN1_FUNCTIONS_const(USERNOTICE)

ASN1_SEQUENCE(NOTICEREF) = {
    ASN1_SIMPLE(NOTICEREF, organization, DISPLAYTEXT),
    ASN1_SEQUENCE_OF(NOTICEREF, noticenos, ASN1_INTEGER),
} ASN1_SEQUENCE_END(NOTICEREF)

IMPLEMENT_ASN1_FUNCTIONS_const(NOTICEREF)

static void *r2i_certpol(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                         const char *value) {
  STACK_OF(POLICYINFO) *pols = NULL;
  char *pstr;
  POLICYINFO *pol;
  ASN1_OBJECT *pobj;
  STACK_OF(CONF_VALUE) *vals;
  CONF_VALUE *cnf;
  size_t i;
  int ia5org;
  pols = sk_POLICYINFO_new_null();
  if (pols == NULL) {
    OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  vals = X509V3_parse_list(value);
  if (vals == NULL) {
    OPENSSL_PUT_ERROR(X509V3, ERR_R_X509V3_LIB);
    goto err;
  }
  ia5org = 0;
  for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
    cnf = sk_CONF_VALUE_value(vals, i);
    if (cnf->value || !cnf->name) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_POLICY_IDENTIFIER);
      X509V3_conf_err(cnf);
      goto err;
    }
    pstr = cnf->name;
    if (!strcmp(pstr, "ia5org")) {
      ia5org = 1;
      continue;
    } else if (*pstr == '@') {
      STACK_OF(CONF_VALUE) *polsect = X509V3_get_section(ctx, pstr + 1);
      if (!polsect) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_SECTION);

        X509V3_conf_err(cnf);
        goto err;
      }
      pol = policy_section(ctx, polsect, ia5org);
      if (!pol) {
        goto err;
      }
    } else {
      if (!(pobj = OBJ_txt2obj(cnf->name, 0))) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
        X509V3_conf_err(cnf);
        goto err;
      }
      pol = POLICYINFO_new();
      if (pol == NULL) {
        OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);
        ASN1_OBJECT_free(pobj);
        goto err;
      }
      pol->policyid = pobj;
    }
    if (!sk_POLICYINFO_push(pols, pol)) {
      POLICYINFO_free(pol);
      OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }
  sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
  return pols;
err:
  sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
  sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
  return NULL;
}

static POLICYINFO *policy_section(X509V3_CTX *ctx,
                                  STACK_OF(CONF_VALUE) *polstrs, int ia5org) {
  size_t i;
  CONF_VALUE *cnf;
  POLICYINFO *pol;
  POLICYQUALINFO *qual;
  if (!(pol = POLICYINFO_new())) {
    goto merr;
  }
  for (i = 0; i < sk_CONF_VALUE_num(polstrs); i++) {
    cnf = sk_CONF_VALUE_value(polstrs, i);
    if (!strcmp(cnf->name, "policyIdentifier")) {
      ASN1_OBJECT *pobj;
      if (!(pobj = OBJ_txt2obj(cnf->value, 0))) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
        X509V3_conf_err(cnf);
        goto err;
      }
      pol->policyid = pobj;

    } else if (x509v3_conf_name_matches(cnf->name, "CPS")) {
      if (!pol->qualifiers) {
        pol->qualifiers = sk_POLICYQUALINFO_new_null();
      }
      if (!(qual = POLICYQUALINFO_new())) {
        goto merr;
      }
      if (!sk_POLICYQUALINFO_push(pol->qualifiers, qual)) {
        goto merr;
      }
      qual->pqualid = OBJ_nid2obj(NID_id_qt_cps);
      if (qual->pqualid == NULL) {
        OPENSSL_PUT_ERROR(X509V3, ERR_R_INTERNAL_ERROR);
        goto err;
      }
      qual->d.cpsuri = ASN1_IA5STRING_new();
      if (qual->d.cpsuri == NULL) {
        goto err;
      }
      if (!ASN1_STRING_set(qual->d.cpsuri, cnf->value, strlen(cnf->value))) {
        goto merr;
      }
    } else if (x509v3_conf_name_matches(cnf->name, "userNotice")) {
      if (*cnf->value != '@') {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXPECTED_A_SECTION_NAME);
        X509V3_conf_err(cnf);
        goto err;
      }
      STACK_OF(CONF_VALUE) *unot = X509V3_get_section(ctx, cnf->value + 1);
      if (!unot) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_SECTION);

        X509V3_conf_err(cnf);
        goto err;
      }
      qual = notice_section(ctx, unot, ia5org);
      if (!qual) {
        goto err;
      }
      if (!pol->qualifiers) {
        pol->qualifiers = sk_POLICYQUALINFO_new_null();
      }
      if (!sk_POLICYQUALINFO_push(pol->qualifiers, qual)) {
        goto merr;
      }
    } else {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OPTION);

      X509V3_conf_err(cnf);
      goto err;
    }
  }
  if (!pol->policyid) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_POLICY_IDENTIFIER);
    goto err;
  }

  return pol;

merr:
  OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);

err:
  POLICYINFO_free(pol);
  return NULL;
}

static POLICYQUALINFO *notice_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *unot, int ia5org) {
  size_t i;
  int ret;
  CONF_VALUE *cnf;
  USERNOTICE * not ;
  POLICYQUALINFO *qual;
  if (!(qual = POLICYQUALINFO_new())) {
    goto merr;
  }
  qual->pqualid = OBJ_nid2obj(NID_id_qt_unotice);
  if (qual->pqualid == NULL) {
    OPENSSL_PUT_ERROR(X509V3, ERR_R_INTERNAL_ERROR);
    goto err;
  }
  if (!(not = USERNOTICE_new())) {
    goto merr;
  }
  qual->d.usernotice = not ;
  for (i = 0; i < sk_CONF_VALUE_num(unot); i++) {
    cnf = sk_CONF_VALUE_value(unot, i);
    if (!strcmp(cnf->name, "explicitText")) {
      not ->exptext = ASN1_VISIBLESTRING_new();
      if (not ->exptext == NULL) {
        goto merr;
      }
      if (!ASN1_STRING_set(not ->exptext, cnf->value, strlen(cnf->value))) {
        goto merr;
      }
    } else if (!strcmp(cnf->name, "organization")) {
      NOTICEREF *nref;
      if (!not ->noticeref) {
        if (!(nref = NOTICEREF_new())) {
          goto merr;
        }
        not ->noticeref = nref;
      } else {
        nref = not ->noticeref;
      }
      if (ia5org) {
        nref->organization->type = V_ASN1_IA5STRING;
      } else {
        nref->organization->type = V_ASN1_VISIBLESTRING;
      }
      if (!ASN1_STRING_set(nref->organization, cnf->value,
                           strlen(cnf->value))) {
        goto merr;
      }
    } else if (!strcmp(cnf->name, "noticeNumbers")) {
      NOTICEREF *nref;
      STACK_OF(CONF_VALUE) *nos;
      if (!not ->noticeref) {
        if (!(nref = NOTICEREF_new())) {
          goto merr;
        }
        not ->noticeref = nref;
      } else {
        nref = not ->noticeref;
      }
      nos = X509V3_parse_list(cnf->value);
      if (!nos || !sk_CONF_VALUE_num(nos)) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_NUMBERS);
        X509V3_conf_err(cnf);
        goto err;
      }
      ret = nref_nos(nref->noticenos, nos);
      sk_CONF_VALUE_pop_free(nos, X509V3_conf_free);
      if (!ret) {
        goto err;
      }
    } else {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_OPTION);
      X509V3_conf_err(cnf);
      goto err;
    }
  }

  if (not ->noticeref &&
      (!not ->noticeref->noticenos || !not ->noticeref->organization)) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_NEED_ORGANIZATION_AND_NUMBERS);
    goto err;
  }

  return qual;

merr:
  OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);

err:
  POLICYQUALINFO_free(qual);
  return NULL;
}

static int nref_nos(STACK_OF(ASN1_INTEGER) *nnums, STACK_OF(CONF_VALUE) *nos) {
  CONF_VALUE *cnf;
  ASN1_INTEGER *aint;

  size_t i;

  for (i = 0; i < sk_CONF_VALUE_num(nos); i++) {
    cnf = sk_CONF_VALUE_value(nos, i);
    if (!(aint = s2i_ASN1_INTEGER(NULL, cnf->name))) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_NUMBER);
      goto err;
    }
    if (!sk_ASN1_INTEGER_push(nnums, aint)) {
      goto merr;
    }
  }
  return 1;

merr:
  ASN1_INTEGER_free(aint);
  OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);

err:
  return 0;
}

static int i2r_certpol(const X509V3_EXT_METHOD *method, void *ext, BIO *out,
                       int indent) {
  const STACK_OF(POLICYINFO) *pol = ext;
  // First print out the policy OIDs
  for (size_t i = 0; i < sk_POLICYINFO_num(pol); i++) {
    const POLICYINFO *pinfo = sk_POLICYINFO_value(pol, i);
    BIO_printf(out, "%*sPolicy: ", indent, "");
    i2a_ASN1_OBJECT(out, pinfo->policyid);
    BIO_puts(out, "\n");
    if (pinfo->qualifiers) {
      print_qualifiers(out, pinfo->qualifiers, indent + 2);
    }
  }
  return 1;
}

static void print_qualifiers(BIO *out, const STACK_OF(POLICYQUALINFO) *quals,
                             int indent) {
  for (size_t i = 0; i < sk_POLICYQUALINFO_num(quals); i++) {
    const POLICYQUALINFO *qualinfo = sk_POLICYQUALINFO_value(quals, i);
    switch (OBJ_obj2nid(qualinfo->pqualid)) {
      case NID_id_qt_cps:
        BIO_printf(out, "%*sCPS: %.*s\n", indent, "",
                   qualinfo->d.cpsuri->length, qualinfo->d.cpsuri->data);
        break;

      case NID_id_qt_unotice:
        BIO_printf(out, "%*sUser Notice:\n", indent, "");
        print_notice(out, qualinfo->d.usernotice, indent + 2);
        break;

      default:
        BIO_printf(out, "%*sUnknown Qualifier: ", indent + 2, "");

        i2a_ASN1_OBJECT(out, qualinfo->pqualid);
        BIO_puts(out, "\n");
        break;
    }
  }
}

static void print_notice(BIO *out, const USERNOTICE *notice, int indent) {
  if (notice->noticeref) {
    NOTICEREF *ref;
    ref = notice->noticeref;
    BIO_printf(out, "%*sOrganization: %.*s\n", indent, "",
               ref->organization->length, ref->organization->data);
    BIO_printf(out, "%*sNumber%s: ", indent, "",
               sk_ASN1_INTEGER_num(ref->noticenos) > 1 ? "s" : "");
    for (size_t i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
      ASN1_INTEGER *num;
      char *tmp;
      num = sk_ASN1_INTEGER_value(ref->noticenos, i);
      if (i) {
        BIO_puts(out, ", ");
      }
      if (num == NULL) {
        BIO_puts(out, "(null)");
      } else {
        tmp = i2s_ASN1_INTEGER(NULL, num);
        if (tmp == NULL) {
          return;
        }
        BIO_puts(out, tmp);
        OPENSSL_free(tmp);
      }
    }
    BIO_puts(out, "\n");
  }
  if (notice->exptext) {
    BIO_printf(out, "%*sExplicit Text: %.*s\n", indent, "",
               notice->exptext->length, notice->exptext->data);
  }
}
