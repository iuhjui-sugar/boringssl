/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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

#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/thread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../internal.h"
#include "../x509/internal.h"
#include "internal.h"

static int policy_data_cmp(const X509_POLICY_DATA **a,
                           const X509_POLICY_DATA **b);
static int policy_cache_set_int(long *out, ASN1_INTEGER *value);

// x509_policy_cache_set_policies sets policies in |cache| based on |policies|.
// It returns one on success and zero on error. In both cases, it takes
// ownership of and releases |policies|.
static int x509_policy_cache_set_policies(X509_POLICY_CACHE *cache,
                                          CERTIFICATEPOLICIES *policies) {
  int ret = 0;
  X509_POLICY_DATA *data = NULL;
  if (sk_POLICYINFO_num(policies) == 0) {
    // The certificate policies extension cannot be empty.
    goto err;
  }

  cache->data = sk_X509_POLICY_DATA_new(policy_data_cmp);
  if (!cache->data) {
    goto err;
  }

  for (size_t i = 0; i < sk_POLICYINFO_num(policies); i++) {
    POLICYINFO *policy = sk_POLICYINFO_value(policies, i);
    data = x509_policy_data_new_from_policyinfo(policy);
    if (!data) {
      goto err;
    }
    if (OBJ_obj2nid(data->valid_policy) == NID_any_policy) {
      // Check for a duplicate anyPolicy OID.
      if (cache->anyPolicy) {
        goto err;
      }
      cache->anyPolicy = data;
    } else if (!sk_X509_POLICY_DATA_push(cache->data, data)) {
      goto err;
    }
    data = NULL;
  }

  // Check for duplicate policy OIDs.
  sk_X509_POLICY_DATA_sort(cache->data);
  for (size_t i = 1; i < sk_X509_POLICY_DATA_num(cache->data); i++) {
    const X509_POLICY_DATA *a = sk_X509_POLICY_DATA_value(cache->data, i - 1);
    const X509_POLICY_DATA *b = sk_X509_POLICY_DATA_value(cache->data, i);
    if (OBJ_cmp(a->valid_policy, b->valid_policy) == 0) {
      goto err;
    }
  }

  ret = 1;

err:
  x509_policy_data_free(data);
  sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
  if (!ret) {
    sk_X509_POLICY_DATA_pop_free(cache->data, x509_policy_data_free);
    cache->data = NULL;
  }
  return ret;
}

void x509v3_setup_policy_cache(X509 *x) {
  X509_POLICY_CACHE *cache;
  ASN1_INTEGER *ext_any = NULL;
  POLICY_CONSTRAINTS *ext_pcons = NULL;
  CERTIFICATEPOLICIES *ext_cpols = NULL;
  POLICY_MAPPINGS *ext_pmaps = NULL;
  cache = OPENSSL_malloc(sizeof(X509_POLICY_CACHE));
  if (!cache) {
    return;
  }
  cache->anyPolicy = NULL;
  cache->data = NULL;
  cache->any_skip = -1;
  cache->explicit_skip = -1;
  cache->map_skip = -1;

  x->policy_cache = cache;

  // Handle requireExplicitPolicy *first*. Need to process this even if we
  // don't have any policies.
  int critical;
  ext_pcons = X509_get_ext_d2i(x, NID_policy_constraints, &critical, NULL);
  if (!ext_pcons) {
    if (critical != -1) {
      goto bad_cache;
    }
  } else {
    if (!ext_pcons->requireExplicitPolicy && !ext_pcons->inhibitPolicyMapping) {
      goto bad_cache;
    }
    if (!policy_cache_set_int(&cache->explicit_skip,
                              ext_pcons->requireExplicitPolicy)) {
      goto bad_cache;
    }
    if (!policy_cache_set_int(&cache->map_skip,
                              ext_pcons->inhibitPolicyMapping)) {
      goto bad_cache;
    }
  }

  ext_cpols = X509_get_ext_d2i(x, NID_certificate_policies, &critical, NULL);
  // If no CertificatePolicies extension or problem decoding then there is
  // no point continuing because the valid policies will be NULL.
  if (!ext_cpols) {
    // If not absent some problem with extension
    if (critical != -1) {
      goto bad_cache;
    }
    goto done;
  }

  // This call frees |ext_cpols|.
  if (!x509_policy_cache_set_policies(cache, ext_cpols)) {
    goto bad_cache;
  }

  ext_pmaps = X509_get_ext_d2i(x, NID_policy_mappings, &critical, NULL);
  if (!ext_pmaps) {
    // If not absent some problem with extension
    if (critical != -1) {
      goto bad_cache;
    }
  } else {
    // This call frees |ext_pmaps|.
    if (!x509_policy_cache_set_mapping(cache, ext_pmaps)) {
      goto bad_cache;
    }
  }

  ext_any = X509_get_ext_d2i(x, NID_inhibit_any_policy, &critical, NULL);
  if (!ext_any) {
    if (critical != -1) {
      goto bad_cache;
    }
  } else if (!policy_cache_set_int(&cache->any_skip, ext_any)) {
    goto bad_cache;
  }

  if (0) {
  bad_cache:
    x->ex_flags |= EXFLAG_INVALID_POLICY;
  }

done:
  POLICY_CONSTRAINTS_free(ext_pcons);
  ASN1_INTEGER_free(ext_any);
}

void x509_policy_cache_free(X509_POLICY_CACHE *cache) {
  if (!cache) {
    return;
  }
  x509_policy_data_free(cache->anyPolicy);
  sk_X509_POLICY_DATA_pop_free(cache->data, x509_policy_data_free);
  OPENSSL_free(cache);
}

const X509_POLICY_CACHE *x509_get_policy_cache(X509 *x) {
  x509v3_cache_extensions(x);
  return x->policy_cache;
}

X509_POLICY_DATA *x509_policy_cache_find_data(X509_POLICY_CACHE *cache,
                                              const ASN1_OBJECT *id) {
  size_t idx;
  X509_POLICY_DATA tmp;
  tmp.valid_policy = (ASN1_OBJECT *)id;
  if (!sk_X509_POLICY_DATA_find(cache->data, &idx, &tmp)) {
    return NULL;
  }
  return sk_X509_POLICY_DATA_value(cache->data, idx);
}

static int policy_data_cmp(const X509_POLICY_DATA **a,
                           const X509_POLICY_DATA **b) {
  return OBJ_cmp((*a)->valid_policy, (*b)->valid_policy);
}

static int policy_cache_set_int(long *out, ASN1_INTEGER *value) {
  if (value == NULL) {
    return 1;
  }
  if (value->type == V_ASN1_NEG_INTEGER) {
    return 0;
  }
  *out = ASN1_INTEGER_get(value);
  return 1;
}
