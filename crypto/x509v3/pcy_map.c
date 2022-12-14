/* pcy_map.c */
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
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/obj.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <assert.h>

#include "../x509/internal.h"
#include "internal.h"


static int x509_policy_mapping_cmp(const POLICY_MAPPING **a,
                                   const POLICY_MAPPING **b) {
  return OBJ_cmp((*a)->issuerDomainPolicy, (*b)->issuerDomainPolicy);
}

int x509_policy_cache_set_mapping(X509_POLICY_CACHE *cache,
                                  POLICY_MAPPINGS *maps) {
  int ret = 0;
  STACK_OF(X509_POLICY_DATA) *extra_data = NULL;
  if (sk_POLICY_MAPPING_num(maps) == 0) {
    // The policy mappings extension cannot be empty.
    goto err;
  }

  // The cache should have been sorted, which allows this function to run in
  // O(N log N) time.
  assert(sk_X509_POLICY_DATA_is_sorted(cache->data));

  // When a policy mapping matches an anyPolicy, we synthesize a node out of it.
  // The new nodes will be staged here, to avoid interfering with the cache's
  // sort.
  X509_POLICY_DATA *last_extra = NULL;
  extra_data = sk_X509_POLICY_DATA_new_null();
  if (extra_data == NULL) {
    goto err;
  }

  // Sort |maps| by |issuerDomainPolicy|.
  sk_POLICY_MAPPING_set_cmp_func(maps, x509_policy_mapping_cmp);
  sk_POLICY_MAPPING_sort(maps);

  for (size_t i = 0; i < sk_POLICY_MAPPING_num(maps); i++) {
    POLICY_MAPPING *map = sk_POLICY_MAPPING_value(maps, i);
    // Reject if mapping to or from anyPolicy.
    if ((OBJ_obj2nid(map->subjectDomainPolicy) == NID_any_policy) ||
        (OBJ_obj2nid(map->issuerDomainPolicy) == NID_any_policy)) {
      goto err;
    }

    // Attempt to find matching policy data.
    X509_POLICY_DATA *data =
        x509_policy_cache_find_data(cache, map->issuerDomainPolicy);

    // The matching policy may also be in |extra_data|. |maps| was sorted, so
    // it will either match |last_extra| or none at all.
    if (data == NULL && last_extra != NULL &&
        OBJ_cmp(last_extra->valid_policy, map->issuerDomainPolicy) == 0) {
      data = last_extra;
    }

    // If not found and anyPolicy isn't asserted, there's nothing to map.
    if (!data && !cache->anyPolicy) {
      continue;
    }

    if (!data) {
      // Create a node from anyPolicy.
      data = x509_policy_data_new_from_oid(map->issuerDomainPolicy);
      if (!data) {
        goto err;
      }
      data->qualifier_set = cache->anyPolicy->qualifier_set;
      data->flags |= POLICY_DATA_FLAG_MAPPED_ANY;
      data->flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
      if (!sk_X509_POLICY_DATA_push(extra_data, data)) {
        x509_policy_data_free(data);
        goto err;
      }
    } else {
      data->flags |= POLICY_DATA_FLAG_MAPPED;
    }
    if (!sk_ASN1_OBJECT_push(data->expected_policy_set,
                             map->subjectDomainPolicy)) {
      goto err;
    }
    map->subjectDomainPolicy = NULL;
  }

  // Merge |extra_data| into |cache| and re-sort.
  for (size_t i = 0; i < sk_X509_POLICY_DATA_num(extra_data); i++) {
    if (!sk_X509_POLICY_DATA_push(cache->data,
                                  sk_X509_POLICY_DATA_value(extra_data, i))) {
      goto err;
    }
    // |cache->data| took ownership.
    sk_X509_POLICY_DATA_set(extra_data, i, NULL);
  }
  sk_X509_POLICY_DATA_sort(cache->data);

  ret = 1;

err:
  sk_POLICY_MAPPING_pop_free(maps, POLICY_MAPPING_free);
  sk_X509_POLICY_DATA_pop_free(extra_data, x509_policy_data_free);
  return ret;
}
