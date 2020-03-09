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

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/thread.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "vpm_int.h"
#include "../internal.h"
#include "../x509v3/internal.h"

static X509 *find_issuer(X509_STORE_CTX *ctx, STACK_OF(X509) *sk, X509 *x);
static int check_chain_extensions(X509_STORE_CTX *ctx);
static int check_name_constraints(X509_STORE_CTX *ctx);
static int check_id(X509_STORE_CTX *ctx);
static int check_trust(X509_STORE_CTX *ctx);

/* Return 1 is a certificate is self signed */
static int cert_self_signed(X509 *x)
{
    X509_check_purpose(x, -1, 0);
    if (x->ex_flags & EXFLAG_SS)
        return 1;
    else
        return 0;
}

/* Given a certificate try and find an exact match in the store */

static X509 *lookup_cert_match(X509_STORE_CTX *ctx, X509 *x)
{
    STACK_OF(X509) *certs;
    X509 *xtmp = NULL;
    size_t i;
    /* Lookup all certs with matching subject name */
    certs = ctx->lookup_certs(ctx, X509_get_subject_name(x));
    if (certs == NULL)
        return NULL;
    /* Look for exact match */
    for (i = 0; i < sk_X509_num(certs); i++) {
        xtmp = sk_X509_value(certs, i);
        if (!X509_cmp(xtmp, x))
            break;
    }
    if (i < sk_X509_num(certs))
        X509_up_ref(xtmp);
    else
        xtmp = NULL;
    sk_X509_pop_free(certs, X509_free);
    return xtmp;
}

int X509_verify_cert_impl(X509_STORE_CTX *ctx)
{
    X509 *x, *xtmp, *xtmp2, *chain_ss = NULL;
    int bad_chain = 0;
    X509_VERIFY_PARAM *param = ctx->param;
    int depth, i, ok = 0;
    int num, j, retry, trust;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    STACK_OF(X509) *sktmp = NULL;
    if (ctx->cert == NULL) {
        OPENSSL_PUT_ERROR(X509, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
        ctx->error = X509_V_ERR_INVALID_CALL;
        return -1;
    }
    if (ctx->chain != NULL) {
        /*
         * This X509_STORE_CTX has already been used to verify a cert. We
         * cannot do another one.
         */
        OPENSSL_PUT_ERROR(X509, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        ctx->error = X509_V_ERR_INVALID_CALL;
        return -1;
    }

    cb = ctx->verify_cb;

    /*
     * first we make sure the chain we are going to build is present and that
     * the first entry is in place
     */
    ctx->chain = sk_X509_new_null();
    if (ctx->chain == NULL || !sk_X509_push(ctx->chain, ctx->cert)) {
        OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        goto end;
    }
    X509_up_ref(ctx->cert);
    ctx->last_untrusted = 1;

    /* We use a temporary STACK so we can chop and hack at it.
     * sktmp = ctx->untrusted ++ ctx->ctx->additional_untrusted */
    if (ctx->untrusted != NULL
        && (sktmp = sk_X509_dup(ctx->untrusted)) == NULL) {
        OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
        ctx->error = X509_V_ERR_OUT_OF_MEM;
        goto end;
    }

    if (ctx->ctx->additional_untrusted != NULL) {
        if (sktmp == NULL) {
            sktmp = sk_X509_new_null();
            if (sktmp == NULL) {
                OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
                ctx->error = X509_V_ERR_OUT_OF_MEM;
                goto end;
            }
        }

        for (size_t k = 0; k < sk_X509_num(ctx->ctx->additional_untrusted);
             k++) {
            if (!sk_X509_push(sktmp,
                              sk_X509_value(ctx->ctx->additional_untrusted,
                              k))) {
                OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
                ctx->error = X509_V_ERR_OUT_OF_MEM;
                goto end;
            }
        }
    }

    num = sk_X509_num(ctx->chain);
    x = sk_X509_value(ctx->chain, num - 1);
    depth = param->depth;

    for (;;) {
        /* If we have enough, we break */
        if (depth < num)
            break;              /* FIXME: If this happens, we should take
                                 * note of it and, if appropriate, use the
                                 * X509_V_ERR_CERT_CHAIN_TOO_LONG error code
                                 * later. */

        /* If we are self signed, we break */
        if (cert_self_signed(x))
            break;
        /*
         * If asked see if we can find issuer in trusted store first
         */
        if (ctx->param->flags & X509_V_FLAG_TRUSTED_FIRST) {
            ok = ctx->get_issuer(&xtmp, ctx, x);
            if (ok < 0) {
                ctx->error = X509_V_ERR_STORE_LOOKUP;
                goto end;
            }
            /*
             * If successful for now free up cert so it will be picked up
             * again later.
             */
            if (ok > 0) {
                X509_free(xtmp);
                break;
            }
        }

        /* If we were passed a cert chain, use it first */
        if (sktmp != NULL) {
            xtmp = find_issuer(ctx, sktmp, x);
            if (xtmp != NULL) {
                if (!sk_X509_push(ctx->chain, xtmp)) {
                    OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
                    ctx->error = X509_V_ERR_OUT_OF_MEM;
                    ok = 0;
                    goto end;
                }
                X509_up_ref(xtmp);
                (void)sk_X509_delete_ptr(sktmp, xtmp);
                ctx->last_untrusted++;
                x = xtmp;
                num++;
                /*
                 * reparse the full chain for the next one
                 */
                continue;
            }
        }
        break;
    }

    /* Remember how many untrusted certs we have */
    j = num;
    /*
     * at this point, chain should contain a list of untrusted certificates.
     * We now need to add at least one trusted one, if possible, otherwise we
     * complain.
     */

    do {
        /*
         * Examine last certificate in chain and see if it is self signed.
         */
        i = sk_X509_num(ctx->chain);
        x = sk_X509_value(ctx->chain, i - 1);
        if (cert_self_signed(x)) {
            /* we have a self signed certificate */
            if (sk_X509_num(ctx->chain) == 1) {
                /*
                 * We have a single self signed certificate: see if we can
                 * find it in the store. We must have an exact match to avoid
                 * possible impersonation.
                 */
                ok = ctx->get_issuer(&xtmp, ctx, x);
                if ((ok <= 0) || X509_cmp(x, xtmp)) {
                    ctx->error = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
                    ctx->current_cert = x;
                    ctx->error_depth = i - 1;
                    if (ok == 1)
                        X509_free(xtmp);
                    bad_chain = 1;
                    ok = cb(0, ctx);
                    if (!ok)
                        goto end;
                } else {
                    /*
                     * We have a match: replace certificate with store
                     * version so we get any trust settings.
                     */
                    X509_free(x);
                    x = xtmp;
                    (void)sk_X509_set(ctx->chain, i - 1, x);
                    ctx->last_untrusted = 0;
                }
            } else {
                /*
                 * extract and save self signed certificate for later use
                 */
                chain_ss = sk_X509_pop(ctx->chain);
                ctx->last_untrusted--;
                num--;
                j--;
                x = sk_X509_value(ctx->chain, num - 1);
            }
        }
        /* We now lookup certs from the certificate store */
        for (;;) {
            /* If we have enough, we break */
            if (depth < num)
                break;
            /* If we are self signed, we break */
            if (cert_self_signed(x))
                break;
            ok = ctx->get_issuer(&xtmp, ctx, x);

            if (ok < 0) {
                ctx->error = X509_V_ERR_STORE_LOOKUP;
                goto end;
            }
            if (ok == 0)
                break;
            x = xtmp;
            if (!sk_X509_push(ctx->chain, x)) {
                X509_free(xtmp);
                OPENSSL_PUT_ERROR(X509, ERR_R_MALLOC_FAILURE);
                ctx->error = X509_V_ERR_OUT_OF_MEM;
                ok = 0;
                goto end;
            }
            num++;
        }

        /* we now have our chain, lets check it... */
        trust = check_trust(ctx);

        /* If explicitly rejected error */
        if (trust == X509_TRUST_REJECTED) {
            ok = 0;
            goto end;
        }
        /*
         * If it's not explicitly trusted then check if there is an alternative
         * chain that could be used. We only do this if we haven't already
         * checked via TRUSTED_FIRST and the user hasn't switched off alternate
         * chain checking
         */
        retry = 0;
        if (trust != X509_TRUST_TRUSTED
            && !(ctx->param->flags & X509_V_FLAG_TRUSTED_FIRST)
            && !(ctx->param->flags & X509_V_FLAG_NO_ALT_CHAINS)) {
            while (j-- > 1) {
                xtmp2 = sk_X509_value(ctx->chain, j - 1);
                ok = ctx->get_issuer(&xtmp, ctx, xtmp2);
                if (ok < 0)
                    goto end;
                /* Check if we found an alternate chain */
                if (ok > 0) {
                    /*
                     * Free up the found cert we'll add it again later
                     */
                    X509_free(xtmp);

                    /*
                     * Dump all the certs above this point - we've found an
                     * alternate chain
                     */
                    while (num > j) {
                        xtmp = sk_X509_pop(ctx->chain);
                        X509_free(xtmp);
                        num--;
                    }
                    ctx->last_untrusted = sk_X509_num(ctx->chain);
                    retry = 1;
                    break;
                }
            }
        }
    } while (retry);

    /*
     * If not explicitly trusted then indicate error unless it's a single
     * self signed certificate in which case we've indicated an error already
     * and set bad_chain == 1
     */
    if (trust != X509_TRUST_TRUSTED && !bad_chain) {
        if ((chain_ss == NULL) || !ctx->check_issued(ctx, x, chain_ss)) {
            if (ctx->last_untrusted >= num)
                ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
            else
                ctx->error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
            ctx->current_cert = x;
        } else {

            sk_X509_push(ctx->chain, chain_ss);
            num++;
            ctx->last_untrusted = num;
            ctx->current_cert = chain_ss;
            ctx->error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
            chain_ss = NULL;
        }

        ctx->error_depth = num - 1;
        bad_chain = 1;
        ok = cb(0, ctx);
        if (!ok)
            goto end;
    }

    /* We have the chain complete: now we need to check its purpose */
    ok = check_chain_extensions(ctx);

    if (!ok)
        goto end;

    ok = check_id(ctx);

    if (!ok)
        goto end;

    /*
     * Check revocation status: we do this after copying parameters because
     * they may be needed for CRL signature verification.
     */

    ok = ctx->check_revocation(ctx);
    if (!ok)
        goto end;

    int err = X509_chain_check_suiteb(&ctx->error_depth, NULL, ctx->chain,
                                      ctx->param->flags);
    if (err != X509_V_OK) {
        ctx->error = err;
        ctx->current_cert = sk_X509_value(ctx->chain, ctx->error_depth);
        ok = cb(0, ctx);
        if (!ok)
            goto end;
    }

    /* At this point, we have a chain and need to verify it */
    if (ctx->verify != NULL)
        ok = ctx->verify(ctx);
    else
        ok = internal_verify_impl(ctx);
    if (!ok)
        goto end;

    /* Check name constraints */

    ok = check_name_constraints(ctx);
    if (!ok)
        goto end;

    /* If we get this far evaluate policies */
    if (!bad_chain && (ctx->param->flags & X509_V_FLAG_POLICY_CHECK))
        ok = ctx->check_policy(ctx);

 end:
    if (sktmp != NULL)
        sk_X509_free(sktmp);
    if (chain_ss != NULL)
        X509_free(chain_ss);

    /* Safety net, error returns must set ctx->error */
    if (ok <= 0 && ctx->error == X509_V_OK)
        ctx->error = X509_V_ERR_UNSPECIFIED;
    return ok;
}

/*
 * Given a STACK_OF(X509) find the issuer of cert (if any)
 */

static X509 *find_issuer(X509_STORE_CTX *ctx, STACK_OF(X509) *sk, X509 *x)
{
    size_t i;
    X509 *issuer;
    for (i = 0; i < sk_X509_num(sk); i++) {
        issuer = sk_X509_value(sk, i);
        if (ctx->check_issued(ctx, x, issuer))
            return issuer;
    }
    return NULL;
}

/*
 * Check a certificate chains extensions for consistency with the supplied
 * purpose
 */

static int check_chain_extensions(X509_STORE_CTX *ctx)
{
    int i, ok = 0, plen = 0;
    X509 *x;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    int proxy_path_length = 0;
    int purpose;
    int allow_proxy_certs;
    cb = ctx->verify_cb;

    enum {
        // ca_or_leaf allows either type of certificate so that direct use of
        // self-signed certificates works.
        ca_or_leaf,
        must_be_ca,
        must_not_be_ca,
    } ca_requirement;

    /* CRL path validation */
    if (ctx->parent) {
        allow_proxy_certs = 0;
        purpose = X509_PURPOSE_CRL_SIGN;
    } else {
        allow_proxy_certs =
            ! !(ctx->param->flags & X509_V_FLAG_ALLOW_PROXY_CERTS);
        purpose = ctx->param->purpose;
    }

    ca_requirement = ca_or_leaf;

    /* Check all untrusted certificates */
    for (i = 0; i < ctx->last_untrusted; i++) {
        int ret;
        x = sk_X509_value(ctx->chain, i);
        if (!(ctx->param->flags & X509_V_FLAG_IGNORE_CRITICAL)
            && (x->ex_flags & EXFLAG_CRITICAL)) {
            ctx->error = X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        if (!allow_proxy_certs && (x->ex_flags & EXFLAG_PROXY)) {
            ctx->error = X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }

        switch (ca_requirement) {
        case ca_or_leaf:
            ret = 1;
            break;
        case must_not_be_ca:
            if (X509_check_ca(x)) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_NON_CA;
            } else
                ret = 1;
            break;
        case must_be_ca:
            if (!X509_check_ca(x)) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_CA;
            } else
                ret = 1;
            break;
        default:
            // impossible.
            ret = 0;
        }

        if (ret == 0) {
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        if (ctx->param->purpose > 0) {
            ret = X509_check_purpose(x, purpose, ca_requirement == must_be_ca);
            if (ret != 1) {
                ret = 0;
                ctx->error = X509_V_ERR_INVALID_PURPOSE;
                ctx->error_depth = i;
                ctx->current_cert = x;
                ok = cb(0, ctx);
                if (!ok)
                    goto end;
            }
        }
        /* Check pathlen if not self issued */
        if ((i > 1) && !(x->ex_flags & EXFLAG_SI)
            && (x->ex_pathlen != -1)
            && (plen > (x->ex_pathlen + proxy_path_length + 1))) {
            ctx->error = X509_V_ERR_PATH_LENGTH_EXCEEDED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            ok = cb(0, ctx);
            if (!ok)
                goto end;
        }
        /* Increment path length if not self issued */
        if (!(x->ex_flags & EXFLAG_SI))
            plen++;
        /*
         * If this certificate is a proxy certificate, the next certificate
         * must be another proxy certificate or a EE certificate.  If not,
         * the next certificate must be a CA certificate.
         */
        if (x->ex_flags & EXFLAG_PROXY) {
            if (x->ex_pcpathlen != -1 && i > x->ex_pcpathlen) {
                ctx->error = X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
                ctx->error_depth = i;
                ctx->current_cert = x;
                ok = cb(0, ctx);
                if (!ok)
                    goto end;
            }
            proxy_path_length++;
            ca_requirement = must_not_be_ca;
        } else {
            ca_requirement = must_be_ca;
        }
    }
    ok = 1;
 end:
    return ok;
}

static int reject_dns_name_in_common_name(X509 *x509)
{
    X509_NAME *name = X509_get_subject_name(x509);
    int i = -1;
    for (;;) {
        i = X509_NAME_get_index_by_NID(name, NID_commonName, i);
        if (i == -1) {
            return X509_V_OK;
        }

        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        ASN1_STRING *common_name = X509_NAME_ENTRY_get_data(entry);
        unsigned char *idval;
        int idlen = ASN1_STRING_to_UTF8(&idval, common_name);
        if (idlen < 0) {
            return X509_V_ERR_OUT_OF_MEM;
        }
        /* Only process attributes that look like host names. Note it is
         * important that this check be mirrored in |X509_check_host|. */
        int looks_like_dns = x509v3_looks_like_dns_name(idval, (size_t)idlen);
        OPENSSL_free(idval);
        if (looks_like_dns) {
            return X509_V_ERR_NAME_CONSTRAINTS_WITHOUT_SANS;
        }
    }
}

static int check_name_constraints(X509_STORE_CTX *ctx)
{
    int i, j, rv;
    int has_name_constraints = 0;
    /* Check name constraints for all certificates */
    for (i = sk_X509_num(ctx->chain) - 1; i >= 0; i--) {
        X509 *x = sk_X509_value(ctx->chain, i);
        /* Ignore self issued certs unless last in chain */
        if (i && (x->ex_flags & EXFLAG_SI))
            continue;
        /*
         * Check against constraints for all certificates higher in chain
         * including trust anchor. Trust anchor not strictly speaking needed
         * but if it includes constraints it is to be assumed it expects them
         * to be obeyed.
         */
        for (j = sk_X509_num(ctx->chain) - 1; j > i; j--) {
            NAME_CONSTRAINTS *nc = sk_X509_value(ctx->chain, j)->nc;
            if (nc) {
                has_name_constraints = 1;
                rv = NAME_CONSTRAINTS_check(x, nc);
                switch (rv) {
                case X509_V_OK:
                    continue;
                case X509_V_ERR_OUT_OF_MEM:
                    ctx->error = rv;
                    return 0;
                default:
                    ctx->error = rv;
                    ctx->error_depth = i;
                    ctx->current_cert = x;
                    if (!ctx->verify_cb(0, ctx))
                        return 0;
                    break;
                }
            }
        }
    }

    /* Name constraints do not match against the common name, but
     * |X509_check_host| still implements the legacy behavior where, on
     * certificates lacking a SAN list, DNS-like names in the common name are
     * checked instead.
     *
     * While we could apply the name constraints to the common name, name
     * constraints are rare enough that can hold such certificates to a higher
     * standard. Note this does not make "DNS-like" heuristic failures any
     * worse. A decorative common-name misidentified as a DNS name would fail
     * the name constraint anyway. */
    X509 *leaf = sk_X509_value(ctx->chain, 0);
    if (has_name_constraints && leaf->altname == NULL) {
        rv = reject_dns_name_in_common_name(leaf);
        switch (rv) {
        case X509_V_OK:
            break;
        case X509_V_ERR_OUT_OF_MEM:
            ctx->error = rv;
            return 0;
        default:
            ctx->error = rv;
            ctx->error_depth = i;
            ctx->current_cert = leaf;
            if (!ctx->verify_cb(0, ctx))
                return 0;
            break;
        }
    }

    return 1;
}

static int check_id_error(X509_STORE_CTX *ctx, int errcode)
{
    ctx->error = errcode;
    ctx->current_cert = ctx->cert;
    ctx->error_depth = 0;
    return ctx->verify_cb(0, ctx);
}

static int check_hosts(X509 *x, X509_VERIFY_PARAM_ID *id)
{
    size_t i;
    size_t n = sk_OPENSSL_STRING_num(id->hosts);
    char *name;

    if (id->peername != NULL) {
        OPENSSL_free(id->peername);
        id->peername = NULL;
    }
    for (i = 0; i < n; ++i) {
        name = sk_OPENSSL_STRING_value(id->hosts, i);
        if (X509_check_host(x, name, strlen(name), id->hostflags,
                            &id->peername) > 0)
            return 1;
    }
    return n == 0;
}

static int check_id(X509_STORE_CTX *ctx)
{
    X509_VERIFY_PARAM *vpm = ctx->param;
    X509_VERIFY_PARAM_ID *id = vpm->id;
    X509 *x = ctx->cert;
    if (id->poison) {
        if (!check_id_error(ctx, X509_V_ERR_INVALID_CALL))
            return 0;
    }
    if (id->hosts && check_hosts(x, id) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_HOSTNAME_MISMATCH))
            return 0;
    }
    if (id->email && X509_check_email(x, id->email, id->emaillen, 0) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_EMAIL_MISMATCH))
            return 0;
    }
    if (id->ip && X509_check_ip(x, id->ip, id->iplen, 0) <= 0) {
        if (!check_id_error(ctx, X509_V_ERR_IP_ADDRESS_MISMATCH))
            return 0;
    }
    return 1;
}

static int check_trust(X509_STORE_CTX *ctx)
{
    size_t i;
    int ok;
    X509 *x = NULL;
    int (*cb) (int xok, X509_STORE_CTX *xctx);
    cb = ctx->verify_cb;
    /* Check all trusted certificates in chain */
    for (i = ctx->last_untrusted; i < sk_X509_num(ctx->chain); i++) {
        x = sk_X509_value(ctx->chain, i);
        ok = X509_check_trust(x, ctx->param->trust, 0);
        /* If explicitly trusted return trusted */
        if (ok == X509_TRUST_TRUSTED)
            return X509_TRUST_TRUSTED;
        /*
         * If explicitly rejected notify callback and reject if not
         * overridden.
         */
        if (ok == X509_TRUST_REJECTED) {
            ctx->error_depth = i;
            ctx->current_cert = x;
            ctx->error = X509_V_ERR_CERT_REJECTED;
            ok = cb(0, ctx);
            if (!ok)
                return X509_TRUST_REJECTED;
        }
    }
    /*
     * If we accept partial chains and have at least one trusted certificate
     * return success.
     */
    if (ctx->param->flags & X509_V_FLAG_PARTIAL_CHAIN) {
        X509 *mx;
        if (ctx->last_untrusted < (int)sk_X509_num(ctx->chain))
            return X509_TRUST_TRUSTED;
        x = sk_X509_value(ctx->chain, 0);
        mx = lookup_cert_match(ctx, x);
        if (mx) {
            (void)sk_X509_set(ctx->chain, 0, mx);
            X509_free(x);
            ctx->last_untrusted = 0;
            return X509_TRUST_TRUSTED;
        }
    }

    /*
     * If no trusted certs in chain at all return untrusted and allow
     * standard (no issuer cert) etc errors to be indicated.
     */
    return X509_TRUST_UNTRUSTED;
}

static int check_cert_time(X509_STORE_CTX *ctx, X509 *x)
{
    time_t *ptime;
    int i;

    if (ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME)
        ptime = &ctx->param->check_time;
    else
        ptime = NULL;

    i = X509_cmp_time(X509_get_notBefore(x), ptime);
    if (i == 0) {
        ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (i > 0) {
        ctx->error = X509_V_ERR_CERT_NOT_YET_VALID;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    i = X509_cmp_time(X509_get_notAfter(x), ptime);
    if (i == 0) {
        ctx->error = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    if (i < 0) {
        ctx->error = X509_V_ERR_CERT_HAS_EXPIRED;
        ctx->current_cert = x;
        if (!ctx->verify_cb(0, ctx))
            return 0;
    }

    return 1;
}

int internal_verify_impl(X509_STORE_CTX *ctx)
{
    int ok = 0, n;
    X509 *xs, *xi;
    EVP_PKEY *pkey = NULL;
    int (*cb) (int xok, X509_STORE_CTX *xctx);

    cb = ctx->verify_cb;

    n = sk_X509_num(ctx->chain);
    ctx->error_depth = n - 1;
    n--;
    xi = sk_X509_value(ctx->chain, n);

    if (ctx->check_issued(ctx, xi, xi))
        xs = xi;
    else {
        if (ctx->param->flags & X509_V_FLAG_PARTIAL_CHAIN) {
            xs = xi;
            goto check_cert;
        }
        if (n <= 0) {
            ctx->error = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
            ctx->current_cert = xi;
            ok = cb(0, ctx);
            goto end;
        } else {
            n--;
            ctx->error_depth = n;
            xs = sk_X509_value(ctx->chain, n);
        }
    }

/*      ctx->error=0;  not needed */
    while (n >= 0) {
        ctx->error_depth = n;

        /*
         * Skip signature check for self signed certificates unless
         * explicitly asked for. It doesn't add any security and just wastes
         * time.
         */
        if (xs != xi || (ctx->param->flags & X509_V_FLAG_CHECK_SS_SIGNATURE)) {
            if ((pkey = X509_get_pubkey(xi)) == NULL) {
                ctx->error = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                ctx->current_cert = xi;
                ok = (*cb) (0, ctx);
                if (!ok)
                    goto end;
            } else if (X509_verify(xs, pkey) <= 0) {
                ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
                ctx->current_cert = xs;
                ok = (*cb) (0, ctx);
                if (!ok) {
                    EVP_PKEY_free(pkey);
                    goto end;
                }
            }
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }

 check_cert:
        ok = check_cert_time(ctx, xs);
        if (!ok)
            goto end;

        /* The last error (if any) is still in the error value */
        ctx->current_issuer = xi;
        ctx->current_cert = xs;
        ok = (*cb) (1, ctx);
        if (!ok)
            goto end;

        n--;
        if (n >= 0) {
            xi = xs;
            xs = sk_X509_value(ctx->chain, n);
        }
    }
    ok = 1;
 end:
    return ok;
}

