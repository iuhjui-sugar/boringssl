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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <utility>

#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "../crypto/internal.h"
#include "internal.h"


namespace bssl {

static int ssl3_send_cert_verify(SSL_HANDSHAKE *hs);
static int ssl3_send_next_proto(SSL_HANDSHAKE *hs);
static int ssl3_send_channel_id(SSL_HANDSHAKE *hs);
static int ssl3_get_new_session_ticket(SSL_HANDSHAKE *hs);

int ssl3_connect(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  int ret = -1;

  assert(ssl->handshake_func == ssl3_connect);
  assert(!ssl->server);

  for (;;) {
    int state = hs->state;

    switch (hs->state) {
      case SSL_ST_INIT: {
        ssl_do_info_callback(ssl, SSL_CB_HANDSHAKE_START, 1);
        hs->do_tls_handshake = tls_client_handshake;
        int early_return = 0;
        ret = tls_handshake(hs, &early_return);
        if (ret <= 0) {
          goto end;
        }

        if (early_return) {
          ret = 1;
          goto end;
        }

        break;
      }

      case SSL3_ST_CW_CERT_VRFY_A:
        if (hs->cert_request && ssl_has_certificate(ssl)) {
          ret = ssl3_send_cert_verify(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_CW_CHANGE;
        break;

      case SSL3_ST_CW_CHANGE:
        if (!ssl->method->add_change_cipher_spec(ssl) ||
            !tls1_change_cipher_state(hs, SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
          ret = -1;
          goto end;
        }

        hs->state = SSL3_ST_CW_NEXT_PROTO_A;
        break;

      case SSL3_ST_CW_NEXT_PROTO_A:
        if (hs->next_proto_neg_seen) {
          ret = ssl3_send_next_proto(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_CW_CHANNEL_ID_A;
        break;

      case SSL3_ST_CW_CHANNEL_ID_A:
        if (ssl->s3->tlsext_channel_id_valid) {
          ret = ssl3_send_channel_id(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_CW_FINISHED_A;
        break;

      case SSL3_ST_CW_FINISHED_A:
        ret = ssl3_send_finished(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_CW_FLUSH;

        if (ssl->session != NULL) {
          hs->next_state = SSL3_ST_FINISH_CLIENT_HANDSHAKE;
        } else {
          /* This is a non-resumption handshake. If it involves ChannelID, then
           * record the handshake hashes at this point in the session so that
           * any resumption of this session with ChannelID can sign those
           * hashes. */
          ret = tls1_record_handshake_hashes_for_channel_id(hs);
          if (ret <= 0) {
            goto end;
          }
          if ((SSL_get_mode(ssl) & SSL_MODE_ENABLE_FALSE_START) &&
              ssl3_can_false_start(ssl) &&
              /* No False Start on renegotiation (would complicate the state
               * machine). */
              !ssl->s3->initial_handshake_complete) {
            hs->next_state = SSL3_ST_FALSE_START;
          } else {
            hs->next_state = SSL3_ST_CR_SESSION_TICKET_A;
          }
        }
        break;

      case SSL3_ST_FALSE_START:
        hs->state = SSL3_ST_CR_SESSION_TICKET_A;
        hs->in_false_start = 1;
        hs->can_early_write = 1;
        ret = 1;
        goto end;

      case SSL3_ST_CR_SESSION_TICKET_A:
        if (hs->ticket_expected) {
          ret = ssl3_get_new_session_ticket(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_CR_CHANGE;
        break;

      case SSL3_ST_CR_CHANGE:
        ret = ssl->method->read_change_cipher_spec(ssl);
        if (ret <= 0) {
          goto end;
        }

        if (!tls1_change_cipher_state(hs, SSL3_CHANGE_CIPHER_CLIENT_READ)) {
          ret = -1;
          goto end;
        }
        hs->state = SSL3_ST_CR_FINISHED_A;
        break;

      case SSL3_ST_CR_FINISHED_A:
        ret = ssl3_get_finished(hs);
        if (ret <= 0) {
          goto end;
        }

        if (ssl->session != NULL) {
          hs->state = SSL3_ST_CW_CHANGE;
        } else {
          hs->state = SSL3_ST_FINISH_CLIENT_HANDSHAKE;
        }
        break;

      case SSL3_ST_CW_FLUSH:
        ret = ssl->method->flush_flight(ssl);
        if (ret <= 0) {
          goto end;
        }
        hs->state = hs->next_state;
        break;

      case SSL3_ST_FINISH_CLIENT_HANDSHAKE:
        ssl->method->on_handshake_complete(ssl);

        SSL_SESSION_free(ssl->s3->established_session);
        if (ssl->session != NULL) {
          SSL_SESSION_up_ref(ssl->session);
          ssl->s3->established_session = ssl->session;
        } else {
          /* We make a copy of the session in order to maintain the immutability
           * of the new established_session due to False Start. The caller may
           * have taken a reference to the temporary session. */
          ssl->s3->established_session =
              SSL_SESSION_dup(hs->new_session.get(), SSL_SESSION_DUP_ALL)
                  .release();
          if (ssl->s3->established_session == NULL) {
            ret = -1;
            goto end;
          }
          ssl->s3->established_session->not_resumable = 0;

          hs->new_session.reset();
        }

        hs->state = SSL_ST_OK;
        break;

      case SSL_ST_OK: {
        const int is_initial_handshake = !ssl->s3->initial_handshake_complete;
        ssl->s3->initial_handshake_complete = 1;
        if (is_initial_handshake) {
          /* Renegotiations do not participate in session resumption. */
          ssl_update_cache(hs, SSL_SESS_CACHE_CLIENT);
        }

        ret = 1;
        ssl_do_info_callback(ssl, SSL_CB_HANDSHAKE_DONE, 1);
        goto end;
      }

      default:
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_STATE);
        ret = -1;
        goto end;
    }

    if (hs->state != state) {
      ssl_do_info_callback(ssl, SSL_CB_CONNECT_LOOP, 1);
    }
  }

end:
  ssl_do_info_callback(ssl, SSL_CB_CONNECT_EXIT, ret);
  return ret;
}

static int ssl3_send_cert_verify(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  assert(ssl_has_private_key(ssl));

  ScopedCBB cbb;
  CBB body, child;
  if (!ssl->method->init_message(ssl, cbb.get(), &body,
                                 SSL3_MT_CERTIFICATE_VERIFY)) {
    return -1;
  }

  uint16_t signature_algorithm;
  if (!tls1_choose_signature_algorithm(hs, &signature_algorithm)) {
    return -1;
  }
  if (ssl3_protocol_version(ssl) >= TLS1_2_VERSION) {
    /* Write out the digest type in TLS 1.2. */
    if (!CBB_add_u16(&body, signature_algorithm)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      return -1;
    }
  }

  /* Set aside space for the signature. */
  const size_t max_sig_len = EVP_PKEY_size(hs->local_pubkey.get());
  uint8_t *ptr;
  if (!CBB_add_u16_length_prefixed(&body, &child) ||
      !CBB_reserve(&child, &ptr, max_sig_len)) {
    return -1;
  }

  size_t sig_len = max_sig_len;
  /* The SSL3 construction for CertificateVerify does not decompose into a
   * single final digest and signature, and must be special-cased. */
  if (ssl3_protocol_version(ssl) == SSL3_VERSION) {
    if (ssl->cert->key_method != NULL) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL_FOR_CUSTOM_KEY);
      return -1;
    }

    uint8_t digest[EVP_MAX_MD_SIZE];
    size_t digest_len;
    if (!hs->transcript.GetSSL3CertVerifyHash(
            digest, &digest_len, hs->new_session.get(), signature_algorithm)) {
      return -1;
    }

    UniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new(ssl->cert->privatekey, NULL));
    if (!pctx ||
        !EVP_PKEY_sign_init(pctx.get()) ||
        !EVP_PKEY_sign(pctx.get(), ptr, &sig_len, digest, digest_len)) {
      return -1;
    }
  } else {
    switch (ssl_private_key_sign(
        hs, ptr, &sig_len, max_sig_len, signature_algorithm,
        hs->transcript.buffer_data(), hs->transcript.buffer_len())) {
      case ssl_private_key_success:
        break;
      case ssl_private_key_failure:
        return -1;
      case ssl_private_key_retry:
        ssl->rwstate = SSL_PRIVATE_KEY_OPERATION;
        return -1;
    }
  }

  if (!CBB_did_write(&child, sig_len) ||
      !ssl_add_message_cbb(ssl, cbb.get())) {
    return -1;
  }

  /* The handshake buffer is no longer necessary. */
  hs->transcript.FreeBuffer();
  return 1;
}

static int ssl3_send_next_proto(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  static const uint8_t kZero[32] = {0};
  size_t padding_len = 32 - ((ssl->s3->next_proto_negotiated_len + 2) % 32);

  ScopedCBB cbb;
  CBB body, child;
  if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_NEXT_PROTO) ||
      !CBB_add_u8_length_prefixed(&body, &child) ||
      !CBB_add_bytes(&child, ssl->s3->next_proto_negotiated,
                     ssl->s3->next_proto_negotiated_len) ||
      !CBB_add_u8_length_prefixed(&body, &child) ||
      !CBB_add_bytes(&child, kZero, padding_len) ||
      !ssl_add_message_cbb(ssl, cbb.get())) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  return 1;
}

static int ssl3_send_channel_id(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!ssl_do_channel_id_callback(ssl)) {
    return -1;
  }

  if (ssl->tlsext_channel_id_private == NULL) {
    ssl->rwstate = SSL_CHANNEL_ID_LOOKUP;
    return -1;
  }

  ScopedCBB cbb;
  CBB body;
  if (!ssl->method->init_message(ssl, cbb.get(), &body, SSL3_MT_CHANNEL_ID) ||
      !tls1_write_channel_id(hs, &body) ||
      !ssl_add_message_cbb(ssl, cbb.get())) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  return 1;
}

static int ssl3_get_new_session_ticket(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  SSLMessage msg;
  int ret = ssl_read_message(ssl, &msg);
  if (ret <= 0) {
    return ret;
  }

  if (!ssl_check_message_type(ssl, msg, SSL3_MT_NEW_SESSION_TICKET) ||
      !ssl_hash_message(hs, msg)) {
    return -1;
  }

  CBS new_session_ticket = msg.body, ticket;
  uint32_t tlsext_tick_lifetime_hint;
  if (!CBS_get_u32(&new_session_ticket, &tlsext_tick_lifetime_hint) ||
      !CBS_get_u16_length_prefixed(&new_session_ticket, &ticket) ||
      CBS_len(&new_session_ticket) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return -1;
  }

  if (CBS_len(&ticket) == 0) {
    /* RFC 5077 allows a server to change its mind and send no ticket after
     * negotiating the extension. The value of |ticket_expected| is checked in
     * |ssl_update_cache| so is cleared here to avoid an unnecessary update. */
    hs->ticket_expected = 0;
    ssl->method->next_message(ssl);
    return 1;
  }

  SSL_SESSION *session = hs->new_session.get();
  UniquePtr<SSL_SESSION> renewed_session;
  if (ssl->session != NULL) {
    /* The server is sending a new ticket for an existing session. Sessions are
     * immutable once established, so duplicate all but the ticket of the
     * existing session. */
    renewed_session =
        SSL_SESSION_dup(ssl->session, SSL_SESSION_INCLUDE_NONAUTH);
    if (!renewed_session) {
      /* This should never happen. */
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      return -1;
    }
    session = renewed_session.get();
  }

  /* |tlsext_tick_lifetime_hint| is measured from when the ticket was issued. */
  ssl_session_rebase_time(ssl, session);

  if (!CBS_stow(&ticket, &session->tlsext_tick, &session->tlsext_ticklen)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return -1;
  }
  session->tlsext_tick_lifetime_hint = tlsext_tick_lifetime_hint;

  /* Generate a session ID for this session based on the session ticket. We use
   * the session ID mechanism for detecting ticket resumption. This also fits in
   * with assumptions elsewhere in OpenSSL.*/
  if (!EVP_Digest(CBS_data(&ticket), CBS_len(&ticket),
                  session->session_id, &session->session_id_length,
                  EVP_sha256(), NULL)) {
    return -1;
  }

  if (renewed_session) {
    session->not_resumable = 0;
    SSL_SESSION_free(ssl->session);
    ssl->session = renewed_session.release();
  }

  ssl->method->next_message(ssl);
  return 1;
}

}  // namespace bssl
