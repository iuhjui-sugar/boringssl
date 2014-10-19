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
 * OTHERWISE. */

#include <limits.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "ssl_locl.h"


static const int kKeyArgTag = CBS_ASN1_CONTEXT_SPECIFIC | 0;
static const int kTimeTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 1;
static const int kTimeoutTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 2;
static const int kPeerTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 3;
static const int kSessionIDContextTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 4;
static const int kVerifyResultTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 5;
static const int kHostNameTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 6;
static const int kPSKIdentityHintTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 7;
static const int kPSKIdentityTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 8;
static const int kTicketLifetimeHintTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 9;
static const int kTicketTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 10;
static const int kPeerSHA256Tag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 13;
static const int kOriginalHandshakeHashTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 14;
static const int kSignedCertTimestampListTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 15;
static const int kOCSPResponseTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 16;

int i2d_SSL_SESSION(SSL_SESSION *in, uint8_t **pp) {
  CBB cbb, session, child, child2;
  uint16_t cipher_id;
  size_t len;

  if (in == NULL || (in->cipher == NULL && in->cipher_id == 0)) {
    return 0;
  }

  if (pp) {
    /* TODO(davidben): Provide a safer API and deprecate this one. */
    if (!CBB_init_fixed(&cbb, *pp, (size_t)-1)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_MALLOC_FAILURE);
    }
  } else {
    if (!CBB_init_length_only(&cbb)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_MALLOC_FAILURE);
    }
  }

  if (in->cipher == NULL) {
    cipher_id = in->cipher_id & 0xffff;
  } else {
    cipher_id = in->cipher->id & 0xffff;
  }

  if (!CBB_add_asn1(&cbb, &session, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&session, SSL_SESSION_ASN1_VERSION) ||
      !CBB_add_asn1_uint64(&session, in->ssl_version) ||
      !CBB_add_asn1(&session, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_u16(&child, cipher_id) ||
      !CBB_add_asn1(&session, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, in->session_id, in->session_id_length) ||
      !CBB_add_asn1(&session, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, in->master_key, in->master_key_length)) {
    OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (in->time != 0) {
    if (!CBB_add_asn1(&session, &child, kTimeTag) ||
        !CBB_add_asn1_uint64(&child, in->time)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->timeout != 0) {
    if (!CBB_add_asn1(&session, &child, kTimeoutTag) ||
        !CBB_add_asn1_uint64(&child, in->timeout)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  /* The peer certificate is only serialized if the SHA-256 isn't
   * serialized instead. */
  if (in->peer && !in->peer_sha256_valid) {
    uint8_t *buf;
    int len = i2d_X509(in->peer, NULL);
    if (len < 0) {
      goto err;
    }
    if (!CBB_add_asn1(&session, &child, kPeerTag) ||
        !CBB_add_space(&child, &buf, len)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
    if (buf != NULL && i2d_X509(in->peer, &buf) < 0) {
      goto err;
    }
  }

  /* Although it is OPTIONAL and usually empty, OpenSSL has
   * historically always encoded the sid_ctx. */
  if (!CBB_add_asn1(&session, &child, kSessionIDContextTag) ||
      !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child2, in->sid_ctx, in->sid_ctx_length)) {
    OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (in->verify_result != X509_V_OK) {
    if (!CBB_add_asn1(&session, &child, kVerifyResultTag) ||
        !CBB_add_asn1_uint64(&child, in->verify_result)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->tlsext_hostname) {
    if (!CBB_add_asn1(&session, &child, kHostNameTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, (const uint8_t *)in->tlsext_hostname,
                       strlen(in->tlsext_hostname))) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->psk_identity_hint) {
    if (!CBB_add_asn1(&session, &child, kPSKIdentityHintTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, (const uint8_t *)in->psk_identity_hint,
                       strlen(in->psk_identity_hint))) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->psk_identity) {
    if (!CBB_add_asn1(&session, &child, kPSKIdentityTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, (const uint8_t *)in->psk_identity,
                       strlen(in->psk_identity))) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->tlsext_tick_lifetime_hint > 0) {
    if (!CBB_add_asn1(&session, &child, kTicketLifetimeHintTag) ||
        !CBB_add_asn1_uint64(&child, in->tlsext_tick_lifetime_hint)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->tlsext_tick) {
    if (!CBB_add_asn1(&session, &child, kTicketTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, in->tlsext_tick, in->tlsext_ticklen)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->peer_sha256_valid) {
    if (!CBB_add_asn1(&session, &child, kPeerSHA256Tag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, in->peer_sha256, sizeof(in->peer_sha256))) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->original_handshake_hash_len > 0) {
    if (!CBB_add_asn1(&session, &child, kOriginalHandshakeHashTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, in->original_handshake_hash,
                       in->original_handshake_hash_len)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->tlsext_signed_cert_timestamp_list_length > 0) {
    if (!CBB_add_asn1(&session, &child, kSignedCertTimestampListTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, in->tlsext_signed_cert_timestamp_list,
                       in->tlsext_signed_cert_timestamp_list_length)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (in->ocsp_response_length > 0) {
    if (!CBB_add_asn1(&session, &child, kOCSPResponseTag) ||
        !CBB_add_asn1(&child, &child2, CBS_ASN1_OCTETSTRING) ||
        !CBB_add_bytes(&child2, in->ocsp_response, in->ocsp_response_length)) {
      OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (!CBB_finish(&cbb, NULL, &len)) {
    OPENSSL_PUT_ERROR(SSL, i2d_SSL_SESSION, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (pp) {
    *pp += len;
  }
  return len;

err:
  CBB_cleanup(&cbb);
  return -1;
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const uint8_t **pp, long length) {
  SSL_SESSION *ret = NULL;
  CBS cbs, session, cipher, session_id, master_key;
  uint64_t version, ssl_version;

  if (a && *a) {
    ret = *a;
  } else {
    ret = SSL_SESSION_new();
    if (ret == NULL) {
      goto err;
    }
  }

  CBS_init(&cbs, *pp, length);
  if (!CBS_get_asn1(&cbs, &session, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&session, &version) ||
      !CBS_get_asn1_uint64(&session, &ssl_version) ||
      !CBS_get_asn1(&session, &cipher, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&session, &session_id, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&session, &master_key, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }

  /* Structure version number is ignored. */

  /* Only support TLS and DTLS. */
  if ((ssl_version >> 8) != SSL3_VERSION_MAJOR &&
      (ssl_version >> 8) != (DTLS1_VERSION >> 8)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_UNKNOWN_SSL_VERSION);
    goto err;
  }
  ret->ssl_version = ssl_version;

  /* Decode the cipher suite. */
  if (CBS_len(&cipher) != 2) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_CIPHER_CODE_WRONG_LENGTH);
    goto err;
  }
  ret->cipher_id =
      0x03000000L | (CBS_data(&cipher)[0] << 8L) | CBS_data(&cipher)[1];
  ret->cipher = ssl3_get_cipher_by_value(ret->cipher_id & 0xffff);
  if (ret->cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_UNSUPPORTED_CIPHER);
    goto err;
  }

  /* Copy the session ID. */
  if (CBS_len(&session_id) > SSL3_MAX_SSL_SESSION_ID_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->session_id, CBS_data(&session_id), CBS_len(&session_id));
  ret->session_id_length = CBS_len(&session_id);

  /* Copy the master key. */
  if (CBS_len(&master_key) > SSL_MAX_MASTER_KEY_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->master_key, CBS_data(&master_key), CBS_len(&master_key));
  ret->master_key_length = CBS_len(&master_key);

  /* keyArg [0] IMPLICIT OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kKeyArgTag)) {
    CBS child;
    if (!CBS_get_asn1(&session, &child, kKeyArgTag)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    /* Skip this field; it's SSLv2-only. */
  }

  /* time [1] INTEGER OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kTimeTag)) {
    CBS child;
    uint64_t start_time;
    if (!CBS_get_asn1(&session, &child, kTimeTag) ||
        !CBS_get_asn1_uint64(&child, &start_time) ||
        start_time > LONG_MAX ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    ret->time = start_time;
  } else {
    ret->time = (unsigned long)time(NULL);
  }

  /* timeout [2] INTEGER OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kTimeoutTag)) {
    CBS child;
    uint64_t timeout;
    if (!CBS_get_asn1(&session, &child, kTimeoutTag) ||
        !CBS_get_asn1_uint64(&child, &timeout) ||
        timeout > LONG_MAX ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    ret->timeout = timeout;
  } else {
    ret->timeout = 3;
  }

  if (ret->peer != NULL) {
    X509_free(ret->peer);
    ret->peer = NULL;
  }
  /* peer [3] Certificate OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kPeerTag)) {
    CBS child;
    const uint8_t *ptr;
    if (!CBS_get_asn1(&session, &child, kPeerTag)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    ptr = CBS_data(&child);
    ret->peer = d2i_X509(NULL, &ptr, CBS_len(&child));
    if (ret->peer == NULL) {
      goto err;
    }
    if (ptr != CBS_data(&child) + CBS_len(&child)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
  }

  /* sessionIDContext [4] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kSessionIDContextTag)) {
    CBS child, sid_ctx;
    if (!CBS_get_asn1(&session, &child, kSessionIDContextTag) ||
        !CBS_get_asn1(&child, &sid_ctx, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&sid_ctx) > SSL_MAX_SID_CTX_LENGTH ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    memcpy(ret->sid_ctx, CBS_data(&sid_ctx), CBS_len(&sid_ctx));
    ret->sid_ctx_length = CBS_len(&sid_ctx);
  } else {
    ret->sid_ctx_length = 0;
  }

  /* verifyResult [5] INTEGER OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kVerifyResultTag)) {
    CBS child;
    uint64_t verify_result;
    if (!CBS_get_asn1(&session, &child, kVerifyResultTag) ||
        !CBS_get_asn1_uint64(&child, &verify_result) ||
        verify_result > LONG_MAX ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    ret->verify_result = verify_result;
  } else {
    ret->verify_result = X509_V_OK;
  }

  /* hostName [6] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kHostNameTag)) {
    CBS child, hostname;
    if (!CBS_get_asn1(&session, &child, kHostNameTag) ||
        !CBS_get_asn1(&child, &hostname, CBS_ASN1_OCTETSTRING) ||
        CBS_contains_zero_byte(&hostname) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_strdup(&hostname, &ret->tlsext_hostname)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else if (ret->tlsext_hostname) {
    OPENSSL_free(ret->tlsext_hostname);
    ret->tlsext_hostname = NULL;
  }

  /* pskIdentityHint [7] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kPSKIdentityHintTag)) {
    CBS child, psk_identity_hint;
    if (!CBS_get_asn1(&session, &child, kPSKIdentityHintTag) ||
        !CBS_get_asn1(&child, &psk_identity_hint, CBS_ASN1_OCTETSTRING) ||
        CBS_contains_zero_byte(&psk_identity_hint) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_strdup(&psk_identity_hint, &ret->psk_identity_hint)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else if (ret->psk_identity_hint) {
    OPENSSL_free(ret->psk_identity_hint);
    ret->psk_identity_hint = NULL;
  }

  /* pskIdentity [8] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kPSKIdentityTag)) {
    CBS child, psk_identity;
    if (!CBS_get_asn1(&session, &child, kPSKIdentityTag) ||
        !CBS_get_asn1(&child, &psk_identity, CBS_ASN1_OCTETSTRING) ||
        CBS_contains_zero_byte(&psk_identity) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_strdup(&psk_identity, &ret->psk_identity)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else if (ret->psk_identity) {
    OPENSSL_free(ret->psk_identity);
    ret->psk_identity = NULL;
  }

  /* ticketLifetimeHint [9] INTEGER OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kTicketLifetimeHintTag)) {
    CBS child;
    uint64_t ticket_lifetime_hint;
    if (!CBS_get_asn1(&session, &child, kTicketLifetimeHintTag) ||
        !CBS_get_asn1_uint64(&child, &ticket_lifetime_hint) ||
        ticket_lifetime_hint > 0xffffffff ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    ret->tlsext_tick_lifetime_hint = ticket_lifetime_hint;
  } else {
    ret->tlsext_tick_lifetime_hint = 0;
  }

  /* ticket [10] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kTicketTag)) {
    CBS child, ticket;
    if (!CBS_get_asn1(&session, &child, kTicketTag) ||
        !CBS_get_asn1(&child, &ticket, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_stow(&ticket, &ret->tlsext_tick, &ret->tlsext_ticklen)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else {
    if (ret->tlsext_tick) {
      OPENSSL_free(ret->tlsext_tick);
    }
    ret->tlsext_tick = NULL;
    ret->tlsext_ticklen = 0;
  }

  /* peerSHA256 [13] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kPeerSHA256Tag)) {
    CBS child, peer_sha256;
    if (!CBS_get_asn1(&session, &child, kPeerSHA256Tag) ||
        !CBS_get_asn1(&child, &peer_sha256, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&peer_sha256) != sizeof(ret->peer_sha256) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    memcpy(ret->peer_sha256, CBS_data(&peer_sha256), sizeof(ret->peer_sha256));
    ret->peer_sha256_valid = 1;
  } else {
    ret->peer_sha256_valid = 0;
  }

  /* originalHandshakeHash [14] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kOriginalHandshakeHashTag)) {
    CBS child, original_handshake_hash;
    if (!CBS_get_asn1(&session, &child, kOriginalHandshakeHashTag) ||
        !CBS_get_asn1(&child, &original_handshake_hash, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&original_handshake_hash) >
            sizeof(ret->original_handshake_hash) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    memcpy(ret->original_handshake_hash, CBS_data(&original_handshake_hash),
           CBS_len(&original_handshake_hash));
    ret->original_handshake_hash_len = CBS_len(&original_handshake_hash);
  } else {
    ret->original_handshake_hash_len = 0;
  }

  /* signedCertTimestampList [15] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kSignedCertTimestampListTag)) {
    CBS child, sct_list;
    if (!CBS_get_asn1(&session, &child, kSignedCertTimestampListTag) ||
        !CBS_get_asn1(&child, &sct_list, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_stow(&sct_list, &ret->tlsext_signed_cert_timestamp_list,
                  &ret->tlsext_signed_cert_timestamp_list_length)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else {
    if (ret->tlsext_signed_cert_timestamp_list) {
      OPENSSL_free(ret->tlsext_signed_cert_timestamp_list);
    }
    ret->tlsext_signed_cert_timestamp_list = NULL;
    ret->tlsext_signed_cert_timestamp_list_length = 0;
  }

  /* ocspResponse [16] OCTET STRING OPTIONAL */
  if (CBS_peek_asn1_tag(&session, kOCSPResponseTag)) {
    CBS child, ocsp_response;
    if (!CBS_get_asn1(&session, &child, kOCSPResponseTag) ||
        !CBS_get_asn1(&child, &ocsp_response, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&child) != 0) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    if (!CBS_stow(&ocsp_response, &ret->ocsp_response,
                  &ret->ocsp_response_length)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  } else {
    if (ret->ocsp_response) {
      OPENSSL_free(ret->ocsp_response);
    }
    ret->ocsp_response = NULL;
    ret->ocsp_response_length = 0;
  }

  if (a) {
    *a = ret;
  }
  *pp = CBS_data(&cbs);
  return ret;

err:
  if (a && *a != ret) {
    SSL_SESSION_free(ret);
  }
  return NULL;
}
