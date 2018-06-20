/* Copyright (c) 2018, Google Inc.
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

#include <openssl/ssl.h>

#include <openssl/bytestring.h>

#include "internal.h"


namespace bssl {

constexpr int kHandoffVersion = 0;
constexpr int kHandbackVersion = 0;

bool SSL_serialize_handoff(const SSL *ssl, CBB *out) {
  const SSL3_STATE *const s3 = ssl->s3;
  if (!ssl->server ||
      s3->hs == nullptr ||
      s3->rwstate != SSL_HANDOFF) {
    return false;
  }

  CBB seq;
  Span<const uint8_t> transcript = s3->hs->transcript.buffer();
  if (!CBB_add_asn1(out, &seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&seq, kHandoffVersion) ||
      !CBB_add_asn1_octet_string(&seq, transcript.data(), transcript.size()) ||
      !CBB_add_asn1_octet_string(&seq,
                                 reinterpret_cast<uint8_t *>(s3->hs_buf->data),
                                 s3->hs_buf->length) ||
      !CBB_flush(out)) {
    return false;
  }

  return true;
}

bool SSL_decline_handoff(SSL *ssl) {
  const SSL3_STATE *const s3 = ssl->s3;
  if (!ssl->server ||
      s3->hs == nullptr ||
      s3->rwstate != SSL_HANDOFF) {
    return false;
  }

  s3->hs->config->handoff = false;
  return true;
}

bool SSL_apply_handoff(SSL *ssl, Span<const uint8_t> handoff) {
  if (ssl->method->is_dtls) {
    return false;
  }

  CBS seq, handoff_cbs(handoff);
  uint64_t handoff_version;
  if (!CBS_get_asn1(&handoff_cbs, &seq, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&seq, &handoff_version) ||
      handoff_version != kHandoffVersion) {
    return false;
  }

  CBS transcript, hs_buf;
  if (!CBS_get_asn1(&seq, &transcript, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &hs_buf, CBS_ASN1_OCTETSTRING)) {
    return false;
  }

  SSL_set_accept_state(ssl);

  SSL3_STATE *const s3 = ssl->s3;
  s3->v2_hello_done = true;
  s3->has_message = true;

  s3->hs_buf.reset(BUF_MEM_new());
  if (!s3->hs_buf ||
      !BUF_MEM_append(s3->hs_buf.get(), CBS_data(&hs_buf), CBS_len(&hs_buf))) {
    return false;
  }

  if (CBS_len(&transcript) != 0) {
    s3->hs->transcript.Update(transcript);
    s3->is_v2_hello = true;
  }
  s3->hs->handback = true;

  return true;
}

// serialize_config encodes how |ssl| is configured.  The configuration is used
// only to check that |ssl| doesn't have anything configured that is unsupported
// on the handback side.
static bool serialize_config(const SSL *ssl, CBB *out) {
  CBB ciphers;
  if (!CBB_add_u16(out, ssl->s3->hs->min_version) ||
      !CBB_add_u16(out, ssl->s3->hs->max_version) ||
      !CBB_add_asn1(out, &ciphers, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  STACK_OF(SSL_CIPHER) *configured_ciphers = SSL_get_ciphers(ssl);
  for (size_t i = 0; i < sk_SSL_CIPHER_num(configured_ciphers); ++i) {
    if (!CBB_add_u16(&ciphers,
                     static_cast<uint16_t>(SSL_CIPHER_get_id(
                         sk_SSL_CIPHER_value(configured_ciphers, i))))) {
      return false;
    }
  }
  CBB supported_groups;
  if (!CBB_add_asn1(out, &supported_groups, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  for (uint16_t group : tls1_get_grouplist(ssl->s3->hs.get())) {
    if (!CBB_add_u16(&supported_groups, group)) {
      return false;
    }
  }
  return CBB_flush(out);
}

bool SSL_serialize_handback(const SSL *ssl, CBB *out) {
  if (!ssl->server || ssl->method->is_dtls || ssl->version < TLS1_VERSION) {
    return false;
  }
  handback_t type;
  switch (ssl->s3->hs->state) {
    case state12_read_change_cipher_spec:
      type = handback_after_session_resumption;
      break;
    case state12_read_client_certificate:
      type = handback_after_ecdhe;
      break;
    case state12_finish_server_handshake:
      type = handback_after_handshake;
      break;
    default:
      return false;
  }

  const SSL3_STATE *const s3 = ssl->s3;
  size_t hostname_len = 0;
  if (s3->hostname) {
    hostname_len = strlen(s3->hostname.get());
  }

  Span<const uint8_t> transcript;
  if (type == handback_after_ecdhe ||
      type == handback_after_session_resumption) {
    transcript = s3->hs->transcript.buffer();
  }
  size_t write_iv_len = 0;
  const uint8_t *write_iv = nullptr;
  if ((type == handback_after_session_resumption ||
       type == handback_after_handshake) &&
      ssl->version == TLS1_VERSION &&
      SSL_CIPHER_is_block_cipher(s3->aead_write_ctx->cipher()) &&
      !s3->aead_write_ctx->GetIV(&write_iv, &write_iv_len)) {
    return false;
  }
  size_t read_iv_len = 0;
  const uint8_t *read_iv = nullptr;
  if (type == handback_after_handshake &&
      ssl->version == TLS1_VERSION &&
      SSL_CIPHER_is_block_cipher(s3->aead_read_ctx->cipher()) &&
      !s3->aead_read_ctx->GetIV(&read_iv, &read_iv_len)) {
      return false;
  }

  // TODO(mab): make sure everything is serialized.
  CBB seq, key_share;
  SSL_SESSION *session =
      s3->session_reused ? ssl->session : s3->hs->new_session.get();
  if (!CBB_add_asn1(out, &seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&seq, kHandbackVersion) ||
      !serialize_config(ssl, &seq) || !CBB_add_asn1_uint64(&seq, type) ||
      !CBB_add_asn1_octet_string(&seq, s3->read_sequence,
                                 sizeof(s3->read_sequence)) ||
      !CBB_add_asn1_octet_string(&seq, s3->write_sequence,
                                 sizeof(s3->write_sequence)) ||
      !CBB_add_asn1_octet_string(&seq, s3->server_random,
                                 sizeof(s3->server_random)) ||
      !CBB_add_asn1_octet_string(&seq, s3->client_random,
                                 sizeof(s3->client_random)) ||
      !CBB_add_asn1_octet_string(&seq, read_iv, read_iv_len) ||
      !CBB_add_asn1_octet_string(&seq, write_iv, write_iv_len) ||
      !CBB_add_asn1_bool(&seq, s3->session_reused) ||
      !CBB_add_asn1_bool(&seq, s3->tlsext_channel_id_valid) ||
      !ssl_session_serialize(session, &seq) ||
      !CBB_add_asn1_octet_string(&seq, s3->next_proto_negotiated.data(),
                                 s3->next_proto_negotiated.size()) ||
      !CBB_add_asn1_octet_string(&seq, s3->alpn_selected.data(),
                                 s3->alpn_selected.size()) ||
      !CBB_add_asn1_octet_string(
          &seq, reinterpret_cast<uint8_t *>(s3->hostname.get()),
          hostname_len) ||
      !CBB_add_asn1_octet_string(&seq, s3->tlsext_channel_id,
                                 sizeof(s3->tlsext_channel_id)) ||
      !CBB_add_asn1_bool(&seq, ssl->s3->token_binding_negotiated) ||
      !CBB_add_asn1_uint64(&seq, ssl->s3->negotiated_token_binding_param) ||
      !CBB_add_asn1_bool(&seq, s3->hs->next_proto_neg_seen) ||
      !CBB_add_asn1_bool(&seq, s3->hs->cert_request) ||
      !CBB_add_asn1_bool(&seq, s3->hs->extended_master_secret) ||
      !CBB_add_asn1_bool(&seq, s3->hs->ticket_expected) ||
      !CBB_add_asn1_uint64(&seq, SSL_CIPHER_get_id(s3->hs->new_cipher)) ||
      !CBB_add_asn1_octet_string(&seq, transcript.data(), transcript.size()) ||
      !CBB_add_asn1(&seq, &key_share, CBS_ASN1_SEQUENCE)) {
    return false;
  }
  if (type == handback_after_ecdhe &&
      !s3->hs->key_share->Serialize(&key_share)) {
    return false;
  }
  return CBB_flush(out);
}

// subset_u16 returns true if |remote|, a SEQUENCE of u16, is non-empty and
// contains no element that isn't present in |supported|.
static bool subset_u16(const uint16_t *supported, size_t len, CBS *remote) {
  CBS list;
  if (!CBS_get_asn1(remote, &list, CBS_ASN1_SEQUENCE) || CBS_len(&list) == 0) {
    return false;
  }
  uint16_t remote_config[len];
  size_t rlen = 0;
  while (CBS_len(&list)) {
    uint16_t id;
    if (!CBS_get_u16(&list, &id) || rlen > len) {
      return false;
    }
    remote_config[rlen++] = id;
  }
  qsort(remote_config, rlen, sizeof(uint16_t), compare_uint16_t);

  uint16_t local_config[len];
  memcpy(local_config, supported, len * sizeof(uint16_t));
  qsort(local_config, len, sizeof(uint16_t), compare_uint16_t);

  size_t r = 0, l = 0;
  for (; r < rlen; ++r) {
    if (local_config[l] > remote_config[r]) {
      return false;
    }
    while (local_config[l] < remote_config[r]) {
      ++l;
      if (l >= len) {
        return false;
      }
    }
    if (local_config[l] != remote_config[r]) {
      return false;
    }
  }
  return true;
}

// deserialize_config returns true iff the configuration used in the handshake
// enables no features that are not also enabled on |ssl|.
//
// For example, rather than choking only when the client and server happen to
// negotiate a cipher that's not supported here, on the handback side, be more
// consistent, and choke whenever the handshaker is configured to support a
// cipher that is unsupported here.
static bool deserialize_config(const SSL *ssl, CBS *in) {
  // TLS 1.3, and its multiple draft versions, is left for future generations to
  // handle.
  uint16_t min_version, max_version;
  if (!CBS_get_u16(in, &min_version) || !CBS_get_u16(in, &max_version) ||
      min_version == 0 || max_version == 0 ||
      min_version < ssl->s3->hs->config->conf_min_version ||
      max_version > ssl->s3->hs->config->conf_max_version ||
      max_version > TLS1_2_VERSION) {
    return false;
  }

  CBS ciphers;
  STACK_OF(SSL_CIPHER) *configured = SSL_get_ciphers(ssl);
  size_t len = sk_SSL_CIPHER_num(configured);
  uint16_t configured_ciphers[len];
  for (size_t i = 0; i < len; ++i) {
    configured_ciphers[i] = static_cast<uint16_t>(
        SSL_CIPHER_get_id(sk_SSL_CIPHER_value(configured, i)));
  }
  Span<const uint16_t> configured_groups =
      tls1_get_grouplist(ssl->s3->hs.get());
  if (!subset_u16(configured_ciphers, len, in) ||
      !subset_u16(configured_groups.data(), configured_groups.size(), in)) {
    return false;
  }
  return true;
}

bool SSL_apply_handback(SSL *ssl, Span<const uint8_t> handback) {
  if (ssl->do_handshake != nullptr ||
      ssl->method->is_dtls) {
    return false;
  }

  SSL3_STATE *const s3 = ssl->s3;
  uint64_t handback_version, negotiated_token_binding_param, cipher, type;

  CBS seq, read_seq, write_seq, server_rand, client_rand, read_iv, write_iv,
      next_proto, alpn, hostname, channel_id, transcript, key_share;
  int session_reused, channel_id_valid, cert_request, extended_master_secret,
      ticket_expected, token_binding_negotiated, next_proto_neg_seen;
  SSL_SESSION *session = nullptr;

  CBS handback_cbs(handback);
  if (!CBS_get_asn1(&handback_cbs, &seq, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&seq, &handback_version) ||
      handback_version != kHandbackVersion || !deserialize_config(ssl, &seq) ||
      !CBS_get_asn1_uint64(&seq, &type) ||
      !CBS_get_asn1(&seq, &read_seq, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&read_seq) != sizeof(s3->read_sequence) ||
      !CBS_get_asn1(&seq, &write_seq, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&write_seq) != sizeof(s3->write_sequence) ||
      !CBS_get_asn1(&seq, &server_rand, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&server_rand) != sizeof(s3->server_random) ||
      !CBS_copy_bytes(&server_rand, s3->server_random,
                      sizeof(s3->server_random)) ||
      !CBS_get_asn1(&seq, &client_rand, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&client_rand) != sizeof(s3->client_random) ||
      !CBS_copy_bytes(&client_rand, s3->client_random,
                      sizeof(s3->client_random)) ||
      !CBS_get_asn1(&seq, &read_iv, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &write_iv, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1_bool(&seq, &session_reused) ||
      !CBS_get_asn1_bool(&seq, &channel_id_valid)) {
    return false;
  }

  s3->hs = ssl_handshake_new(ssl);
  if (session_reused) {
    ssl->session =
        SSL_SESSION_parse(&seq, ssl->ctx->x509_method, ssl->ctx->pool)
            .release();
    session = ssl->session;
  } else {
    s3->hs->new_session =
        SSL_SESSION_parse(&seq, ssl->ctx->x509_method, ssl->ctx->pool);
    session = s3->hs->new_session.get();
  }

  if (!session || !CBS_get_asn1(&seq, &next_proto, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &alpn, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &hostname, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &channel_id, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&channel_id) != sizeof(s3->tlsext_channel_id) ||
      !CBS_copy_bytes(&channel_id, s3->tlsext_channel_id,
                      sizeof(s3->tlsext_channel_id)) ||
      !CBS_get_asn1_bool(&seq, &token_binding_negotiated) ||
      !CBS_get_asn1_uint64(&seq, &negotiated_token_binding_param) ||
      !CBS_get_asn1_bool(&seq, &next_proto_neg_seen) ||
      !CBS_get_asn1_bool(&seq, &cert_request) ||
      !CBS_get_asn1_bool(&seq, &extended_master_secret) ||
      !CBS_get_asn1_bool(&seq, &ticket_expected) ||
      !CBS_get_asn1_uint64(&seq, &cipher)) {
    return false;
  }
  if ((s3->hs->new_cipher =
           SSL_get_cipher_by_value(static_cast<uint16_t>(cipher))) == nullptr) {
    return false;
  }
  if (!CBS_get_asn1(&seq, &transcript, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &key_share, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  ssl->version = session->ssl_version;
  s3->have_version = true;
  if (!ssl_method_supports_version(ssl->method, ssl->version) ||
      session->cipher != s3->hs->new_cipher ||
      ssl_protocol_version(ssl) < SSL_CIPHER_get_min_version(session->cipher) ||
      SSL_CIPHER_get_max_version(session->cipher) < ssl_protocol_version(ssl)) {
    return false;
  }
  ssl->do_handshake = ssl_server_handshake;
  ssl->server = true;
  switch (type) {
    case handback_after_session_resumption:
      ssl->s3->hs->state = state12_read_change_cipher_spec;
      if (!session_reused) {
        return false;
      }
      break;
    case handback_after_ecdhe:
      ssl->s3->hs->state = state12_read_client_certificate;
      if (session_reused) {
        return false;
      }
      break;
    case handback_after_handshake:
      ssl->s3->hs->state = state12_finish_server_handshake;
      break;
    default:
      return false;
  }
  s3->session_reused = session_reused;
  s3->tlsext_channel_id_valid = channel_id_valid;
  s3->next_proto_negotiated.CopyFrom(next_proto);
  s3->alpn_selected.CopyFrom(alpn);

  const size_t hostname_len = CBS_len(&hostname);
  if (hostname_len == 0) {
    s3->hostname.reset();
  } else {
    char *hostname_str = nullptr;
    if (!CBS_strdup(&hostname, &hostname_str)) {
      return false;
    }
    s3->hostname.reset(hostname_str);
  }

  s3->token_binding_negotiated = token_binding_negotiated;
  s3->negotiated_token_binding_param =
      static_cast<uint8_t>(negotiated_token_binding_param);
  s3->hs->next_proto_neg_seen = next_proto_neg_seen;
  s3->hs->wait = ssl_hs_flush;
  s3->hs->extended_master_secret = extended_master_secret;
  s3->hs->ticket_expected = ticket_expected;
  s3->aead_write_ctx->SetVersionIfNullCipher(ssl->version);
  s3->hs->cert_request = cert_request;

  Array<uint8_t> key_block;
  if ((type == handback_after_session_resumption ||
       type == handback_after_handshake) &&
      (!tls1_configure_aead(ssl, evp_aead_seal, &key_block, session->cipher,
                            write_iv) ||
       !CBS_copy_bytes(&write_seq, s3->write_sequence,
                       sizeof(s3->write_sequence)))) {
    return false;
  }
  if (type == handback_after_handshake &&
      (!tls1_configure_aead(ssl, evp_aead_open, &key_block, session->cipher,
                            read_iv) ||
       !CBS_copy_bytes(&read_seq, s3->read_sequence,
                       sizeof(s3->read_sequence)))) {
    return false;
  }
  if ((type == handback_after_ecdhe ||
       type == handback_after_session_resumption) &&
      (!s3->hs->transcript.Init() ||
       !s3->hs->transcript.InitHash(ssl_protocol_version(ssl),
                                    s3->hs->new_cipher) ||
       !s3->hs->transcript.Update(transcript))) {
    return false;
  }
  if (type == handback_after_ecdhe &&
      (s3->hs->key_share = SSLKeyShare::Create(&key_share)) == nullptr) {
    return false;
  }

  return CBS_len(&seq) == 0;
}

}  // namespace bssl
