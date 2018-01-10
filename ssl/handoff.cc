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

constexpr int kHandbackVersion = 0;

bool SSL_serialize_handback(const SSL *ssl, CBB *out) {
  if (!ssl->server ||
      !ssl->s3->initial_handshake_complete) {
    return false;
  }

  const SSL3_STATE *const s3 = ssl->s3;
  size_t hostname_len = 0;
  if (s3->hostname) {
    hostname_len = strlen(s3->hostname.get());
  }

  CBB seq;
  if (!CBB_add_asn1(out, &seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&seq, kHandbackVersion) ||
      !CBB_add_asn1_uint64(&seq, ssl->version) ||
      !CBB_add_asn1_uint64(&seq, ssl->conf_max_version) ||
      !CBB_add_asn1_uint64(&seq, ssl->conf_min_version) ||
      !CBB_add_asn1_uint64(&seq, ssl->max_send_fragment) ||
      !CBB_add_asn1_octet_string(&seq, s3->read_sequence,
                                 sizeof(s3->read_sequence)) ||
      !CBB_add_asn1_octet_string(&seq, s3->write_sequence,
                                 sizeof(s3->write_sequence)) ||
      !CBB_add_asn1_octet_string(&seq, s3->server_random,
                                 sizeof(s3->server_random)) ||
      !CBB_add_asn1_octet_string(&seq, s3->client_random,
                                 sizeof(s3->client_random)) ||
      !CBB_add_asn1_bool(&seq, s3->session_reused) ||
      !CBB_add_asn1_bool(&seq, s3->tlsext_channel_id_valid) ||
      !ssl_session_serialize(&seq, s3->established_session.get()) ||
      !CBB_add_asn1_octet_string(&seq, s3->next_proto_negotiated.data(),
                                 s3->next_proto_negotiated.size()) ||
      !CBB_add_asn1_octet_string(&seq, s3->alpn_selected.data(),
                                 s3->alpn_selected.size()) ||
      !CBB_add_asn1_octet_string(
          &seq, reinterpret_cast<uint8_t *>(s3->hostname.get()), hostname_len) ||
      !CBB_add_asn1_octet_string(&seq, s3->tlsext_channel_id,
                                 sizeof(s3->tlsext_channel_id)) ||
      !CBB_add_asn1_uint64(&seq, ssl->options) ||
      !CBB_add_asn1_uint64(&seq, ssl->mode) ||
      !CBB_add_asn1_bool(&seq, ssl->tlsext_channel_id_enabled) ||
      !CBB_add_asn1_bool(&seq, ssl->retain_only_sha256_of_client_certs) ||
      !CBB_flush(out)) {
    return false;
  }

  return true;
}

bool SSL_apply_handback(SSL *ssl, CBS *handback) {
  if (ssl->do_handshake != nullptr) {
    return false;
  }

  SSL3_STATE *const s3 = ssl->s3;
  uint64_t handback_version, version, conf_max_version, conf_min_version,
      max_send_fragment, options, mode;
  CBS seq, read_seq, write_seq, server_rand, client_rand, next_proto, alpn,
      hostname, channel_id;
  int session_reused, channel_id_valid, channel_id_enabled, retain_only_sha256;

  if (!CBS_get_asn1(handback, &seq, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&seq, &handback_version) ||
      handback_version != kHandbackVersion) {
    return false;
  }

  if (!CBS_get_asn1_uint64(&seq, &version) ||
      !CBS_get_asn1_uint64(&seq, &conf_max_version) ||
      !CBS_get_asn1_uint64(&seq, &conf_min_version) ||
      !CBS_get_asn1_uint64(&seq, &max_send_fragment) ||
      !CBS_get_asn1(&seq, &read_seq, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&read_seq) != sizeof(s3->read_sequence) ||
      !CBS_get_asn1(&seq, &write_seq, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&write_seq) != sizeof(s3->write_sequence) ||
      !CBS_get_asn1(&seq, &server_rand, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&server_rand) != sizeof(s3->server_random) ||
      !CBS_get_asn1(&seq, &client_rand, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&client_rand) != sizeof(s3->client_random) ||
      !CBS_get_asn1_bool(&seq, &session_reused) ||
      !CBS_get_asn1_bool(&seq, &channel_id_valid)) {
    return false;
  }

  s3->established_session =
      SSL_SESSION_parse(&seq, ssl->ctx->x509_method, ssl->ctx->pool);

  if (!s3->established_session ||
      !CBS_get_asn1(&seq, &next_proto, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &alpn, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &hostname, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&seq, &channel_id, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&channel_id) != sizeof(s3->tlsext_channel_id) ||
      !CBS_get_asn1_uint64(&seq, &options) ||
      !CBS_get_asn1_uint64(&seq, &mode) ||
      !CBS_get_asn1_bool(&seq, &channel_id_enabled) ||
      !CBS_get_asn1_bool(&seq, &retain_only_sha256)) {
    return false;
  }

  if (ssl->conf_max_version != conf_max_version ||
      ssl->conf_min_version != conf_min_version ||
      ssl->options != options ||
      ssl->mode != mode) {
    return false;
  }

  ssl->version = version;
  ssl->max_send_fragment = max_send_fragment;
  ssl->do_handshake = ssl_server_handshake;
  ssl->server = true;

  s3->hs.reset();
  OPENSSL_memcpy(s3->server_random, CBS_data(&server_rand),
                 sizeof(s3->server_random));
  OPENSSL_memcpy(s3->client_random, CBS_data(&client_rand),
                 sizeof(s3->client_random));
  s3->have_version = true;
  s3->initial_handshake_complete = true;
  s3->session_reused = session_reused;
  s3->tlsext_channel_id_valid = channel_id_valid;
  s3->next_proto_negotiated.CopyFrom(next_proto);
  s3->alpn_selected.CopyFrom(alpn);

  const size_t hostname_len = CBS_len(&hostname);
  if (hostname_len == 0) {
    s3->hostname.reset();
  } else {
    s3->hostname.reset(
        reinterpret_cast<char *>(OPENSSL_malloc(hostname_len + 1)));
    OPENSSL_memcpy(s3->hostname.get(), CBS_data(&hostname), hostname_len);
    s3->hostname.get()[hostname_len] = 0;
  }

  OPENSSL_memcpy(s3->tlsext_channel_id, CBS_data(&channel_id),
                 sizeof(s3->tlsext_channel_id));

  ssl->tlsext_channel_id_enabled = channel_id_enabled;
  ssl->retain_only_sha256_of_client_certs = retain_only_sha256;

  Array<uint8_t> key_block;
  if (!tls1_configure_aead(ssl, evp_aead_open, &key_block,
                           s3->established_session->cipher) ||
      !tls1_configure_aead(ssl, evp_aead_seal, &key_block,
                           s3->established_session->cipher)) {
    return false;
  }

  OPENSSL_memcpy(s3->read_sequence, CBS_data(&read_seq),
                 sizeof(s3->read_sequence));
  OPENSSL_memcpy(s3->write_sequence, CBS_data(&write_seq),
                 sizeof(s3->write_sequence));

  return true;
}

}  // namespace bssl
