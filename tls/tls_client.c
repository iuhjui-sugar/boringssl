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

int tls13_handshake(SSL *ssl) {
  int result = 0;

  ERR_clear_system_error();
  assert(!ssl->server);

  void (*cb)(const SSL *ssl, int type, int value) = NULL;
  if (ssl->info_callback != NULL) {
    cb = ssl->info_callback;
  } else if (ssl->ctx->info_callback != NULL) {
    cb = ssl->ctx->info_callback;
  }

  switch (ssl->handshake_state) {
    case HS_STATE_CONNECT:
      result = tls13_assemble_client_hello(ssl);
      // TODO: 0RTT (Finished/Application Data/end_of_early_data)
      ssl->handshake_state = HS_STATE_RECV_SERVER_HELLO;
      break;
    case HS_STATE_RECV_SERVER_HELLO:
      result = tls13_receive_server_hello(ssl);
      // Deal with Server Hello / Recv EncryptedExtensions / CertificateRequest / Certificate
      // / CertificateVerify / Finished
      break;
  }

  if (cb != NULL) {
    cb(ssl, SSL_CB_CONNECT_LOOP, result);
  }
  return result;
}

int tls13_assemble_client_hello(SSL *ssl) {
  CBB cbb;
  CBB_zero(&cbb);

  if (!ssl->s3->have_version) {
    uint16_t max_version = ssl_get_max_client_version(ssl);
    if (max_version == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_SSL_VERSION);
      goto err;
    }
    ssl->version = max_version;
    ssl->client_version = max_version;
  }

  CBB child;
  if (!CBB_init(&cbb, 16) ||
      !CBB_add_u16(&cbb, ssl->client_version) ||
      !ssl_fill_hello_random(ssl->s3->client_random,
                             sizeof(ssl->s3->client_random), 0) ||
      !CBB_add_bytes(&cbb, ssl->s3->client_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u8_length_prefixed(&cbb, &child)) {
    goto err;
  }

  MESSAGE client_hello;
  size_t unused;
  if (!ssl_write_client_cipher_list(ssl, &cbb) ||
      !CBB_add_u8(&cbb, 1) ||
      !CBB_add_u8(&cbb, 0) ||
      !ssl_add_clienthello_tlsext(ssl, &cbb, &unused) ||
      !CBB_finish(&cbb, &client_hello.data, &client_hello.length)) {
    goto err;
  }

  ssl->out_message = &client_hello;
  ssl->handshake_interrupt = HS_NEED_WRITE | HS_NEED_READ;
  return 0;

err:
  CBB_cleanup(&cbb);
  return -1;
}

int tls13_receive_server_hello(SSL *ssl) {
  CBS server_hello;
  CBS_init(&server_hello, ssl->in_message.data, ssl->in_message.length);

  CBS server_random;
  uint16_t server_version, cipher_suite;
  if (!CBS_get_u16(&server_hello, &server_version) ||
      !CBS_get_bytes(&server_hello, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&server_hello, &cipher_suite)) {
    goto f_err;
  }

  if (!ssl_is_version_enabled(ssl, server_version)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_PROTOCOL);
    ssl->version = server_version;
    /* Mark the version as fixed so the record-layer version is not clamped
     * to TLS 1.0. */
    ssl->s3->have_version = 1;
    al = SSL_AD_PROTOCOL_VERSION;
    goto f_err;
  }
  ssl->version = server_version;
  ssl->s3->enc_method = ssl_get_enc_method(server_version);
  assert(ssl->s3->enc_method != NULL);
  /* At this point, the connection's version is known and ssl->version is
   * fixed. Begin enforcing the record-layer version. */
  ssl->s3->have_version = 1;

  /* Copy over the server random. */
  memcpy(ssl->s3->server_random, CBS_data(&server_random), SSL3_RANDOM_SIZE);

  /* The session wasn't resumed. Create a fresh SSL_SESSION to
   * fill out. */
  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 0 /* client */)) {
    goto f_err;
  }

  c = SSL_get_cipher_by_value(cipher_suite);
  if (c == NULL) {
    /* unknown cipher */
    al = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    goto f_err;
  }
  /* If the cipher is disabled then we didn't sent it in the ClientHello, so if
   * the server selected it, it's an error. */
  if ((c->algorithm_mkey & ct->mask_k) || (c->algorithm_auth & ct->mask_a) ||
      SSL_CIPHER_get_min_version(c) > ssl_protocol_version(ssl)) {
    al = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    goto f_err;
  }

  sk = ssl_get_ciphers_by_id(ssl);
  if (!sk_SSL_CIPHER_find(sk, NULL, c)) {
    /* we did not say we would use this cipher */
    al = SSL_AD_ILLEGAL_PARAMETER;
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    goto f_err;
  }

  ssl->session->cipher = c;
  ssl->s3->tmp.new_cipher = c;

  /* Now that the cipher is known, initialize the handshake hash. */
  if (!ssl_init_handshake_hash(ssl)) {
    goto f_err;
  }

  /* If doing a full handshake with TLS 1.2, the server may request a client
   * certificate which requires hashing the handshake transcript under a
   * different hash. Otherwise, the handshake buffer may be released. */
  if (ssl_protocol_version(ssl) < TLS1_2_VERSION) {
    ssl_free_handshake_buffer(ssl);
  }

  /* TLS extensions */
  if (!ssl_parse_serverhello_tlsext(ssl, &server_hello)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    goto err;
  }

  /* There should be nothing left over in the record. */
  if (CBS_len(&server_hello) != 0) {
    /* wrong packet length */
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
    goto f_err;
  }

  return 1;

f_err:
  ssl_send_alert(ssl, SSL3_AL_FATAL, al);
err:
  return -1;

}
