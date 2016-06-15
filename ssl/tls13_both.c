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

#include <string.h>

#include "internal.h"

int tls13_handshake(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  int result = 1;
  while (result && hs->handshake_state != HS_STATE_DONE) {
    ssl->rwstate = SSL_NOTHING;

    if (hs->handshake_interrupt & HS_NEED_WRITE) {
      int ret = tls13_handshake_write(ssl, hs->out_message);
      if (ret <= 0) {
       ssl->rwstate = SSL_WRITING;
        return ret;
      }
      hs->handshake_interrupt &= ~HS_NEED_WRITE;
      if (hs->handshake_interrupt & HS_NEED_FLUSH) {
        return 1;
      }
    }
    if (hs->handshake_interrupt & HS_NEED_READ) {
      int ret = tls13_handshake_read(ssl, hs->in_message);
      if (ret <= 0) {
        ssl->rwstate = SSL_READING;
        return ret;
      }
      hs->handshake_interrupt &= ~HS_NEED_READ;
    }
    if (ssl->server) {
      result = tls13_server_handshake(ssl, hs);
    } else {
      result = tls13_client_handshake(ssl, hs);
    }
  }

  return result;
}

int assemble_handshake_message(SSL_HS_MESSAGE *out, uint8_t type, uint8_t *data,
                               size_t length) {
  if (out->raw != NULL) {
    OPENSSL_free(out->raw);
    out->raw = NULL;
  }

  out->type = type;
  out->length = length;
  out->raw = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH + out->length);
  if (out->raw == NULL) {
    return -1;
  }
  uint8_t *p = out->raw;
  *(p++) = out->type;
  l2n3(out->length, p);
  out->data = p;
  memcpy(out->data, data, out->length);
  out->offset = 0;

  return 1;
}

int tls13_handshake_read(SSL *ssl, SSL_HS_MESSAGE *msg) {
  int ok;
  long n = ssl->method->ssl_get_message(ssl, -1, ssl_dont_hash_message, &ok);

  if (!ok) {
    return n;
  }

  if (!assemble_handshake_message(msg, ssl->s3->tmp.message_type, ssl->init_msg,
                                  n)) {
    return -1;
  }

  ssl3_update_handshake_hash(ssl, msg->raw, n + SSL3_HM_HEADER_LENGTH);
  return 1;
}

int tls13_handshake_write(SSL *ssl, SSL_HS_MESSAGE *msg) {
  size_t length = SSL3_HM_HEADER_LENGTH + msg->length;

  if (!msg->offset) {
    CBB cbb, data;
    if (!CBB_init_fixed(&cbb, (uint8_t *)ssl->init_buf->data, length) ||
        !CBB_add_u8(&cbb, msg->type) ||
        !CBB_add_u24_length_prefixed(&cbb, &data) ||
        !CBB_add_bytes(&data, msg->data, msg->length) ||
        !CBB_finish(&cbb, NULL, NULL)) {
      return -1;
    }
    ssl->init_num = length;
    ssl->init_off = 0;
    msg->offset = 1;
  }

  int ret = ssl_do_write(ssl);
  if (ret <= 0) {
    return ret;
  }

  ssl3_update_handshake_hash(ssl, msg->raw, length);
  msg->offset = 0;
  return 1;
}

int tls13_post_handshake_read(SSL *ssl, SSL3_RECORD *rr) {
  SSL_HS_MESSAGE *msg = ssl->s3->post_message;
  if (msg->offset < SSL3_HM_HEADER_LENGTH) {
    if (msg->raw != NULL) {
      OPENSSL_free(msg->raw);
      msg->raw = NULL;
    }

    if (msg->offset == 0) {
      msg->data = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH);
    }

    size_t length = SSL3_HM_HEADER_LENGTH;
    size_t n = length - msg->offset;
    if (rr->length < n) {
      n = rr->length;
    }
    memcpy(&msg->data[msg->offset], rr->data, n);

    msg->offset += n;
    rr->data += n;
    rr->length -= n;
    if (msg->offset < length) {
      return 0;
    }

    const uint8_t *p = msg->data;
    msg->type = p[0];
    msg->length = (((uint32_t)p[1]) << 16) | (((uint32_t)p[2]) << 8) | p[3];
    msg->raw = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH + msg->length);
    if (msg->raw == NULL) {
      return -1;
    }
    memcpy(msg->raw, msg->data, SSL3_HM_HEADER_LENGTH);
    OPENSSL_free(msg->data);
    msg->data = &msg->raw[SSL3_HM_HEADER_LENGTH];
  }

  size_t length = SSL3_HM_HEADER_LENGTH + msg->length;
  size_t n = length - msg->offset;
  if (rr->length < n) {
    n = rr->length;
  }
  memcpy(&msg->raw[msg->offset], rr->data, n);

  msg->offset += n;
  rr->data += n;
  rr->length -= n;
  if (msg->offset < length) {
    return 0;
  }

  msg->offset = 0;
  ssl3_update_handshake_hash(ssl, msg->raw, length);
  if (ssl->msg_callback) {
    ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, &msg->raw,
                      length, ssl, ssl->msg_callback_arg);
  }

  if (ssl->server) {
    if (!tls13_server_post_handshake(ssl, *msg)) {
      return -1;
    }
  } else {
    if (!tls13_client_post_handshake(ssl, *msg)) {
      return -1;
    }
  }

  return 1;
}
