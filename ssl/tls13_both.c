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
    if (hs->handshake_interrupt & HS_NEED_WRITE) {
      int ret = tls13_handshake_write(ssl, hs->out_message);
      if (ret <= 0) {
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

int tls13_assemble_handshake_message(SSL_HS_MESSAGE *out, uint8_t type,
                                     uint8_t *data, size_t length) {
  out->type = type;
  out->length = length;

  if (out->data != NULL) {
    OPENSSL_free(out->data);
    out->data = NULL;
  }
  out->data = OPENSSL_malloc(length);
  memcpy(out->data, data, length);

  if (out->raw != NULL) {
    OPENSSL_free(out->raw);
    out->raw = NULL;
  }
  out->offset = 0;

  return 1;
}

int tls13_handshake_read(SSL *ssl, SSL_HS_MESSAGE *msg) {
  int ok;
  long n = ssl->method->ssl_get_message(ssl, -1, ssl_hash_message, &ok);

  if (!ok) {
    return n;
  }

  if (!tls13_assemble_handshake_message(msg, ssl->s3->tmp.message_type,
                                        ssl->init_msg, n)) {
    return -1;
  }
  return 1;
}

int tls13_handshake_write(SSL *ssl, SSL_HS_MESSAGE *msg) {
  if (!msg->offset) {
    CBB cbb, data;
    if (!ssl->method->init_message(ssl, &cbb, &data, msg->type) ||
        !CBB_add_bytes(&data, msg->data, msg->length) ||
        !ssl->method->finish_message(ssl, &cbb)) {
      return -1;
    }
    msg->offset = 1;
  }

  int ret = ssl->method->write_message(ssl);
  if (ret <= 0) {
    return ret;
  }

  msg->offset = 0;
  return 1;
}
