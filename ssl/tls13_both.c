#include <string.h>

#include "internal.h"

int tls13_handshake(SSL *ssl) {
  int result = 1;
  while (result == 1 && ssl->hs->handshake_state != HS_STATE_DONE) {
    ssl->rwstate = SSL_NOTHING;
    /* Functions which use SSL_get_error must clear the error queue on entry. */
    ERR_clear_error();

    printf("HS START\n");

    if (!SSL_in_init(ssl)) {
      return 1;
    }

    if (ssl->hs->handshake_interrupt & HS_NEED_WRITE) {
      int ret = ssl->method->write_handshake(ssl, ssl->hs->out_message);
      if (ret <= 0) {
       ssl->rwstate = SSL_WRITING;
        return ret;
      }
      OPENSSL_free(ssl->hs->out_message->data);
      ssl->hs->handshake_interrupt &= ~HS_NEED_WRITE;
    }
    if (ssl->hs->handshake_interrupt & HS_NEED_READ) {
      int ret = ssl->method->read_handshake(ssl, ssl->hs->in_message);
      if (ret <= 0) {
        ssl->rwstate = SSL_READING;
        return ret;
      }
      ssl->hs->handshake_interrupt &= ~HS_NEED_READ;
    }
    printf("IN: %d\n", ssl->hs->in_message->type);
    if (ssl->server) {
      result = tls13_server_handshake(ssl);
    } else {
      result = tls13_client_handshake(ssl);
    }
    printf("HS END %d: %d (%d)\n", result, ssl->hs->handshake_state, ssl->hs->handshake_interrupt);
  }

  return result;
}

int tls13_handshake_read(SSL *ssl, SSL_HS_MESSAGE *msg) {
  int n;
  int len;

  if (!msg->assembled) {
    if (msg->offset == 0) {
      msg->data = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH);
    }
    len = SSL3_HM_HEADER_LENGTH - msg->offset;
    n = ssl3_read_bytes(ssl, SSL3_RT_HANDSHAKE, &msg->data[msg->offset], len, 0);
    if (n < 0) {
      return -1;
    }

    msg->offset += n;
    if (n < len) {
      return 0;
    }

    uint8_t *p = msg->data;
    msg->type = *(p++);
    n2l3(p, msg->length);
    uint8_t *data = OPENSSL_malloc(SSL3_HM_HEADER_LENGTH + msg->length);
    memcpy(data, &msg->data, SSL3_HM_HEADER_LENGTH);
    OPENSSL_free(msg->data);
    msg->data = data;
    msg->assembled = 1;
  }
  len = msg->length - (msg->offset - SSL3_HM_HEADER_LENGTH);
  n = ssl3_read_bytes(ssl, SSL3_RT_HANDSHAKE, &msg->data[msg->offset], len, 0);
  if (n < 0) {
    printf("%x %x\n", (uint)msg->type, (uint)msg->length);
    return -1;
  }

  msg->offset += n;
  // UPDATE HASH
  if (n < len) {
    return 0;
  }

  if (ssl->msg_callback) {
    ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, &msg->data,
                      msg->length, ssl, ssl->msg_callback_arg);
  }

  uint8_t *data = OPENSSL_malloc(msg->length);
  memcpy(data, &msg->data[SSL3_HM_HEADER_LENGTH], msg->length);
  OPENSSL_free(msg->data);
  msg->data = data;

  msg->assembled = 0;
  msg->offset = 0;
  return 1;
}

int tls13_handshake_write(SSL *ssl, SSL_HS_MESSAGE *msg) {
  if (!msg->assembled) {
    uint8_t *data = OPENSSL_malloc(msg->length + SSL3_HM_HEADER_LENGTH);
    uint8_t *p = data;
    *(p++) = msg->type;
    l2n3(msg->length, p);
    memcpy(&data[SSL3_HM_HEADER_LENGTH], msg->data, msg->length);
    msg->offset = 0;
    OPENSSL_free(msg->data);
    msg->data = data;
    msg->length += SSL3_HM_HEADER_LENGTH;
    msg->assembled = 1;
  }

  int len = msg->length - msg->offset;
  int n = ssl3_write_bytes(ssl, SSL3_RT_HANDSHAKE, &msg->data[msg->offset], len);
  if (n < 0) {
    return -1;
  }

  msg->offset += n;
  // Update Hash
  if (n < len) {
    return 0;
  }

  if (ssl->msg_callback) {
    ssl->msg_callback(1, ssl->version, SSL3_RT_HANDSHAKE, &msg->data,
                      msg->length, ssl, ssl->msg_callback_arg);
  }

  msg->assembled = 0;
  msg->offset = 0;
  return 1;
}
