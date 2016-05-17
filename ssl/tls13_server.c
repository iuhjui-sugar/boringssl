#include "internal.h"

int tls13_server_handshake(SSL *ssl) {
  return 1;
}

int tls13_server_post_handshake(SSL *ssl, SSL_HS_MESSAGE msg) {
  return 1;
}
