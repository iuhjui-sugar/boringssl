

int ssl_do_client_cert_cb(SSL *ssl, X509 **out_x509, EVP_PKEY **out_pkey) {
  if (ssl->ctx->client_cert_cb == NULL) {
    return 0;
  }

  int ret = ssl->ctx->client_cert_cb(ssl, out_x509, out_pkey);
  if (ret <= 0) {
    return ret;
  }

  assert(*out_x509 != NULL);
  assert(*out_pkey != NULL);
  return 1;
}

int ssl_verify_server_cert(SSL *ssl) {
  int ret = ssl_verify_cert_chain(ssl, ssl->session->cert_chain);
  if (ssl->verify_mode != SSL_VERIFY_NONE && ret <= 0) {
    int al = ssl_verify_alarm_type(ssl->verify_result);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
    OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
  } else {
    ret = 1;
    ERR_clear_error(); /* but we keep ssl->verify_result */
  }

  return ret;
}
