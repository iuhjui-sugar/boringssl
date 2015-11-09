#include <openssl/x509.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  const uint8_t *bufp = buf;
  X509 *cert = d2i_X509(NULL, &bufp, len);
  if (cert != NULL) {
    X509_free(cert);
  }
  return 0;
}
