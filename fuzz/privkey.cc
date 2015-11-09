#include <openssl/evp.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  const uint8_t *bufp = buf;
  EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &bufp, len);
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
  return 0;
}
