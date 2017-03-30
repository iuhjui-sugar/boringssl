#include <openssl/base.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include "../internal.h"

#include "sha/sha256.c"
#include "hmac/hmac.c"
#include "digest/digest.c"
#include "digest/digests.c"

static void hexdump(const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(stderr, "%02x", in[i]);
  }
}

static void BORINGSSL_bcm_text_dummy_start(void) {}
static void BORINGSSL_bcm_text_dummy_end(void) {}
static void BORINGSSL_bcm_text_dummy_hash(void) {}

static void BORINGSSL_bcm_power_on_self_test(void) __attribute__((constructor,used));

static void BORINGSSL_bcm_power_on_self_test(void) {
  CRYPTO_library_init();

  const uint8_t *const start = (const uint8_t *)BORINGSSL_bcm_text_dummy_start;
  const uint8_t *const end = (const uint8_t *)BORINGSSL_bcm_text_dummy_end;

  static const uint8_t kHMACKey[32] = {0};
  uint8_t result[SHA256_DIGEST_LENGTH];

  unsigned result_len;
  if (!HMAC(EVP_sha256(), kHMACKey, sizeof(kHMACKey), start, end - start,
            result, &result_len) ||
      result_len != sizeof(result)) {
    goto err;
  }

  const uint8_t *const expected =
      (const uint8_t *)BORINGSSL_bcm_text_dummy_hash;

  if (OPENSSL_memcmp(expected, result, sizeof(result)) != 0) {
    fprintf(stderr, "FIPS integrity test failed.\nExpected: ");
    hexdump(expected, sizeof(result));
    fprintf(stderr, "\nCalculated: ");
    hexdump(result, sizeof(result));
    fprintf(stderr, "\n");
    goto err;
  }

  return;

err:
  for (;;) {
    exit(1);
  }
}
