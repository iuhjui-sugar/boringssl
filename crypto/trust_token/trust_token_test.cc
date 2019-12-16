/* Copyright (c) 2019, Google Inc.
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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/trust_token.h>

#include "../internal.h"

BSSL_NAMESPACE_BEGIN

namespace {

TEST(TrustTokenTest, Protocol) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key,
      &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  printf("Key Sizes: %zu %zu\n", priv_key_len, pub_key_len);

  TRUST_TOKEN_CLIENT *client = TRUST_TOKEN_CLIENT_new(100);
  ASSERT_TRUE(client);
  ASSERT_TRUE(
      TRUST_TOKEN_CLIENT_add_key(client, 1, pub_key, pub_key_len));

  TRUST_TOKEN_ISSUER *issuer = TRUST_TOKEN_ISSUER_new(100);
  ASSERT_TRUE(issuer);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_add_key(issuer, 1, priv_key, priv_key_len));


  bssl::UniquePtr<EVP_PKEY_CTX> pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  ASSERT_TRUE(pctx);
  ASSERT_TRUE(EVP_PKEY_keygen_init(pctx.get()));
  EVP_PKEY *priv = nullptr;
  ASSERT_TRUE(EVP_PKEY_keygen(pctx.get(), &priv));

  size_t pub_len;
  ASSERT_TRUE(EVP_PKEY_get_raw_public_key(priv, NULL, &pub_len));
  uint8_t *pub_data = (uint8_t *)OPENSSL_malloc(pub_len);
  ASSERT_TRUE(EVP_PKEY_get_raw_public_key(priv, pub_data, &pub_len));
  EVP_PKEY *pub =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_data, pub_len);

  TRUST_TOKEN_CLIENT_set_srr_key(client, pub);
  TRUST_TOKEN_ISSUER_set_srr_key(issuer, priv);

  uint8_t *msg, *resp;
  size_t msg_len, resp_len;

  uint32_t key_id;

  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client, &msg, &msg_len, 10));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(issuer, &resp, &resp_len, msg, msg_len));
  STACK_OF(TRUST_TOKEN) *tokens =
      TRUST_TOKEN_CLIENT_finish_issuance(client, &key_id, resp, resp_len);
  ASSERT_TRUE(tokens);

  size_t i = 0;
  for (TRUST_TOKEN *token : tokens) {
    // The 2nd, 5th, etc tokens are corrupted.
    if (i % 3 == 2) {
      token->data[0] = i>>8;
      token->data[1] = i;
    }
    const uint8_t kClientData[] =
        "\xa3\x68\x6b\x65\x79\x2d\x68\x61\x73\x68\x78\x20\xe3\xb0\xc4\x42\x98"
        "\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b"
        "\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55\x69\x70\x75\x62\x6c\x69\x73"
        "\x68\x65\x72\x6b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x74\x72"
        "\x65\x64\x65\x6d\x70\x74\x69\x6f\x6e\x2d\x74\x69\x6d\x65\x73\x74\x61"
        "\x6d\x70\x1a\x5e\x4c\x2f\xa8";

    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client, &msg, &msg_len, token, kClientData, sizeof(kClientData) - 1,
        1582051240));
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(issuer, &resp, &resp_len, &rtoken,
                                          &client_data, &client_data_len,
                                          msg, msg_len, 600));
    int result = false;
    uint8_t *srr = NULL, *sig = NULL;
    size_t srr_len, sig_len;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_finish_redemption(
        client, &result, &srr, &srr_len, &sig, &sig_len, resp, resp_len));
    ASSERT_TRUE(result == (i % 3 != 2));
    printf("Token #%zu/%zu: %d\n", ++i, sk_TRUST_TOKEN_num(tokens),
           token->data[0] << 8 | token->data[1]);
    if (srr != NULL) {
      printf("SRR: ");
      for(size_t j = 0; j < srr_len; j++) { printf("%02x", srr[j]); }
      printf("\n");
    }
    OPENSSL_free(srr);
    printf("Result: %d\n", result);

    TRUST_TOKEN_free(token);
  }

  TRUST_TOKEN_CLIENT_free(client);
  TRUST_TOKEN_ISSUER_free(issuer);
}

}  // namespace
BSSL_NAMESPACE_END
