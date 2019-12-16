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

#include <openssl/mem.h>
#include <openssl/trust_token.h>

BSSL_NAMESPACE_BEGIN

namespace {

TEST(TrustTokenTest, ClearProtocol) {
  TT_CTX *client = TRUST_TOKEN_Client_InitClear(17);
  TT_CTX *issuer = TRUST_TOKEN_Issuer_InitClear(42);

  uint8_t *msg, *resp;
  TRUST_TOKEN **tokens;
  size_t msg_len, resp_len, tokens_len;

  ASSERT_TRUE(TRUST_TOKEN_Client_BeginIssuance(client, &msg, &msg_len, 10));
  ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformIssuance(issuer, &resp, &resp_len, msg, msg_len));
  ASSERT_TRUE(TRUST_TOKEN_Client_FinishIssuance(client, &tokens, &tokens_len, resp, resp_len));

  OPENSSL_free(msg);
  OPENSSL_free(resp);

  for (size_t i = 0; i < tokens_len; i++) {
    if (i % 3 == 0) {
      tokens[i]->data = i;
    }
    ASSERT_TRUE(TRUST_TOKEN_Client_BeginRedemption(client, &msg, &msg_len, tokens[i], nullptr, 0));
    ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformRedemption(issuer, &resp, &resp_len, msg, msg_len));
    bool result = false;
    ASSERT_TRUE(TRUST_TOKEN_Client_FinishRedemption(client, &result, resp, resp_len));
    printf("Token #%zu/%zu: %d\n", i+1, tokens_len, tokens[i]->data);
    printf("Result: %d\n", result);

    OPENSSL_free(msg);
    OPENSSL_free(resp);
    OPENSSL_free(tokens[i]);
  }

  TRUST_TOKEN_free(client);
  TRUST_TOKEN_free(issuer);
  OPENSSL_free(tokens);
}

TEST(TrustTokenTest, PrivacyPassProtocol) {
  // TT_CTX *client = TRUST_TOKEN_Client_InitPrivacyPass(ciphersuite, publicKey, batchsize);
  // TT_CTX *issuer = TRUST_TOKEN_Issuer_InitPrivacyPass(ciphersuite, privateKey, batchsize);

  TT_CTX *client = TRUST_TOKEN_Client_InitClear(17);
  TT_CTX *issuer = TRUST_TOKEN_Issuer_InitClear(42);

  uint8_t *msg, *resp;
  TRUST_TOKEN **tokens;
  size_t msg_len, resp_len, tokens_len;

  ASSERT_TRUE(TRUST_TOKEN_Client_BeginIssuance(client, &msg, &msg_len, 10));
  ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformIssuance(issuer, &resp, &resp_len, msg, msg_len));
  ASSERT_TRUE(TRUST_TOKEN_Client_FinishIssuance(client, &tokens, &tokens_len, resp, resp_len));

  OPENSSL_free(msg);
  OPENSSL_free(resp);

  for (size_t i = 0; i < tokens_len; i++) {
    if (i % 3 == 0) {
      tokens[i]->data = i;
    }
    ASSERT_TRUE(TRUST_TOKEN_Client_BeginRedemption(client, &msg, &msg_len, tokens[i], nullptr, 0));
    ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformRedemption(issuer, &resp, &resp_len, msg, msg_len));
    bool result = false;
    ASSERT_TRUE(TRUST_TOKEN_Client_FinishRedemption(client, &result, resp, resp_len));
    printf("Token #%zu/%zu: %d\n", i+1, tokens_len, tokens[i]->data);
    printf("Result: %d\n", result);

    OPENSSL_free(msg);
    OPENSSL_free(resp);
    OPENSSL_free(tokens[i]);
  }

  TRUST_TOKEN_free(client);
  TRUST_TOKEN_free(issuer);
  OPENSSL_free(tokens);
}

}  // namespace
BSSL_NAMESPACE_END
