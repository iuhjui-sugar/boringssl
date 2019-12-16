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
#include <openssl/mem.h>
#include <openssl/trust_token.h>

BSSL_NAMESPACE_BEGIN

namespace {

TEST(TrustTokenTest, ClearProtocol) {
  TT_CTX *client = TRUST_TOKEN_clear_init_client(17);
  TT_CTX *issuer = TRUST_TOKEN_clear_init_issuer(42);

  uint8_t *msg, *resp;
  size_t msg_len, resp_len;
  STACK_OF(TRUST_TOKEN) *tokens;

  ASSERT_TRUE(TRUST_TOKEN_client_begin_issuance(client, &msg, &msg_len, 10));
  ASSERT_TRUE(TRUST_TOKEN_issuer_perform_issuance(issuer, &resp, &resp_len, CBS(MakeSpan(msg, msg_len))));
  ASSERT_TRUE(TRUST_TOKEN_client_finish_issuance(client, &tokens, CBS(MakeSpan(resp, resp_len))));

  size_t i = 0;
  for (TRUST_TOKEN *token : tokens) {
    // The 2nd, 5th, etc tokens are corrupted.
    if (i % 3 == 2) {
      token->data = i;
    }
    ASSERT_TRUE(TRUST_TOKEN_client_begin_redemption(client, &msg, &msg_len, token, CBS()));
    CBS msg_cbs;
    CBS_init(&msg_cbs, msg, msg_len);
    ASSERT_TRUE(TRUST_TOKEN_issuer_perform_redemption(issuer, &resp, &resp_len, msg_cbs));
    bool result = false;
    CBS resp_cbs;
    CBS_init(&resp_cbs, resp, resp_len);
    ASSERT_TRUE(TRUST_TOKEN_client_finish_redemption(client, &result, resp_cbs));
    ASSERT_TRUE(result == (i % 3 != 2));
    printf("Token #%zu/%zu: %d\n", ++i, sk_TRUST_TOKEN_num(tokens), token->data);
    printf("Result: %d\n", result);

    OPENSSL_free(token);
  }

  TRUST_TOKEN_free(client);
  TRUST_TOKEN_free(issuer);
}

// TEST(TrustTokenTest, PrivacyPassProtocol) {
//   std::vector<uint8_t> priv_key, pub_key;
//   ASSERT_TRUE(TRUST_TOKEN_privacypass_initkey(0x4242, 0x0001, &priv_key, &pub_key));
//   printf("Key Sizes: %zu %zu\n", priv_key.size(), pub_key.size());

//   std::vector<std::vector<uint8_t>> pub_keys;
//   pub_keys.push_back(pub_key);
//   TT_CTX *pp_client = TRUST_TOKEN_PrivacyPass_InitClient(0x4242, 100, pub_keys);
//   ASSERT_TRUE(pp_client);
//   TT_CTX *client = TRUST_TOKEN_Clear_InitClient(17);
//   TT_CTX *issuer = TRUST_TOKEN_Clear_InitIssuer(42);

//   std::vector<uint8_t> msg, resp;
//   std::vector<TRUST_TOKEN*> tokens;

//   ASSERT_TRUE(TRUST_TOKEN_Client_BeginIssuance(client, &msg, 10));
//   ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformIssuance(issuer, &resp, msg));
//   ASSERT_TRUE(TRUST_TOKEN_Client_FinishIssuance(client, &tokens, resp));

//   size_t i = 0;
//   for (TRUST_TOKEN *token : tokens) {
//     ASSERT_TRUE(TRUST_TOKEN_Client_BeginRedemption(client, &msg, token, std::vector<uint8_t>()));
//     ASSERT_TRUE(TRUST_TOKEN_Issuer_PerformRedemption(issuer, &resp, msg));
//     bool result = false;
//     ASSERT_TRUE(TRUST_TOKEN_Client_FinishRedemption(client, &result, resp));
//     printf("Token #%zu/%zu: %d\n", ++i, tokens.size(), token->data);
//     printf("Result: %d\n", result);

//     OPENSSL_free(token);
//   }

//   TRUST_TOKEN_free(client);
//   TRUST_TOKEN_free(issuer);
// }

}  // namespace
BSSL_NAMESPACE_END
