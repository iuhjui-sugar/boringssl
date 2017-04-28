/* Copyright (c) 2017, Google Inc.
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

// cavp_sha_monte_test processes a NIST CAVP SHA-Monte test vector request file
// and emits the corresponding response. An optional sample vector file can be
// passed to verify the result.

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "../test/file_test.h"
#include "cavp_test_util.h"


static bool TestSHAMonte(FileTest *t, void *arg) {
  std::string out_len_str;
  if (!t->GetInstruction(&out_len_str, "L")) {
    return false;
  }

  size_t out_len = strtoul(out_len_str.c_str(), nullptr, 0);

  std::vector<uint8_t> seed;
  if (!t->GetBytes(&seed, "Seed") ||
      seed.size() != out_len) {
    return false;
  }

  std::vector<uint8_t> out = seed;

  printf("%s\r\n", t->CurrentTestToString().c_str());

  for (int count = 0; count < 100; count++) {
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), out.begin(), out.end());
    msg.insert(msg.end(), out.begin(), out.end());
    msg.insert(msg.end(), out.begin(), out.end());
    for (int i = 0; i < 1000; i++) {
      uint8_t *result = nullptr;
      switch (out_len) {
        case 20:
          result = SHA1(msg.data(), msg.size(), out.data());
          break;
        case 28:
          result = SHA224(msg.data(), msg.size(), out.data());
          break;
        case 32:
          result = SHA256(msg.data(), msg.size(), out.data());
          break;
        case 48:
          result = SHA384(msg.data(), msg.size(), out.data());
          break;
        case 64:
          result = SHA512(msg.data(), msg.size(), out.data());
          break;
        default:
          return false;
      }

      if (result == nullptr) {
        return false;
      }

      msg.erase(msg.begin(), msg.begin() + out.size());
      msg.insert(msg.end(), out.begin(), out.end());
    }
    printf("COUNT = %d\r\n", count);
    printf("MD = %s\r\n\r\n", EncodeHex(out.data(), out.size()).c_str());
  }

  return true;
}

static int usage(char *arg) {
  fprintf(stderr, "usage: %s <test file>\n", arg);
  return 1;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 2) {
    return usage(argv[0]);
  }

  printf("# Generated by");
  for (int i = 0; i < argc; i++) {
    printf(" %s", argv[i]);
  }
  printf("\r\n\r\n");

  return FileTestMainSilent(TestSHAMonte, nullptr, argv[1]);
}
