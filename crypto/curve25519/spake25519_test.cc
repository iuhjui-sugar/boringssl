/* Copyright (c) 2016, Google Inc.
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

#include <openssl/curve25519.h>

#include <string>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../test/scoped_types.h"
#include "../test/test_util.h"


struct SPAKE2Run {
  bool Run() {
    ScopedSPAKE2_CTX alice(SPAKE2_CTX_new(
        spake2_role_alice,
        reinterpret_cast<const uint8_t *>(alice_names.first.data()),
        alice_names.first.size(),
        reinterpret_cast<const uint8_t *>(alice_names.second.data()),
        alice_names.second.size()));
    ScopedSPAKE2_CTX bob(SPAKE2_CTX_new(
        spake2_role_bob,
        reinterpret_cast<const uint8_t *>(bob_names.first.data()),
        bob_names.first.size(),
        reinterpret_cast<const uint8_t *>(bob_names.second.data()),
        bob_names.second.size()));

    if (!alice || !bob) {
      return false;
    }

    uint8_t alice_msg[SPAKE2_MAX_MSG_SIZE];
    uint8_t bob_msg[SPAKE2_MAX_MSG_SIZE];
    size_t alice_msg_len, bob_msg_len;

    if (!SPAKE2_generate_msg(
            alice.get(), alice_msg, &alice_msg_len, sizeof(alice_msg),
            reinterpret_cast<const uint8_t *>(alice_password.data()),
            alice_password.size()) ||
        !SPAKE2_generate_msg(
            bob.get(), bob_msg, &bob_msg_len, sizeof(bob_msg),
            reinterpret_cast<const uint8_t *>(bob_password.data()),
            bob_password.size())) {
      return false;
    }

    if (alice_corrupt_msg_bit >= 0 &&
        static_cast<size_t>(alice_corrupt_msg_bit) < 8 * alice_msg_len) {
      alice_msg[alice_corrupt_msg_bit/8] ^= 1 << (alice_corrupt_msg_bit & 7);
    }

    uint8_t alice_key[64], bob_key[64];
    size_t alice_key_len, bob_key_len;

    if (!SPAKE2_process_msg(alice.get(), alice_key, &alice_key_len,
                            sizeof(alice_key), bob_msg, bob_msg_len) ||
        !SPAKE2_process_msg(bob.get(), bob_key, &bob_key_len, sizeof(bob_key),
                            alice_msg, alice_msg_len)) {
      return false;
    }

    key_matches_ = (alice_key_len == bob_key_len &&
                    memcmp(alice_key, bob_key, alice_key_len) == 0);

    return true;
  }

  bool key_matches() const {
    return key_matches_;
  }

  std::string alice_password = "password";
  std::string bob_password = "password";
  std::pair<std::string, std::string> alice_names = {"alice", "bob"};
  std::pair<std::string, std::string> bob_names = {"bob", "alice"};
  int alice_corrupt_msg_bit = -1;

 private:
  bool key_matches_ = false;
};

static bool TestSPAKE2() {
  for (unsigned i = 0; i < 20; i++) {
    SPAKE2Run spake2;
    if (!spake2.Run()) {
      fprintf(stderr, "TestSPAKE2: SPAKE2 failed.\n");
      return false;
    }

    if (!spake2.key_matches()) {
      fprintf(stderr, "Key didn't match for equal passwords.\n");
      return false;
    }
  }

  return true;
}

static bool TestWrongPassword() {
  SPAKE2Run spake2;
  spake2.bob_password = "wrong password";
  if (!spake2.Run()) {
    fprintf(stderr, "TestSPAKE2: SPAKE2 failed.\n");
    return false;
  }

  if (spake2.key_matches()) {
    fprintf(stderr, "Key matched for unequal passwords.\n");
    return false;
  }

  return true;
}

static bool TestWrongNames() {
  SPAKE2Run spake2;
  spake2.alice_names.second = "charlie";
  spake2.bob_names.second = "charlie";
  if (!spake2.Run()) {
    fprintf(stderr, "TestSPAKE2: SPAKE2 failed.\n");
    return false;
  }

  if (spake2.key_matches()) {
    fprintf(stderr, "Key matched for unequal names.\n");
    return false;
  }

  return true;
}

static bool TestCorruptMessages() {
  for (int i = 0; i < 8 * SPAKE2_MAX_MSG_SIZE; i++) {
    SPAKE2Run spake2;
    spake2.alice_corrupt_msg_bit = i;
    if (spake2.Run() && spake2.key_matches()) {
      fprintf(stderr, "Passed after corrupting Alice's message, bit %d\n", i);
      return false;
    }
  }

  return true;
}

struct TestVector {
  const char *alice_name, *bob_name, *password;
  uint8_t alice_msg[SPAKE2_MAX_MSG_SIZE];
  uint8_t bob_msg[SPAKE2_MAX_MSG_SIZE];
  uint8_t shared_key[SPAKE2_MAX_KEY_SIZE];
};

static const TestVector kTestVectors[] = {
    {
        "",
        "",
        "",
        {0x7a, 0x44, 0x62, 0xf5, 0x6d, 0xdb, 0xd7, 0x99, 0x1c, 0x9f, 0x4b,
         0x0a, 0x09, 0xda, 0x12, 0x8a, 0xe9, 0x70, 0x3c, 0x2d, 0x23, 0x32,
         0x5e, 0x51, 0xd3, 0x94, 0x31, 0x3d, 0xbb, 0x85, 0x2a, 0xc7},
        {0xec, 0x7c, 0x96, 0x13, 0x9a, 0xee, 0x44, 0x49, 0x29, 0x12, 0xb1,
         0x9a, 0x7a, 0xee, 0xf2, 0xdc, 0xe4, 0xa8, 0x51, 0x9c, 0x97, 0x77,
         0xd8, 0xb8, 0x67, 0x60, 0x32, 0x24, 0xda, 0xc0, 0x7b, 0x2b},
        {0x01, 0x1b, 0x3e, 0x2f, 0xb4, 0x12, 0xd5, 0x12, 0xaf, 0xd0, 0x78,
         0x2f, 0x85, 0x95, 0xcb, 0xd2, 0xc5, 0x8e, 0xfb, 0xd6, 0x19, 0x06,
         0x34, 0x70, 0x1e, 0xdf, 0x0b, 0xde, 0xeb, 0x5f, 0xb8, 0x97, 0x42,
         0xd6, 0xb5, 0x1e, 0x3e, 0xc1, 0x39, 0x4f, 0x02, 0xc0, 0xb6, 0xd1,
         0xfd, 0x1c, 0xfa, 0xf3, 0x5b, 0x33, 0xe2, 0xe7, 0xa0, 0x2c, 0x5a,
         0x67, 0x53, 0x6b, 0xb3, 0xea, 0x5a, 0x91, 0x5d, 0x10},
    },
    {
        "",
        "",
        "password",
        {0x6d, 0xa0, 0xd4, 0x4c, 0x7a, 0xad, 0xb8, 0xb7, 0x98, 0x33, 0x0e,
         0xd4, 0x6e, 0xe0, 0xef, 0x13, 0x18, 0xfa, 0x2b, 0x15, 0xfe, 0x5b,
         0xa2, 0xdb, 0xca, 0x2d, 0xc5, 0x13, 0x35, 0xc8, 0x6c, 0x52},
        {0xac, 0x30, 0x77, 0x79, 0x9a, 0x9e, 0x40, 0x8f, 0x52, 0x6a, 0x7c,
         0x00, 0xfd, 0xa5, 0x7f, 0x87, 0x8c, 0x66, 0xc0, 0xc3, 0x7a, 0x0b,
         0x5b, 0x5e, 0x74, 0x53, 0x4f, 0xbb, 0x5c, 0x1f, 0x5a, 0xab},
        {0xc0, 0xce, 0xff, 0x53, 0x4e, 0xa0, 0xe8, 0x69, 0xac, 0x21, 0x9c,
         0x4b, 0x35, 0xfb, 0x55, 0xb7, 0x13, 0x6c, 0x6e, 0x73, 0x60, 0xfe,
         0xa0, 0x5b, 0xe6, 0x14, 0x00, 0x51, 0x9f, 0xe1, 0x6c, 0xd7, 0xf0,
         0x0e, 0x93, 0xbb, 0x52, 0x79, 0x93, 0xca, 0x2c, 0x3f, 0x1b, 0x70,
         0x75, 0x9c, 0x76, 0x5b, 0x43, 0x3d, 0x47, 0xea, 0x7a, 0x4d, 0xe4,
         0xfb, 0xa9, 0xb4, 0x32, 0x3f, 0x18, 0xd1, 0xd7, 0x09},
    },
    {
        "alice",
        "bob",
        "hunter2",
        {0x0a, 0xc7, 0x0a, 0x67, 0x1c, 0x20, 0x5e, 0x87, 0xb9, 0x1f, 0x18,
         0xd2, 0x40, 0xc9, 0x29, 0x16, 0x9f, 0xc1, 0xcf, 0x1f, 0x45, 0x92,
         0x75, 0xce, 0xb5, 0x47, 0x4a, 0x70, 0x93, 0x82, 0x35, 0x23},
        {0x67, 0x72, 0xe6, 0x56, 0x7e, 0xc8, 0x4e, 0x44, 0x03, 0xaa, 0x9c,
         0xab, 0xc3, 0x2e, 0x05, 0x23, 0x25, 0x1c, 0x24, 0x34, 0x52, 0xbf,
         0x79, 0x45, 0x9d, 0x4a, 0x42, 0x4c, 0xe1, 0xb0, 0x43, 0xe0},
        {0x80, 0x32, 0x43, 0x9a, 0x6d, 0xbd, 0xd3, 0x51, 0x3c, 0x40, 0xfa,
         0x03, 0x1e, 0x73, 0xea, 0x35, 0xc4, 0x85, 0x08, 0x80, 0x28, 0xdb,
         0x98, 0x31, 0xd5, 0xf0, 0x1e, 0x11, 0xc1, 0x96, 0x3c, 0x9e, 0x5b,
         0x70, 0x94, 0xac, 0x6e, 0x7f, 0x1f, 0x65, 0x59, 0x3f, 0x04, 0x18,
         0x6d, 0xc2, 0xc7, 0x3a, 0xa4, 0x85, 0xea, 0xbf, 0x6f, 0xef, 0x04,
         0x66, 0x13, 0x7b, 0xa9, 0x25, 0x37, 0x60, 0x9b, 0xf3},
    },
};

static bool TestVectors() {
  unsigned test_num = 0;
  for (const auto& test : kTestVectors) {
    test_num++;

    const uint8_t *alice_name =
        reinterpret_cast<const uint8_t *>(test.alice_name);
    const uint8_t *bob_name = reinterpret_cast<const uint8_t *>(test.bob_name);
    const uint8_t *password = reinterpret_cast<const uint8_t *>(test.password);
    const size_t alice_name_len = strlen(test.alice_name);
    const size_t bob_name_len = strlen(test.bob_name);
    const size_t password_len = strlen(test.password);

    ScopedSPAKE2_CTX alice(SPAKE2_CTX_new(
        spake2_role_alice, alice_name, alice_name_len, bob_name, bob_name_len));
    ScopedSPAKE2_CTX bob(SPAKE2_CTX_new(spake2_role_bob, bob_name, bob_name_len,
                                        alice_name, alice_name_len));

    uint8_t alice_msg[SPAKE2_MAX_MSG_SIZE];
    size_t alice_msg_len;
    if (!SPAKE2_generate_msg(alice.get(), alice_msg, &alice_msg_len,
                             sizeof(alice_msg), password, password_len)) {
      fprintf(stderr, "#%u: SPAKE2_generate_msg failed for Alice.\n", test_num);
      return false;
    }

    if (sizeof(test.alice_msg) != alice_msg_len ||
        memcmp(alice_msg, test.alice_msg, alice_msg_len) != 0) {
      fprintf(stderr, "#%u: Alice's message is incorrect.\n", test_num);
      hexdump(stderr, "Got:  ", alice_msg, alice_msg_len);
      hexdump(stderr, "Want: ", test.alice_msg, sizeof(test.alice_msg));
    }

    uint8_t bob_msg[SPAKE2_MAX_MSG_SIZE];
    size_t bob_msg_len;
    if (!SPAKE2_generate_msg(bob.get(), bob_msg, &bob_msg_len, sizeof(bob_msg),
                             password, password_len)) {
      fprintf(stderr, "#%u: SPAKE2_generate_msg failed for Bob.\n", test_num);
      return false;
    }

    if (sizeof(test.bob_msg) != bob_msg_len ||
        memcmp(bob_msg, test.bob_msg, bob_msg_len) != 0) {
      fprintf(stderr, "#%u: Bob's message is incorrect.\n", test_num);
      hexdump(stderr, "Got:  ", bob_msg, bob_msg_len);
      hexdump(stderr, "Want: ", test.bob_msg, sizeof(test.bob_msg));
    }

    uint8_t alice_key[SPAKE2_MAX_KEY_SIZE];
    size_t alice_key_len;
    if (!SPAKE2_process_msg(alice.get(), alice_key, &alice_key_len, sizeof(alice_key), bob_msg, bob_msg_len)) {
      fprintf(stderr, "#%u: SPAKE2_process_msg failed for Alice.\n", test_num);
      return false;
    }

    if (sizeof(test.shared_key) != alice_key_len ||
        memcmp(alice_key, test.shared_key, alice_key_len) != 0) {
      fprintf(stderr, "#%u: Alice's key is incorrect.\n", test_num);
      hexdump(stderr, "Got:  ", alice_key, alice_key_len);
      hexdump(stderr, "Want: ", test.shared_key, sizeof(test.shared_key));
    }

    uint8_t bob_key[SPAKE2_MAX_KEY_SIZE];
    size_t bob_key_len;
    if (!SPAKE2_process_msg(bob.get(), bob_key, &bob_key_len, sizeof(bob_key),
                            alice_msg, alice_msg_len)) {
      fprintf(stderr, "#%u: SPAKE2_process_msg failed for Bob.\n", test_num);
      return false;
    }

    if (sizeof(test.shared_key) != bob_key_len ||
        memcmp(bob_key, test.shared_key, bob_key_len) != 0) {
      fprintf(stderr, "#%u: Bob's key is incorrect.\n", test_num);
      hexdump(stderr, "Got:  ", bob_key, bob_key_len);
      hexdump(stderr, "Want: ", test.shared_key, sizeof(test.shared_key));
    }
  }

  return true;
}

int main(int argc, char **argv) {
  if (!TestSPAKE2() ||
      !TestWrongPassword() ||
      !TestWrongNames() ||
      !TestCorruptMessages() ||
      !TestVectors()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
