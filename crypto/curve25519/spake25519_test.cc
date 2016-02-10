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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/curve25519.h>

static bool TestSPAKE2() {
  uint8_t password[] = "han solo shot first";

  SPAKE2_state alice, bob;
  SPAKE2_commitment(&alice, password, sizeof(password), kSpakeRoleInitiator);
  SPAKE2_commitment(&bob, password, sizeof(password), kSpakeRoleResponder);

  uint8_t alices_key[32];
  uint8_t bobs_key[32];

  if (0 != SPAKE2_get_key(alices_key, &alice, bob.our_commitment)) {
    fprintf(stderr, "SPAKE2 test one failed (decoding bob's key).\n");
    return false;
  }
  if (0 != SPAKE2_get_key(bobs_key, &bob, alice.our_commitment)) {
    fprintf(stderr, "SPAKE2 test one failed (decoding alice's key).\n");
    return false;
  }

  if (memcmp(alices_key, bobs_key, 32) != 0) {
    fprintf(stderr, "SPAKE2 test one failed.\n");
    return false;
  }

  return true;
}

static bool TestSPAKE2FuzzPassword() {
  uint8_t password[] = "han solo shot first";
  uint8_t password_fuzz[] = "han solo shot first";
  SPAKE2_state alice, bob;

  for (unsigned i = 0; i < sizeof(password) * 8; ++i) {
    memcpy(password_fuzz, password, sizeof(password));
    password_fuzz[i/8] ^= 1 << (i & 7);

    SPAKE2_commitment(&alice, password, sizeof(password), kSpakeRoleInitiator);
    SPAKE2_commitment(&bob, password_fuzz, sizeof(password_fuzz), kSpakeRoleResponder);

    uint8_t alices_key[32];
    uint8_t bobs_key[32];

    if (0 != SPAKE2_get_key(alices_key, &alice, bob.our_commitment)) {
      fprintf(stderr, "SPAKE2 test two failed (decoding bob's key).\n");
      return false;
    }
    if (0 != SPAKE2_get_key(bobs_key, &bob, alice.our_commitment)) {
      fprintf(stderr, "SPAKE2 test two failed (decoding alice's key).\n");
      return false;
    }

    if (memcmp(alices_key, bobs_key, 32) == 0) {
      fprintf(stderr, "SPAKE2 test two failed.\n");
      return false;
    }
  }

  // Shorten password
  SPAKE2_commitment(&alice, password, sizeof(password), kSpakeRoleInitiator);
  SPAKE2_commitment(&bob, password, sizeof(password)-1, kSpakeRoleResponder);

  uint8_t alices_key[32];
  uint8_t bobs_key[32];

  if (0 != SPAKE2_get_key(alices_key, &alice, bob.our_commitment)) {
    fprintf(stderr, "SPAKE2 test two failed (decoding bob's key).\n");
    return false;
  }
  if (0 != SPAKE2_get_key(bobs_key, &bob, alice.our_commitment)) {
    fprintf(stderr, "SPAKE2 test two failed (decoding alice's key).\n");
    return false;
  }

  if (memcmp(alices_key, bobs_key, 32) == 0) {
    fprintf(stderr, "SPAKE2 test one failed.\n");
    return false;
  }

  return true;
}

static bool TestSPAKE2FuzzCommitment() {
  uint8_t password[] = "han solo shot first";
  SPAKE2_state alice, bob;

  for (unsigned i = 0; i < 8 * 32; ++i) {
    SPAKE2_commitment(&alice, password, sizeof(password), kSpakeRoleInitiator);
    SPAKE2_commitment(&bob, password, sizeof(password), kSpakeRoleResponder);

    uint8_t alices_commitment[32];
    memcpy(alices_commitment, alice.our_commitment, 32);

    uint8_t bobs_commitment[32];
    memcpy(bobs_commitment, bob.our_commitment, 32);

    // Fuzz both every third run
    // Fuzz only Alice every third run
    // Fuzz only Bob every third run
    if (i % 3 == 0 || i % 3 == 1) {
      alices_commitment[i/8] ^= 1 << (i & 7);
    }
    if (i % 3 == 0 || i % 3 == 2) {
      bobs_commitment[i/8] ^= 1 << (i & 7);
    }

    uint8_t alices_key[32];
    uint8_t bobs_key[32];

    if (0 != SPAKE2_get_key(alices_key, &alice, bobs_commitment)) {
      // Fuzzed point didn't decode, which is good
      continue;
    }
    if (0 != SPAKE2_get_key(bobs_key, &bob, alices_commitment)) {
      continue;
    }

    if (memcmp(alices_key, bobs_key, 32) == 0) {
      fprintf(stderr, "SPAKE2 test three failed (i=%d).\n", i);
      return false;
    }
  }

  return true;
}

static bool TestSPAKE2Vector() {

  uint8_t pwd[32] = {  // SHA256("secret")
    0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3,
    0x8b, 0xd3, 0x03, 0x61, 0xaa, 0x85, 0x56, 0x86,
    0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6,
    0xa2, 0x5f, 0xe9, 0x7b, 0xf5, 0x27, 0xa2, 0x5b
  };

  uint8_t initiator_private_key[32] = {
    0xae, 0x05, 0x32, 0x6e, 0x84, 0x5f, 0x96, 0x42,
    0x38, 0x9f, 0x51, 0x4e, 0xcc, 0xed, 0x1a, 0x3e,
    0x05, 0x0b, 0xa2, 0xdb, 0xc0, 0x17, 0x5f, 0xa0,
    0xc6, 0x60, 0x6c, 0xd3, 0xb1, 0xf8, 0x3d, 0x5c
  };
  /* Unused by test, but for reference
  uint8_t initiator_public_key[32] = {
    0x1a, 0xb7, 0x56, 0x3e, 0x34, 0x8a, 0xaf, 0xfd,
    0x2c, 0x3d, 0x3c, 0x02, 0x98, 0x99, 0x39, 0x3c,
    0x17, 0xa1, 0xdb, 0xd6, 0xda, 0xc7, 0x3b, 0xe3,
    0xa4, 0xbf, 0xf6, 0x5d, 0x6e, 0xae, 0xdb, 0xb0
  }; */
  uint8_t initiator_commitment[32] = {  // pw*M + initiator_public_key
    0xeb, 0xa7, 0xc1, 0xe5, 0x6c, 0x63, 0x0f, 0x28,
    0xc9, 0xa4, 0x9e, 0x02, 0x5a, 0x99, 0x1c, 0xda,
    0x46, 0x90, 0xe9, 0xdc, 0xeb, 0xfe, 0xba, 0x9e,
    0xfa, 0xa7, 0x6f, 0xc5, 0x74, 0x7a, 0x7c, 0x04
  };

  uint8_t responder_private_key[32] = {
    0xd4, 0x7c, 0x6f, 0x59, 0x1a, 0x67, 0x7b, 0xa8,
    0x0b, 0xd2, 0xf4, 0xe8, 0x84, 0xf3, 0xa7, 0xf1,
    0x5f, 0xd9, 0xb4, 0xab, 0xa3, 0x6c, 0x68, 0xdf,
    0x16, 0x15, 0x17, 0xf5, 0x94, 0xf8, 0xe9, 0x42
  };
  /* Unused by test, but for reference
  uint8_t responder_public_key[32] = {
    0x2e, 0xe8, 0x06, 0xb5, 0xcd, 0x92, 0x23, 0x76,
    0xa1, 0xac, 0x8d, 0xa8, 0xe2, 0x59, 0x7b, 0x35,
    0x98, 0xf3, 0xb8, 0xb2, 0xcb, 0xe5, 0xbd, 0x79,
    0x73, 0x92, 0x52, 0xac, 0x1d, 0x56, 0x69, 0x10
  }; */
  uint8_t responder_commitment[32] = {  // pwd*N + responder_public_key
    0x21, 0x78, 0x43, 0x59, 0xee, 0x70, 0xa6, 0x6c,
    0xf5, 0xf5, 0x16, 0x40, 0xec, 0xfb, 0xe7, 0x12,
    0x8e, 0xe0, 0x31, 0x91, 0xf3, 0xb9, 0xa9, 0xf1,
    0xd8, 0xe1, 0x19, 0x34, 0xb2, 0x2c, 0x2a, 0xcf
  };

  uint8_t shared_key[32] = {
    0x52, 0x2f, 0xaf, 0xd7, 0x26, 0x5c, 0xc3, 0xc1,
    0x7c, 0x32, 0x59, 0xd5, 0x8f, 0x31, 0x19, 0x5e,
    0xd7, 0x2d, 0x2d, 0x21, 0x4c, 0xec, 0x54, 0xf2,
    0xab, 0x36, 0x88, 0x43, 0xbf, 0xe1, 0x72, 0xc4
  };

  SPAKE2_state initiator_state;
  initiator_state.role = kSpakeRoleInitiator;
  memcpy(initiator_state.private_key, initiator_private_key, 32);
  memcpy(initiator_state.our_commitment, initiator_commitment, 32);
  memcpy(initiator_state.pwd, pwd, 32);

  uint8_t initiator_key[32];
  if (0 != SPAKE2_get_key(initiator_key, &initiator_state, responder_commitment)) {
    fprintf(stderr, "SPAKE2 test four failed (initiator decode).\n");
    return false;
  }
  if (memcmp(shared_key, initiator_key, 32) != 0) {
    fprintf(stderr, "SPAKE2 test four failed (initiator derive).\n");
    return false;
  }

  SPAKE2_state responder_state;
  responder_state.role = kSpakeRoleResponder;
  memcpy(responder_state.private_key, responder_private_key, 32);
  memcpy(responder_state.our_commitment, responder_commitment, 32);
  memcpy(responder_state.pwd, pwd, 32);

  uint8_t responder_key[32];
  if (0 != SPAKE2_get_key(responder_key, &responder_state, initiator_commitment)) {
    fprintf(stderr, "SPAKE2 test four failed (responder decode).\n");
    return false;
  }
  if (memcmp(shared_key, responder_key, 32) != 0) {
    fprintf(stderr, "SPAKE2 test four failed (responder derive).\n");
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  if (!TestSPAKE2() ||
      !TestSPAKE2FuzzPassword() ||
      !TestSPAKE2FuzzCommitment() ||
      !TestSPAKE2Vector()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
