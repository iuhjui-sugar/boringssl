/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "../test/file_test.h"
#include "../test/scoped_types.h"
#include "../test/stl_compat.h"


// In each of these tests, the value of the first attribute is the name of a key
// to use. PrivateKey tests import a key with that given name, while other tests
// look up the key with that name.

static const EVP_MD *GetDigest(const std::string &name) {
  if (name == "MD5") {
    return EVP_md5();
  } else if (name == "SHA1") {
    return EVP_sha1();
  } else if (name == "SHA224") {
    return EVP_sha224();
  } else if (name == "SHA256") {
    return EVP_sha256();
  } else if (name == "SHA384") {
    return EVP_sha384();
  } else if (name == "SHA512") {
    return EVP_sha512();
  }
  return nullptr;
}

using KeyMap = std::map<std::string, EVP_PKEY*>;

// ImportPrivateKey evaluates a PrivateKey test in |t| and writes the resulting
// private key to |key_map|.
static bool ImportPrivateKey(FileTest *t, KeyMap *key_map) {
  const std::string &key_name = t->GetValue();
  if (key_map->count(key_name) > 0) {
    t->PrintLine("Duplicate key '%s'.", key_name.c_str());
    return false;
  }
  const std::string &block = t->GetBlock();
  ScopedBIO bio(BIO_new_mem_buf(const_cast<char*>(block.data()), block.size()));
  if (!bio) {
    return false;
  }
  ScopedEVP_PKEY pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, 0, nullptr));
  if (!pkey) {
    t->PrintLine("Error reading private key.");
    return false;
  }
  (*key_map)[key_name] = pkey.release();
  return true;
}

static bool TestHMAC(FileTest *t) {
  const EVP_MD *digest = GetDigest(t->GetValue());
  if (digest == nullptr) {
    t->PrintLine("Unknown digest '%s'", t->GetValue().c_str());
    return false;
  }

  std::vector<uint8_t> key, input, output;
  if (!t->DecodeBytes(&key, t->GetAttribute("Key")) ||
      !t->DecodeBytes(&input, t->GetAttribute("Input")) ||
      !t->DecodeBytes(&output, t->GetAttribute("Output"))) {
    return false;
  }

  ScopedEVP_PKEY pkey(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                           bssl::vector_data(&key),
                                           key.size()));
  ScopedEVP_MD_CTX mctx;
  if (!pkey ||
      !EVP_DigestSignInit(mctx.get(), nullptr, digest, nullptr, pkey.get()) ||
      !EVP_DigestSignUpdate(mctx.get(), bssl::vector_data(&input),
                            input.size())) {
    return false;
  }

  size_t len;
  std::vector<uint8_t> actual;
  if (!EVP_DigestSignFinal(mctx.get(), nullptr, &len)) {
    return false;
  }
  actual.resize(len);
  if (!EVP_DigestSignFinal(mctx.get(), bssl::vector_data(&actual), &len)) {
    return false;
  }
  actual.resize(len);
  return t->ExpectBytesEqual(bssl::vector_data(&output), output.size(),
                             bssl::vector_data(&actual), actual.size());
}

static bool TestEVP(FileTest *t, void *arg) {
  KeyMap *key_map = reinterpret_cast<KeyMap*>(arg);
  if (t->GetName() == "PrivateKey") {
    return ImportPrivateKey(t, key_map);
  } else if (t->GetName() == "HMAC") {
    return TestHMAC(t);
  }

  int (*key_op_init)(EVP_PKEY_CTX *ctx);
  int (*key_op)(EVP_PKEY_CTX *ctx, uint8_t *out, size_t *out_len,
                const uint8_t *in, size_t in_len);
  if (t->GetName() == "Decrypt") {
    key_op_init = EVP_PKEY_decrypt_init;
    key_op = EVP_PKEY_decrypt;
  } else if (t->GetName() == "Sign") {
    key_op_init = EVP_PKEY_sign_init;
    key_op = EVP_PKEY_sign;
  } else if (t->GetName() == "Verify") {
    key_op_init = EVP_PKEY_verify_init;
    key_op = nullptr;  // EVP_PKEY_verify is handled differently.
  } else {
    t->PrintLine("Unknown test '%s'", t->GetName().c_str());
    return false;
  }

  // Load the key.
  const std::string &key_name = t->GetValue();
  if (key_map->count(key_name) == 0) {
    t->PrintLine("Could not find key '%s'.", key_name.c_str());
    return false;
  }
  EVP_PKEY *key = (*key_map)[key_name];

  std::vector<uint8_t> input, output;
  if (!t->DecodeBytes(&input, t->GetAttribute("Input")) ||
      !t->DecodeBytes(&output, t->GetAttribute("Output"))) {
    return false;
  }

  // Set up the EVP_PKEY_CTX.
  ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(key, nullptr));
  if (!ctx || !key_op_init(ctx.get())) {
    return false;
  }
  if (t->HasAttribute("Digest")) {
    const EVP_MD *digest = GetDigest(t->GetAttribute("Digest"));
    if (digest == nullptr) {
      t->PrintLine("Unknown digest: '%s'", t->GetAttribute("Digest").c_str());
      return false;
    }
    if (!EVP_PKEY_CTX_set_signature_md(ctx.get(), digest)) {
      return false;
    }
  }

  if (t->GetName() == "Verify") {
    if (!EVP_PKEY_verify(ctx.get(), bssl::vector_data(&output), output.size(),
                         bssl::vector_data(&input), input.size())) {
      // ECDSA sometimes doesn't push an error code. Push one on the error queue
      // so it's distinguishable from other errors.
      ERR_put_error(ERR_LIB_USER, 0, ERR_R_EVP_LIB, __FILE__, __LINE__);
      return false;
    }
    return true;
  }

  size_t len;
  std::vector<uint8_t> actual;
  if (!key_op(ctx.get(), nullptr, &len, bssl::vector_data(&input),
              input.size())) {
    return false;
  }
  actual.resize(len);
  if (!key_op(ctx.get(), bssl::vector_data(&actual), &len,
              bssl::vector_data(&input), input.size())) {
    return false;
  }
  actual.resize(len);
  if (!t->ExpectBytesEqual(bssl::vector_data(&output), output.size(),
                           bssl::vector_data(&actual), len)) {
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();
  if (argc != 2) {
    fprintf(stderr, "%s <test file.txt>\n", argv[0]);
    return 1;
  }

  KeyMap map;
  int ret = FileTestMain(&TestEVP, &map, argv[1]);
  // TODO(davidben): When we can rely on a move-aware std::map, make KeyMap a
  // map of ScopedEVP_PKEY instead.
  for (const auto &pair : map) {
    EVP_PKEY_free(pair.second);
  }
  return ret;
}
