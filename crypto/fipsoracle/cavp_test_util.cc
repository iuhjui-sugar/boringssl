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

#include "cavp_test_util.h"

std::string EncodeHex(const uint8_t *in, size_t in_len) {
  static const char kHexDigits[] = "0123456789abcdef";
  std::string ret;
  ret.reserve(in_len * 2);
  for (size_t i = 0; i < in_len; i++) {
    ret += kHexDigits[in[i] >> 4];
    ret += kHexDigits[in[i] & 0xf];
  }
  return ret;
}

const EVP_CIPHER *GetCipher(const std::string &name) {
  if (name == "DES-CBC") {
    return EVP_des_cbc();
  } else if (name == "DES-ECB") {
    return EVP_des_ecb();
  } else if (name == "DES-EDE") {
    return EVP_des_ede();
  } else if (name == "DES-EDE3") {
    return EVP_des_ede3();
  } else if (name == "DES-EDE-CBC") {
    return EVP_des_ede_cbc();
  } else if (name == "DES-EDE3-CBC") {
    return EVP_des_ede3_cbc();
  } else if (name == "RC4") {
    return EVP_rc4();
  } else if (name == "AES-128-ECB") {
    return EVP_aes_128_ecb();
  } else if (name == "AES-256-ECB") {
    return EVP_aes_256_ecb();
  } else if (name == "AES-128-CBC") {
    return EVP_aes_128_cbc();
  } else if (name == "AES-128-GCM") {
    return EVP_aes_128_gcm();
  } else if (name == "AES-128-OFB") {
    return EVP_aes_128_ofb();
  } else if (name == "AES-192-CBC") {
    return EVP_aes_192_cbc();
  } else if (name == "AES-192-CTR") {
    return EVP_aes_192_ctr();
  } else if (name == "AES-192-ECB") {
    return EVP_aes_192_ecb();
  } else if (name == "AES-256-CBC") {
    return EVP_aes_256_cbc();
  } else if (name == "AES-128-CTR") {
    return EVP_aes_128_ctr();
  } else if (name == "AES-256-CTR") {
    return EVP_aes_256_ctr();
  } else if (name == "AES-256-GCM") {
    return EVP_aes_256_gcm();
  } else if (name == "AES-256-OFB") {
    return EVP_aes_256_ofb();
  }
  return nullptr;
}

bool CipherOperation(const EVP_CIPHER *cipher, bool encrypt,
                     const std::vector<uint8_t> &key,
                     const std::vector<uint8_t> &iv,
                     const std::vector<uint8_t> &in,
                     const std::vector<uint8_t> &aad,
                     const std::vector<uint8_t> &tag, std::vector<uint8_t> *out,
                     uint8_t *out_tag[16]) {
  bool is_aead = EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE;

  bssl::ScopedEVP_CIPHER_CTX ctx;
  if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr,
                         encrypt ? 1 : 0)) {
    return false;
  }
  if (!iv.empty()) {
    if (is_aead) {
      if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(),
                               0)) {
        return false;
      }
    } else if (iv.size() != EVP_CIPHER_CTX_iv_length(ctx.get())) {
      return false;
    }
  }
  if (is_aead && !encrypt &&
      !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                           const_cast<uint8_t *>(tag.data()))) {
    return false;
  }

  // Note: the deprecated |EVP_CIPHER|-based AES-GCM API is sensitive to whether
  // parameters are NULL, so it is important to skip the |in| and |aad|
  // |EVP_CipherUpdate| calls when empty.
  int unused, result_len1 = 0, result_len2;
  if (!EVP_CIPHER_CTX_set_key_length(ctx.get(), key.size()) ||
      !EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data(),
                         -1) ||
      (!aad.empty() && !EVP_CipherUpdate(ctx.get(), nullptr, &unused,
                                         aad.data(), aad.size())) ||
      !EVP_CIPHER_CTX_set_padding(ctx.get(), 0)) {
    return false;
  }

  *out = std::vector<uint8_t>(in.size());

  if ((!in.empty() && !EVP_CipherUpdate(ctx.get(), out->data(), &result_len1,
                                        in.data(), in.size())) ||
      !EVP_CipherFinal_ex(ctx.get(), out->data() + result_len1, &result_len2)) {
    return false;
  }
  out->resize(result_len1 + result_len2);

  if (encrypt && is_aead) {
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(),
                             out_tag)) {
      return false;
    }
  }
  return true;
}

#
