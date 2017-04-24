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

bool CipherOperation(const EVP_CIPHER *cipher, std::vector<uint8_t> *out,
                     bool encrypt, const std::vector<uint8_t> &key,
                     const std::vector<uint8_t> &iv,
                     const std::vector<uint8_t> &in) {
  bssl::ScopedEVP_CIPHER_CTX ctx;
  if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr,
                         encrypt ? 1 : 0)) {
    return false;
  }
  if (!iv.empty() && iv.size() != EVP_CIPHER_CTX_iv_length(ctx.get())) {
    return false;
  }

  int result_len1 = 0, result_len2;
  *out = std::vector<uint8_t>(in.size());
  if (!EVP_CIPHER_CTX_set_key_length(ctx.get(), key.size()) ||
      !EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data(),
                         -1) ||
      !EVP_CIPHER_CTX_set_padding(ctx.get(), 0) ||
      !EVP_CipherUpdate(ctx.get(), out->data(), &result_len1, in.data(),
                        in.size()) ||
      !EVP_CipherFinal_ex(ctx.get(), out->data() + result_len1, &result_len2)) {
    return false;
  }
  out->resize(result_len1 + result_len2);

  return true;
}

bool AEADEncrypt(const EVP_AEAD *aead, std::vector<uint8_t> *ct,
                 std::vector<uint8_t> *tag, size_t tag_len,
                 const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &pt,
                 const std::vector<uint8_t> &aad, std::vector<uint8_t> *iv) {
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag->size(), evp_aead_seal)) {
    return false;
  }

  std::vector<uint8_t> out;
  out.resize(pt.size() + EVP_AEAD_max_overhead(aead));
  size_t out_len;
  iv->resize(EVP_AEAD_nonce_length(aead));
  if (!EVP_AEAD_CTX_seal(ctx.get(), out.data(), &out_len, out.size(),
                         nullptr /* iv */, 0 /* iv_len */, pt.data(), pt.size(),
                         aad.data(), aad.size())) {
    return false;
  }

  static const size_t iv_len = 12;
  iv->assign(out.begin(), out.begin() + iv_len);
  ct->assign(out.begin() + iv_len, out.end() - tag_len);
  tag->assign(out.end() - tag_len, out.end());

  return true;
}

bool AEADDecrypt(const EVP_AEAD *aead, std::vector<uint8_t> *pt,
                 std::vector<uint8_t> *aad, size_t pt_len, size_t aad_len,
                 const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &ct,
                 const std::vector<uint8_t> &tag, std::vector<uint8_t> &iv) {
  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag.size(), evp_aead_open)) {
    return false;
  }
  std::vector<uint8_t> in = iv;
  in.reserve(in.size() + ct.size() + tag.size());
  in.insert(in.end(), ct.begin(), ct.end());
  in.insert(in.end(), tag.begin(), tag.end());

  pt->resize(pt_len);
  aad->resize(aad_len);
  size_t out_pt_len;
  if (!EVP_AEAD_CTX_open(ctx.get(), pt->data(), &out_pt_len, pt->size(),
                         nullptr /* iv */, 0 /* iv_len */, in.data(), in.size(),
                         aad->data(), aad->size()) ||
      out_pt_len != pt_len) {
    return false;
  }
  return true;
}
