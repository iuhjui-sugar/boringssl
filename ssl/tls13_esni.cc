// Encrypted Server name indication (ESNI).
//
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/05/.

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "../crypto/evp/internal.h"
#include "../ssl/internal.h"

BSSL_NAMESPACE_BEGIN

// PRIVATE APIs

// esni_config_parser_st decodes an ESNI config base64 string as described in
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/05/.
class esni_config_parser_st {
 public:
  // Constructor just makes copies of config and the optionally
  // specified |dummy_hostname|. No real work is done in this constructor.
  esni_config_parser_st(const std::string &base64_config,
                        const char *dummy_hostname = nullptr) {
    m_esni.base64 = base64_config;
    if (dummy_hostname != nullptr) {
      m_esni.dummy_hostname = dummy_hostname;
    }
  }

  // Decode the config passed in the ctor and stores the extracted data
  // in |out| (which is located in the SSL structure (ssl_st) for the socket.
  int parse(esni_config_st *out) {
    auto b64_config_len = m_esni.base64.size();
    auto b64_config = (const uint8_t *)m_esni.base64.c_str();
    auto config_len = (b64_config_len * 3) / 4;
    m_esni.raw_bytes.reserve(config_len);
    if (!EVP_DecodeBase64(m_esni.raw_bytes.data(), &config_len, config_len,
                          b64_config, b64_config_len)) {
      return false;
    }
    m_esni.raw = bssl::MakeSpan(m_esni.raw_bytes.data(), config_len);

    // auto raw_bytes = std::vector<uint8_t>{};
    // auto config_len2 = (b64_config_len * 3) / 4;
    // raw_bytes.reserve(config_len2);
    // if (!EVP_DecodeBase64(raw_bytes.data(), &config_len2, config_len2,
    //                       b64_config, b64_config_len)) {
    //   return false;
    // }
    // auto raw_scan = bssl::MakeSpan(raw_bytes.data(), config_len2);
    CBS_init(&m_cbs, m_esni.raw.data(), m_esni.raw.size());

    if (!check_version() || !verify_checksum() || !decode_keyshare() ||
        !decode_suites() || !get_padding_length() || !get_not_before_after() ||
        !get_extensions() || !hash_config()) {
      return false;
    }
    *out = std::move(m_esni);
    return true;
  }

 private:
  // Crypto byte bstring of the esni config to make parsing easier.
  CBS m_cbs;

  // Parsed ESNI config data, eventually stored in ssl_st.esni.config.
  esni_config_st m_esni;

  // Checks that the ESNI config was a known version. Draft 05 has
  // only one supported version, 0xff01.
  int check_version() {
    constexpr uint16_t ESNI_CONFIG_VERSION_1 = 0xff01;
    auto config = &m_esni.config;
    if (!CBS_get_u16(&m_cbs, &config->version) ||
        (config->version != ESNI_CONFIG_VERSION_1)) {
      return false;
    }
    return true;
  }

  // Verify that the checksum is correct. In draft 05, the checksum is actually
  // what was stored in  ESNIConfig.public_name.
  int verify_checksum() {
    auto config = &m_esni.config;
    if (!CBS_copy_bytes(&m_cbs, config->checksum, sizeof(config->checksum))) {
      return false;
    }

    // Calculate the checksum of the esni config * with the checksum zeroed *.
    constexpr size_t CHECKSUM_COMPARE_LEN = sizeof(config->checksum);
    constexpr auto MAX_ESNI_DIGEST_LEN = 32;
    uint8_t digest[MAX_ESNI_DIGEST_LEN];
    unsigned int digest_len = sizeof(digest);
    memset((void *)(m_esni.raw.data() + 2), 0, CHECKSUM_COMPARE_LEN);
    auto ctx = EVP_MD_CTX_new();
    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, m_esni.raw.data(), m_esni.raw.size()) ||
        !EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
      return false;
    }

    // Verify that the first 4 bytes of the checksum match.
    if (memcmp(&config->checksum, digest, sizeof(config->checksum)) != 0) {
      return false;
    }

    // Restore the original checksum.
    auto ptr = (void *)(m_esni.raw.data() + 2);
    memcpy(ptr, config->checksum, sizeof(config->checksum));
    return true;
  }

  // Decode the key share to extract the group id and the public key itself.
  int decode_keyshare() {
    uint16_t len;
    auto ptr = (uint8_t *)CBS_data(&m_cbs);
    if (!CBS_get_u16(&m_cbs, &len) || (len <= sizeof(uint16_t)) ||
        !CBS_get_u16(&m_cbs, &m_esni.config.group_id)) {
      return false;
    }
    m_esni.config.keyshare = bssl::MakeSpan<uint8_t>(ptr, len + 2);
    if (!CBS_skip(&m_cbs, len - sizeof(uint16_t))) {
      return false;
    }
    return true;
  }

  // Decode the suites. Note - currently, it is illegal to send anything other
  // than just once suite anyway. But in case this is extended, this method will
  // handle that case.
  int decode_suites() {
    uint16_t len;
    auto ptr = (uint8_t *)CBS_data(&m_cbs);
    if (!CBS_get_u16(&m_cbs, &len) ||
        !CBS_get_u16(&m_cbs, &m_esni.config.suite_id)) {
      return false;
    }
    m_esni.config.suite = bssl::MakeSpan<uint8_t>(ptr, len);
    return true;
  }

  // Retrieve the padding requirement for the SNI prior to encrypted. OpenSSL
  // has a default of 260 whereas we retrieve the padding length from config.
  int get_padding_length() {
    constexpr uint16_t MAX_ESNI_PADDING_LENGTH = 260;
    auto config = &m_esni.config;
    if (!CBS_get_u16(&m_cbs, &config->padding_len) ||
        (config->padding_len > MAX_ESNI_PADDING_LENGTH)) {
      return false;
    }
    return true;
  }

  // Retrieve the time periods when this config is valid.
  int get_not_before_after() {
    auto config = &m_esni.config;
    if (!CBS_get_u64(&m_cbs, &config->not_before) ||
        !CBS_get_u64(&m_cbs, &config->not_after)) {
      return false;
    }
    return true;
  }

  // Get the extension count. BUGBUGBUG - Don't bother with additional
  // extensions for now.
  int get_extensions() {
    auto config = &m_esni.config;
    auto ptr = (uint8_t *)CBS_data(&m_cbs);
    if (!CBS_get_u16(&m_cbs, &config->ext_len)) {
      return false;
    }
    m_esni.config.ext = bssl::MakeSpan<uint8_t>(ptr, config->ext_len);
    return true;
  }

  // Get the SHA256 hash of the ESNIConfig buffer, this is needed to build the
  // ESNIContents buffer later.
  int hash_config() {
    auto ctx = bssl::MakeUnique<EVP_MD_CTX>();
    if (!ctx.get()) {
      return false;
    }
    auto digest = EVP_sha256();
    if (!digest) {
      return false;
    }
    auto config = &m_esni.config;
    if (!EVP_DigestInit(ctx.get(), digest) ||
        !EVP_DigestUpdate(ctx.get(), m_esni.raw.data(), m_esni.raw.size()) ||
        !EVP_DigestFinal(ctx.get(), config->hash, &config->hash_len)) {
      return false;
    }
    return true;
  }
};

// esni_clienthell_builder_st constructs ClientEncryptedSNI
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/05/.
class esni_clienthello_extension_writer_st {
 public:
  esni_clienthello_extension_writer_st(SSL_HANDSHAKE *hs)
      : m_hs(hs), m_ssl(hs->ssl) {}

  // Builds an encrypted_server_name structure and appends it to |out|. Callers
  // must have enabled ESNI via a call to SSL_set_tlsext_esni_config.
  int build(CBB *out) {
    if (!m_ssl->esni.enabled || !build_ClientESNIInner() ||
        !build_ClientEncryptedSNI()) {
      return false;
    }
    CBB esni;
    if (!CBB_add_u16(out, 0xffce) || !CBB_add_u16_length_prefixed(out, &esni) ||
        !CBB_add_bytes(&esni, CBB_data(&m_ClientEncryptedSNI),
                       CBB_len(&m_ClientEncryptedSNI)) ||
        !CBB_flush(out)) {
      return false;
    }
    return true;
  }

 private:
  SSL_HANDSHAKE *m_hs;
  SSL *m_ssl;
  CBB m_ClientESNIInner;
  CBB m_ClientESNIInnerEncrypted;
  CBB m_ClientEncryptedSNI;

  // Build's an inner inner SNI from m_ssl->hostname.
  int build_ClientESNIInner() {
    // There is the struct we are building.
    // struct ClientESNIInner {
    //   uint8_t nonce[16];               (Server hello should contain this)
    //
    //   struct PaddedServerNameList {    (The hostname, only 1 allowed in list)
    //     struct ServerNameList {
    //       struct ServerName {
    //         uint8_t type;              (TLS SNI name type, always 0)
    //         uint16_t length;           (Hostname length)
    //         uint8_t hostname[length];  (Non null terminated hostname bytes)
    //       } ServerName;
    //     } ServerNameList[1];
    //
    //     uint8_t zeroes[];              (ESNI padding, paddding_len - sni_len)
    //   } PaddedServerNameList;
    // } ClientESNIInner;

    // 1. Generate Nonce
    if (RAND_bytes(m_ssl->esni.nonce, sizeof(m_ssl->esni.nonce)) != 1) {
      return false;
    }

    if (!CBB_init(&m_ClientESNIInner, 0) ||
        !CBB_add_bytes(&m_ClientESNIInner, m_ssl->esni.nonce,
                       sizeof(m_ssl->esni.nonce)) ||
        !CBB_flush(&m_ClientESNIInner)) {
      return false;
    }
    auto sni_start = CBB_len(&m_ClientESNIInner);

    // 2. Build ServerNameList
    auto hostname_bytes = (const uint8_t *)m_ssl->hostname.get();
    auto hostname_len = strlen(m_ssl->hostname.get());
    if (!CBB_add_u16(&m_ClientESNIInner, hostname_len + 3) ||
        !CBB_add_u8(&m_ClientESNIInner, 0) ||
        !CBB_add_u16(&m_ClientESNIInner, hostname_len) ||
        !CBB_add_bytes(&m_ClientESNIInner, hostname_bytes, hostname_len)) {
      return false;
    }
    auto sni_end = CBB_len(&m_ClientESNIInner);

    // 3. Add Padding
    auto padding_len = m_ssl->esni.config.padding_len - (sni_end - sni_start);
    auto padding = std::vector<uint8_t>(padding_len);
    memset(padding.data(), 0, padding.capacity());
    if (!CBB_add_bytes(&m_ClientESNIInner, padding.data(), padding_len) ||
        !CBB_flush(&m_ClientESNIInner)) {
      return false;
    }

    return true;
  }

  // Initializes |m_ssl->esni.crypto|. The cipher we need is specified by the
  // suite id passed to us in the peer's ßESNIConfig.
  int init_crypto() {
    auto crypto = &m_ssl->esni.crypto;
    crypto->cipher = SSL_get_cipher_by_value(m_ssl->esni.config.suite_id);
    if (!crypto->cipher) {
      return false;
    }
    size_t mac_len = 0;
    size_t iv_len = 0;
    if (!ssl_cipher_get_evp_aead(&crypto->aead, &mac_len, &iv_len,
                                 crypto->cipher, TLS1_3_VERSION,
                                 SSL_is_dtls(m_ssl))) {
      return false;
    }
    crypto->group_id = SSL_CIPHER_get_prf_nid(crypto->cipher);
    if (!crypto->group_id) {
      return false;
    }
    crypto->digest = EVP_get_digestbynid(crypto->group_id);
    if (!crypto->digest) {
      return false;
    }
    return true;
  }

  // Initializes |m_ssl->esni.keyshare| by creating a new ephemeral ECDH keypair
  // and generating a key context for it.
  int init_keys(const bssl::Span<uint8_t> &key, const bssl::Span<uint8_t> &iv) {
    // 0. Initialize anything we expect exists.
    if (!init_crypto()) {
      return false;
    }

    // 1. Build the ephemeral ESNI keypair and keyshare.
    auto config = &m_ssl->esni.config;
    m_ssl->esni.keyshare = SSLKeyShare::Create(config->group_id);
    Array<uint8_t> Z;
    uint8_t alert{0};
    CBB public_key;
    CBB_init(&public_key, 0);
    auto peer_keyshare = bssl::MakeSpan(config->keyshare.data() + 6,
                                        config->keyshare.size() - 6);
    if (!m_ssl->esni.keyshare->Accept(&public_key, &Z, &alert, peer_keyshare)) {
      return false;
    }
    m_ssl->esni.public_key_bytes.reserve(CBB_len(&public_key));
    memcpy((void *)m_ssl->esni.public_key_bytes.data(), CBB_data(&public_key),
           CBB_len(&public_key));
    m_ssl->esni.public_key_bytes.reserve(CBB_len(&public_key));
    m_ssl->esni.public_key = bssl::MakeSpan<uint8_t>(
        (uint8_t *)CBB_data(&public_key), CBB_len(&public_key));

    // 2. Build out ESNIContents and calculate the hash of the structure.
    //  struct {
    //    struct record_digest {
    //      uint16_t length;
    //      uint8_t hash[length];
    //    };
    //    struct KeyShareEntry {
    //      uint16_t group;
    //      uint64_t length;
    //      uint8_t keyshare[length];
    //    };
    //    uint8_t client_hello_random[32];
    //  } ESNIContents;
    uint8_t esni_contents_hash[32]{0};
    auto esni_contents_hash_len = (unsigned int)sizeof(esni_contents_hash);
    CBB esni_contents, keyshare, config_hash;
    if (!CBB_init(&esni_contents, 0) ||
        !CBB_add_u16_length_prefixed(&esni_contents, &config_hash) ||
        !CBB_add_bytes(&config_hash, config->hash, config->hash_len) ||
        !CBB_add_u16(&esni_contents, config->group_id) ||
        !CBB_add_u16_length_prefixed(&esni_contents, &keyshare) ||
        !CBB_add_bytes(&keyshare, m_ssl->esni.public_key.data(),
                       m_ssl->esni.public_key.size()) ||
        !CBB_add_bytes(&esni_contents, m_ssl->s3->client_random,
                       sizeof(m_ssl->s3->client_random))) {
      return false;
    }
    auto hash_ctx = EVP_MD_CTX_new();
    if (!hash_ctx) {
      return false;
    }
    auto success{EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL) &&
                 EVP_DigestUpdate(hash_ctx, CBB_data(&esni_contents),
                                  CBB_len(&esni_contents)) &&
                 EVP_DigestFinal_ex(hash_ctx, esni_contents_hash,
                                    &esni_contents_hash_len)};
    EVP_MD_CTX_free(hash_ctx);
    if (!success) {
      return false;
    }

    // 3. Compute the symmetric key we encrypt the inner SNI encryption:
    //  a. Extract the ECDH shared secret from the peer's ESNIConfig.KeyShare
    //      Zx = HKDF-Extract(0, Z) - the 0 means no salt.
    //  b. key = HKDF-Expand-Label(Zx, KeyLabel, Hash(ESNIContents), key_length)
    //      KeyLabel is "esni key" for the first and "hrr esni key" for any
    //      subsequent client hello messages
    //  c. iv = HKDF-Expand-Label(Zx, IvLabel, Hash(ESNIContents), iv_length)
    //      IvLabel is "esni iv" for the first and "hrr esni iv" for any
    //      subsequent client hello messages.
    auto HKDF_expand_label =
        [](uint8_t *out_key, size_t out_len, const EVP_MD *digest,
           const uint8_t *prk, size_t prk_len, const uint8_t *info,
           size_t info_len, const uint8_t *label, size_t label_len) -> int {
      const static uint8_t *label_prefix = (uint8_t *)"tls13 ";
      auto label_prefix_len = strlen((const char *)label_prefix);
      CBB cbb, cbb_label, cbb_info;
      if (!CBB_init(&cbb, 0) || !CBB_add_u16(&cbb, out_len) ||
          !CBB_add_u8_length_prefixed(&cbb, &cbb_label) ||
          !CBB_add_bytes(&cbb_label, label_prefix, label_prefix_len) ||
          !CBB_add_bytes(&cbb_label, label, label_len) ||
          !CBB_add_u8_length_prefixed(&cbb, &cbb_info) ||
          !CBB_add_bytes(&cbb_info, info, info_len) || !CBB_flush(&cbb) ||
          !HKDF_expand(out_key, out_len, digest, prk, prk_len, CBB_data(&cbb),
                       CBB_len(&cbb))) {
        return false;
      }
      return true;
    };
    uint8_t Zx[32]{0};
    auto Zx_len = sizeof(Zx);
    auto digest = m_ssl->esni.crypto.digest;
    auto key_label = (const uint8_t *)"esni key";
    auto key_label_len = strlen((const char *)key_label);
    auto iv_label = (const uint8_t *)"esni iv";
    auto iv_label_len = strlen((const char *)iv_label);
    if (!HKDF_extract(Zx, &Zx_len, digest, Z.data(), Z.size(), nullptr, 0) ||
        !HKDF_expand_label(key.data(), key.size(), digest, Zx, Zx_len,
                           esni_contents_hash, sizeof(esni_contents_hash),
                           key_label, key_label_len) ||
        !HKDF_expand_label(iv.data(), iv.size(), digest, Zx, Zx_len,
                           esni_contents_hash, sizeof(esni_contents_hash),
                           iv_label, iv_label_len)) {
      return false;
    }

    // If we got to here then we succeeded.
    return true;
  }

  // Initializes crypto if necessary, derives encryption keys from our own
  // ephemeral key pair and the peer's keyshare from ESNIConfig.
  int encrypt_ClientESNIInner() {
    uint8_t key[0x10]{0};
    uint8_t iv[0xc]{0};
    if (!init_keys(MakeSpan<uint8_t>(key, sizeof(key)),
                   MakeSpan<uint8_t>(iv, sizeof(iv)))) {
      return false;
    }

    // Build up the additional data. We use 0 as the 8 byte sequence number and
    // add the client hello keyshare to the buffer so we end up with:
    // struct ESNIAdditionalData {
    //   uint64_t sequence_number; <-- NOTE - Not required with BoringSSL.
    //   struct KeyShareEntry {
    //     uint16_t length;
    //     uint16_t group;
    //     uint16_t keyshare_length;
    //     uint8_t keyshare[keyshare_length];
    //   };
    // };
    CBB ad_cbb, keyshare_cbb;
    if (!CBB_init(&ad_cbb, 0) ||
        !CBB_add_u16_length_prefixed(&ad_cbb, &keyshare_cbb) ||
        !CBB_add_bytes(&keyshare_cbb, m_hs->key_share_bytes.data(),
                       m_hs->key_share_bytes.size()) ||
        !CBB_flush(&ad_cbb)) {
      return false;
    }

    // Encrypt the output buffer. Reserve an area on the stack that is big
    // pretty much double the max SNI size. In reality, all we need is the size
    // of the buffer plus the size of the signature (typically 32 bytes) but
    // this is safer for now.
    uint8_t outbuf[0x200]{0};
    auto outbuf_len = sizeof(outbuf);
    EVP_AEAD_CTX ctx;
    if (!EVP_AEAD_CTX_init(&ctx, m_ssl->esni.crypto.aead, key, sizeof(key),
                           EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr) ||
        !EVP_AEAD_CTX_seal(&ctx, outbuf, &outbuf_len, outbuf_len, iv,
                           EVP_AEAD_nonce_length(m_ssl->esni.crypto.aead),
                           CBB_data(&m_ClientESNIInner),
                           CBB_len(&m_ClientESNIInner), CBB_data(&ad_cbb),
                           CBB_len(&ad_cbb))) {
      return false;
    }
    if (!CBB_init(&m_ClientESNIInnerEncrypted, 0) ||
        !CBB_add_bytes(&m_ClientESNIInnerEncrypted, outbuf, outbuf_len)) {
      return false;
    }
    return true;
  };

  // Build's the full encrypted ESNI extension text.
  int build_ClientEncryptedSNI() {
    // struct ClientEncryptedSNI {
    //   uint16_t suite;
    //   struct KeyShareEntry {
    //     uint16_t group;
    //     uint16_t length;
    //     uint8_t keyshare[length];
    //   };
    //   struct CountedHash {
    //     uint16_t length;
    //     uint8_t hash[length];
    //   };
    //   struct EncryptedClientESNIInner {
    //     uint16_t length;
    //     uint8_t encrypted[length];
    //   };
    // };
    CBB tmp;
    if (CBB_len(&m_ClientESNIInner) == 0) {
      return false;
    }
    if (!encrypt_ClientESNIInner()) {
      return false;
    }
    if (!CBB_init(&m_ClientEncryptedSNI, 0) ||
        !CBB_add_u16(&m_ClientEncryptedSNI, m_ssl->esni.config.suite_id)) {
      return false;
    }
    if (!CBB_add_u16(&m_ClientEncryptedSNI, m_ssl->esni.config.group_id) ||
        !CBB_add_u16_length_prefixed(&m_ClientEncryptedSNI, &tmp) ||
        !CBB_add_bytes(&tmp, m_ssl->esni.public_key.data(),
                       m_ssl->esni.public_key.size()) ||
        !CBB_flush(&m_ClientEncryptedSNI)) {
      return false;
    }
    if (!CBB_init(&tmp, 0) ||
        !CBB_add_u16_length_prefixed(&m_ClientEncryptedSNI, &tmp) ||
        !CBB_add_bytes(&tmp, m_ssl->esni.config.hash,
                       m_ssl->esni.config.hash_len) ||
        !CBB_flush(&m_ClientEncryptedSNI)) {
      return false;
    }
    if (!CBB_init(&tmp, 0) ||
        !CBB_add_u16_length_prefixed(&m_ClientEncryptedSNI, &tmp) ||
        !CBB_add_bytes(&tmp, CBB_data(&m_ClientESNIInnerEncrypted),
                       CBB_len(&m_ClientESNIInnerEncrypted)) ||
        !CBB_flush(&m_ClientEncryptedSNI)) {
      return false;
    }

    // If we got to here, we succeeded.
    return true;
  }
};

// PUBLIC APIs

int ssl_esni_enable(SSL *ssl, const char *esni_config,
                    const char *dummy_hostname) {
  // Decode the config and store the buffer in the ssl struct so we
  // can use it in the TLS extension handlers.
  esni_config_parser_st config_parser(esni_config, dummy_hostname);
  if (!config_parser.parse(&ssl->esni)) {
    return false;
  }

  // Set ESNI to enabled so that we can:
  //  1. Decide to add 'server_name' TLS extension.
  //    a. If server_name is null we do not supply
  //  2. Decide to add 'server_name' TLS extension if the caller supplied a
  //  dummy hostname.
  //    a. Generate key materials from our the esni config and own
  //       ephemeral key pair. Note, this should be done during the
  //       connect phase of the handshake, we do this in the
  //       ssl_esni_add_clienthello API.
  //    b. Build and encrypt the real 'server_name' structure.
  //    c. Build and add a 'encrypted_server_name' TLS extension that contains
  //    the above encrypted real SNI.
  ssl->esni.enabled = true;
  return true;
}

int ssl_esni_add_clienthello(SSL_HANDSHAKE *hs, CBB *out) {
  // Bail if the caller did enabled ESNI with SSL_EnableESNI.
  if ((hs->ssl->hostname == nullptr) || (hs->ssl->esni.enabled == false)) {
    return true;
  }

  // Build up the ESNI exension.
  esni_clienthello_extension_writer_st esni_writer(hs);
  if (!esni_writer.build(out)) {
    return false;
  }

  return true;
}

BSSL_NAMESPACE_END
