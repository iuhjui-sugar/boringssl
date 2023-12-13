/* Copyright (c) 2023, Google Inc.
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

#include <openssl/pki/verify.h>

#include <assert.h>

#include <chrono>
#include <optional>
#include <string_view>

#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/pool.h>

#include <openssl/pki/signature_verify_cache.h>

#include "cert_errors.h"
#include "cert_issuer_source_static.h"
#include "certificate_policies.h"
#include "common_cert_errors.h"
#include "encode_values.h"
#include "input.h"
#include "parse_certificate.h"
#include "parse_values.h"
#include "parsed_certificate.h"
#include "path_builder.h"
#include "simple_path_builder_delegate.h"
#include "trust_store.h"
#include "trust_store_in_memory.h"
#include "verify_certificate_chain.h"

namespace bssl {

namespace {

std::optional<std::shared_ptr<const ParsedCertificate>>
InternalParseCertificate(std::string_view cert, std::string *out_diagnostic) {
  ParseCertificateOptions default_options{};
  // We follow Chromium in setting |allow_invalid_serial_numbers| in order to
  // not choke on 21-byte serial numbers, which are common.  davidben explains
  // why:
  //
  // The reason for the discrepancy is that unsigned numbers with the high bit
  // otherwise set get an extra 0 byte in front to keep them positive. So if you
  // do:
  //    var num [20]byte
  //    fillWithRandom(num[:])
  //    serialNumber := new(big.Int).SetBytes(num[:])
  //    encodeASN1Integer(serialNumber)
  //
  // Then half of your serial numbers will be encoded with 21 bytes. (And
  // 1/512th will have 19 bytes instead of 20.)
  default_options.allow_invalid_serial_numbers = true;

  bssl::UniquePtr<CRYPTO_BUFFER> buffer(CRYPTO_BUFFER_new(
      reinterpret_cast<const uint8_t *>(cert.data()), cert.size(), nullptr));
  bssl::CertErrors errors;
  std::shared_ptr<const bssl::ParsedCertificate> parsed_cert(
      ParsedCertificate::Create(std::move(buffer), default_options, &errors));
  if (!parsed_cert) {
    *out_diagnostic = errors.ToDebugString();
    return {};
  }
  return parsed_cert;
}
}  // namespace


class CertErrors;

CertPool::CertPool() {}

Opts::Opts() {}

static std::unique_ptr<VerifyTrustStore> WrapTrustStore(
    std::unique_ptr<TrustStoreInMemory> trust_store) {
  std::unique_ptr<VerifyTrustStore> ret(new VerifyTrustStore);
  ret->trust_store = std::move(trust_store);
  return ret;
}

VerifyTrustStore::~VerifyTrustStore() {}

std::optional<std::unique_ptr<VerifyTrustStore>> VerifyTrustStore::FromDER(
    std::string_view der_certs, std::string *out_diagnostic) {
  std::unique_ptr<TrustStoreInMemory> trust_store(new TrustStoreInMemory);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t *>(der_certs.data()),
           der_certs.size());

  for (size_t cert_num = 1; CBS_len(&cbs) != 0; cert_num++) {
    CBS cert;
    if (!CBS_get_asn1_element(&cbs, &cert, CBS_ASN1_SEQUENCE)) {
      *out_diagnostic = "failed to get ASN.1 SEQUENCE from input at cert " +
                        std::to_string(cert_num);
      return {};
    }

    auto parsed_cert = bssl::InternalParseCertificate(
        std::string_view(reinterpret_cast<const char *>(CBS_data(&cert)),
                         CBS_len(&cert)),
        out_diagnostic);
    if (!parsed_cert.has_value()) {
      return {};
    }
    trust_store->AddTrustAnchor(parsed_cert.value());
  }

  return WrapTrustStore(std::move(trust_store));
}

std::optional<std::unique_ptr<VerifyTrustStore>> VerifyTrustStore::FromDER(
    const std::vector<std::string_view> &der_roots,
    std::string *out_diagnostic) {
  std::unique_ptr<TrustStoreInMemory> trust_store(new TrustStoreInMemory);

  for (const std::string_view &cert : der_roots) {
    auto parsed_cert = bssl::InternalParseCertificate(cert, out_diagnostic);
    if (!parsed_cert.has_value()) {
      return {};
    }
    trust_store->AddTrustAnchor(parsed_cert.value());
  }

  return WrapTrustStore(std::move(trust_store));
}

CertPool::~CertPool() {}

std::optional<std::unique_ptr<CertPool>> NewCertPoolFromCerts(
    const std::vector<std::string_view> &der_certs,
    std::string *out_diagnostic) {
  std::unique_ptr<CertPool> pool(new CertPool);
  pool->impl_ = std::make_unique<CertIssuerSourceStatic>();

  for (const std::string_view &cert : der_certs) {
    auto parsed_cert = bssl::InternalParseCertificate(cert, out_diagnostic);
    if (!parsed_cert.has_value()) {
      return {};
    }
    pool->impl_->AddCert(std::move(parsed_cert.value()));
  }

  return std::move(pool);
}

VerifyStatus::VerifyStatus() {}

size_t VerifyStatus::IterationCount() const { return iteration_count_; }

size_t VerifyStatus::MaxDepthSeen() const { return max_depth_seen_; }

// PathBuilderDelegateImpl implements a deadline and allows for the
// use of a SignatureVerifyCache if an implementation is provided.
class PathBuilderDelegateImpl : public SimplePathBuilderDelegate {
 public:
  PathBuilderDelegateImpl(
      size_t min_rsa_modulus_length_bits, DigestPolicy digest_policy,
      std::chrono::time_point<std::chrono::steady_clock> deadline,
      SignatureVerifyCache *cache)
      : SimplePathBuilderDelegate(min_rsa_modulus_length_bits, digest_policy),
        deadline_(deadline),
        cache_(cache) {}

  bool IsDeadlineExpired() override {
    return (std::chrono::steady_clock::now() > deadline_);
  }

  SignatureVerifyCache *GetVerifyCache() override { return cache_; }

 private:
  const std::chrono::time_point<std::chrono::steady_clock> deadline_;
  SignatureVerifyCache *cache_;
};

std::optional<std::vector<std::vector<std::string>>> VerifyInternal(
    const Opts &opts, VerifyError *out_error, VerifyStatus *out_status,
    bool all_paths) {
  VerifyError dummy;
  if (!out_error) {
    out_error = &dummy;
  }
  if (out_status != nullptr) {
    out_status->iteration_count_ = 0;
    out_status->max_depth_seen_ = 0;
  }

  std::string diagnostic;
  std::optional<std::shared_ptr<const ParsedCertificate>> maybe_leaf =
      bssl::InternalParseCertificate(opts.leaf_cert, &diagnostic);

  if (!maybe_leaf.has_value()) {
    *out_error = {VerifyError::StatusCode::CERTIFICATE_INVALID, 0, diagnostic};
    return {};
  }
  std::shared_ptr<const ParsedCertificate> leaf_cert = maybe_leaf.value();

  int64_t now;
  if (opts.time.has_value()) {
    now = opts.time.value();
  } else {
    now = time(NULL);
  }

  bssl::der::GeneralizedTime verification_time;
  if (!bssl::der::EncodePosixTimeAsGeneralizedTime(now, &verification_time)) {
    *out_error = {VerifyError::StatusCode::VERIFICATION_FAILURE, -1,
                  "\nCould not encode verification time\n"};
    return {};
  }

  bssl::TrustStore *trust_store = nullptr;
  if (opts.trust_store) {
    trust_store = opts.trust_store->trust_store.get();
  }

  auto digest_policy = SimplePathBuilderDelegate::DigestPolicy::kStrong;
  // TODO(b/111551631): remove this
  if (opts.insecurely_allow_sha1) {
    digest_policy = SimplePathBuilderDelegate::DigestPolicy::kWeakAllowSha1;
  }

  std::chrono::time_point<std::chrono::steady_clock> deadline =
      std::chrono::time_point<std::chrono::steady_clock>::max();
  if (opts.deadline.has_value()) {
    deadline = opts.deadline.value();
  }

  PathBuilderDelegateImpl path_builder_delegate(
      opts.min_rsa_modulus_length, digest_policy, deadline,
      opts.signature_verify_cache);

  bssl::KeyPurpose key_purpose = bssl::KeyPurpose::SERVER_AUTH;
  switch (opts.key_purpose) {
    case Opts::KeyPurpose::ANY_EKU:
      key_purpose = bssl::KeyPurpose::ANY_EKU;
      break;
    case Opts::KeyPurpose::SERVER_AUTH:
      key_purpose = bssl::KeyPurpose::SERVER_AUTH;
      break;
    case Opts::KeyPurpose::CLIENT_AUTH:
      key_purpose = bssl::KeyPurpose::CLIENT_AUTH;
      break;
    case Opts::KeyPurpose::SERVER_AUTH_STRICT:
      key_purpose = bssl::KeyPurpose::SERVER_AUTH_STRICT;
      break;
    case Opts::KeyPurpose::CLIENT_AUTH_STRICT:
      key_purpose = bssl::KeyPurpose::CLIENT_AUTH_STRICT;
      break;
  }
  CertPathBuilder path_builder(leaf_cert, trust_store, &path_builder_delegate,
                               verification_time, key_purpose,
                               bssl::InitialExplicitPolicy::kFalse,
                               /* user_initial_policy_set= */
                               {bssl::der::Input(bssl::kAnyPolicyOid)},
                               bssl::InitialPolicyMappingInhibit::kFalse,
                               bssl::InitialAnyPolicyInhibit::kFalse);

  CertIssuerSourceStatic intermediates;
  for (const std::string_view &cert : opts.intermediates) {
    std::string diag_string;
    std::optional<std::shared_ptr<const ParsedCertificate>> parsed =
        bssl::InternalParseCertificate(cert, &diag_string);
    if (!parsed.has_value()) {
      if (path_builder_delegate.IsDebugLogEnabled()) {
        path_builder_delegate.DebugLog("skipping bad intermediate: " +
                                       diag_string);
      }
      continue;
    }
    intermediates.AddCert(std::move(parsed.value()));
  }
  path_builder.AddCertIssuerSource(&intermediates);

  if (opts.extra_intermediates != nullptr) {
    path_builder.AddCertIssuerSource(opts.extra_intermediates->impl_.get());
  }

  if (opts.max_iteration_count > 0) {
    path_builder.SetIterationLimit(opts.max_iteration_count);
  }

  if (opts.max_path_building_depth > 0) {
    path_builder.SetDepthLimit(opts.max_path_building_depth);
  }

  path_builder.SetExploreAllPaths(all_paths);

  CertPathBuilder::Result result = path_builder.Run();

  if (out_status != nullptr) {
    out_status->iteration_count_ = result.iteration_count;
    out_status->max_depth_seen_ = result.max_depth_seen;
  }

  *out_error = result.GetBestPathVerifyError();

  if (result.HasValidPath()) {
    std::vector<std::vector<std::string>> ret;
    if (!all_paths) {
      auto best_path = result.GetBestValidPath();
      ret.push_back(std::vector<std::string>());
      for (size_t i = 0; i < best_path->certs.size(); i++) {
        ret[0].push_back(
            std::string(best_path->certs[i]->der_cert().AsStringView()));
      }
      return ret;
    }
    for (const auto &path : result.paths) {
      if (!path->IsValid()) {
        continue;
      }
      std::vector<std::string> ret_path;
      for (const auto &cert : path->certs) {
        ret_path.push_back(std::string(cert->der_cert().AsStringView()));
      }
      ret.push_back(ret_path);
    }
    return ret;
  }

#if 0
  if (result.paths.empty()) {
    if (leaf_cert->normalized_issuer() == leaf_cert->normalized_subject()) {
      *out_error = {VerifyError::StatusCode::CERTIFICATE_SELF_SIGNED, 0,
                    "No path to a trusted certificate could be built."};
      return {};
    }
    *out_error = {VerifyError::StatusCode::PATH_NOT_FOUND, 0,
                  "No path to a trusted certifiate could be built."};
    return {};
  }

  // If there are paths, report the first error on the best path.
  CertPathBuilderResultPath *path =
      result.paths[result.best_result_index].get();
  assert(path->certs[0] == leaf_cert);
  *out_error = path->GetVerifyError();
#endif

  return {};
}

std::optional<std::vector<std::string>> Verify(const Opts &opts,
                                               VerifyError *out_error,
                                               VerifyStatus *out_status) {
  auto single_path =
      VerifyInternal(opts, out_error, out_status, /*all_paths=*/false);
  if (!single_path.has_value()) {
    return {};
  }
  return single_path.value()[0];
}

std::optional<std::vector<std::vector<std::string>>> VerifyAllPaths(
    const Opts &opts) {
  return VerifyInternal(opts, nullptr, nullptr, /*all_paths=*/true);
}

}  // namespace bssl
