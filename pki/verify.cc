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
}  // namespace bssl

using bssl::CertError;
using bssl::CertErrors;
using bssl::CertIssuerSourceStatic;
using bssl::CertPathBuilder;
using bssl::CertPathBuilderResultPath;
using bssl::ParsedCertificate;
using bssl::SignatureVerifyCache;
using bssl::SimplePathBuilderDelegate;
using bssl::TrustStoreInMemory;
using bssl::cert_errors::kCertificateRevoked;
using bssl::cert_errors::kDepthLimitExceeded;
using bssl::cert_errors::kEkuLacksClientAuth;
using bssl::cert_errors::kEkuLacksServerAuth;
using bssl::cert_errors::kNoIssuersFound;
using bssl::cert_errors::kUnacceptableSignatureAlgorithm;
using bssl::cert_errors::kValidityFailedNotAfter;
using bssl::cert_errors::kValidityFailedNotBefore;
using bssl::cert_errors::kVerifySignedDataFailed;

namespace verify {

CertPool::CertPool() {}

Opts::Opts() {}

static std::unique_ptr<TrustStore> WrapTrustStore(
    std::unique_ptr<TrustStoreInMemory> trust_store) {
  std::unique_ptr<TrustStore> ret(new TrustStore);
  ret->trust_store = std::move(trust_store);
  return ret;
}

TrustStore::~TrustStore() {}

std::optional<std::unique_ptr<TrustStore>> TrustStore::FromDER(
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

std::optional<std::unique_ptr<TrustStore>> TrustStore::FromDER(
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

Error::Error() {}

Error::Error(Code code, size_t offset, std::string_view diagnostic)
    : offset_(offset), code_(code), diagnostic_(diagnostic) {}

Error &Error::operator=(const Error &other) {
  code_ = other.code_;
  offset_ = other.offset_;
  diagnostic_ = other.diagnostic_;
  return *this;
}

std::string Error::DiagnosticString() const { return diagnostic_; }

std::string Error::AsString() const {
  std::string location =
      offset_ ? "Certificate " + std::to_string(offset_) + " of the best path"
              : "Leaf certificate";
  switch (code_) {
    case Error::Code::CERTIFICATE_REJECTED:
      return location + " is invalid";
    case Error::Code::CERTIFICATE_REVOKED:
      return location + " has been revoked";
    case Error::Code::CERTIFICATE_SELF_SIGNED:
      assert(offset_ == 0);
      return location + " is self-signed";
    case Error::Code::NO_PATH:
      return "No path found from the leaf certificate to any root.  Maybe an "
             "intermediate certificate is missing?";
    case Error::Code::CERTIFICATE_EXPIRED:
      return location + " is expired";
    case Error::Code::CERTIFICATE_NOT_YET_VALID:
      return location + " is not yet valid";
    case Error::Code::CERTIFICATE_LACKS_SERVER_AUTH:
      return location + " is not valid for server authentication";
    case Error::Code::CERTIFICATE_LACKS_CLIENT_AUTH:
      return location + " is not valid for client authentication";
    case Error::Code::CERTIFICATE_UNACCEPTABLE_SIGALG:
      return location + " uses an unacceptable signature algorithm";
    case Error::Code::CERTIFICATE_SIGNATURE_VERIFY_FAILED:
      return location + " has a signature that could not be verified";
    case Error::Code::CERTIFICATE_OTHER_ERROR:
      return location + " has an error";
    case Error::Code::ITERATION_COUNT_EXCEEDED:
      return "No path was found within the permitted number of iterations";
    case Error::Code::DEADLINE_EXCEEDED:
      return "No path was found within the permitted amount of time";
    case Error::Code::DEPTH_LIMIT_REACHED:
      return "No path was found within the depth limit";
    case Error::Code::UNKNOWN_ERROR:
      return "An error occurred while trying to build a path";
  }
  assert(0);  // NOTREACHED
  return "An unknown error code was returned";
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
    const Opts &opts, Error *out_error, VerifyStatus *out_status,
    bool all_paths) {
  Error dummy;
  if (!out_error) {
    out_error = &dummy;
  }
  if (out_status != nullptr) {
    out_status->iteration_count_ = 0;
    out_status->max_depth_seen_ = 0;
  }

  std::optional<std::shared_ptr<const ParsedCertificate>> maybe_leaf =
      bssl::InternalParseCertificate(opts.leaf_cert, &out_error->diagnostic_);

  if (!maybe_leaf.has_value()) {
    out_error->code_ = Error::Code::CERTIFICATE_REJECTED;
    out_error->offset_ = 0;
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
    *out_error = {Error::Code::UNKNOWN_ERROR, 0, ""};
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
    std::string diagnostic;
    std::optional<std::shared_ptr<const ParsedCertificate>> parsed =
        bssl::InternalParseCertificate(cert, &diagnostic);
    if (!parsed.has_value()) {
      if (path_builder_delegate.IsDebugLogEnabled()) {
        path_builder_delegate.DebugLog("skipping bad intermediate: " +
                                       diagnostic);
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

  // If there are no paths, then we have no errors to report beyond what we
  // can synthesize from the inputs.

  if (result.exceeded_iteration_limit) {
    *out_error = {Error::Code::ITERATION_COUNT_EXCEEDED, 0, ""};
    return {};
  }

  if (result.exceeded_deadline) {
    *out_error = {Error::Code::DEADLINE_EXCEEDED, 0, ""};
    return {};
  }

  if (result.AnyPathContainsError(kDepthLimitExceeded)) {
    // We can only return one error. Returning a path depth limit reached error
    // if it appears on any path will make this error prominent even if there
    // are other paths with different errors.
    *out_error = {Error::Code::DEPTH_LIMIT_REACHED, 0, ""};
    return {};
  }

  if (result.paths.empty()) {
    if (leaf_cert->normalized_issuer() == leaf_cert->normalized_subject()) {
      *out_error = {Error::Code::CERTIFICATE_SELF_SIGNED, 0, ""};
      return {};
    }
    *out_error = {Error::Code::NO_PATH, 0, ""};
    return {};
  }

  // If there are paths, report the first error on the best path.
  CertPathBuilderResultPath *path =
      result.paths[result.best_result_index].get();
  assert(path->certs[0] == leaf_cert);
  for (size_t i = 0; i < path->certs.size(); ++i) {
    const CertErrors *errors = path->errors.GetErrorsForCert(i);
    if (errors->ContainsAnyErrorWithSeverity(CertError::SEVERITY_HIGH)) {
      if (errors->ContainsError(kValidityFailedNotAfter)) {
        *out_error = {Error::Code::CERTIFICATE_EXPIRED, i, ""};
        return {};
      } else if (errors->ContainsError(kValidityFailedNotBefore)) {
        *out_error = {Error::Code::CERTIFICATE_NOT_YET_VALID, i, ""};
        return {};
      } else if (errors->ContainsError(kEkuLacksServerAuth)) {
        *out_error = {Error::Code::CERTIFICATE_LACKS_SERVER_AUTH, i, ""};
        return {};
      } else if (errors->ContainsError(kEkuLacksClientAuth)) {
        *out_error = {Error::Code::CERTIFICATE_LACKS_CLIENT_AUTH, i, ""};
        return {};
      } else if (errors->ContainsError(kVerifySignedDataFailed)) {
        *out_error = {Error::Code::CERTIFICATE_SIGNATURE_VERIFY_FAILED, i, ""};
        return {};
      } else if (errors->ContainsError(kUnacceptableSignatureAlgorithm)) {
        *out_error = {Error::Code::CERTIFICATE_UNACCEPTABLE_SIGALG, i, ""};
        return {};
      } else if (errors->ContainsError(kCertificateRevoked)) {
        *out_error = {Error::Code::CERTIFICATE_REVOKED, i, ""};
        return {};
      } else if (errors->ContainsError(kNoIssuersFound)) {
        if (path->certs.size() == 1 &&
            leaf_cert->normalized_issuer() == leaf_cert->normalized_subject()) {
          *out_error = {Error::Code::CERTIFICATE_SELF_SIGNED, i, ""};
        } else {
          *out_error = {Error::Code::NO_PATH, i, ""};
        }
        return {};
      }
      std::string diagnostic = errors->ToDebugString();
      *out_error = {Error::Code::CERTIFICATE_OTHER_ERROR, i, diagnostic};
      return {};
    }
  }
  *out_error = {Error::Code::UNKNOWN_ERROR, 0,
                "Difficulties are just things to overcome, after all."};
  return {};
}

std::optional<std::vector<std::string>> Verify(const Opts &opts,
                                               Error *out_error,
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

}  // namespace verify
