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

#include <optional>
#include <string_view>

#include <openssl/pki/certificate.h>
#include <openssl/pool.h>

#include "cert_errors.h"
#include "encode_values.h"
#include "parsed_certificate.h"
#include "pem.h"
#include "parse_values.h"

namespace bssl {

namespace {

std::optional<std::shared_ptr<const bssl::ParsedCertificate>>
ParseCertificateFromDer(std::string_view cert, std::string *out_diagnostic) {
  bssl::ParseCertificateOptions default_options{};
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
      reinterpret_cast<const uint8_t*>(cert.data()), cert.size(), nullptr));
  bssl::CertErrors errors;
  std::shared_ptr<const bssl::ParsedCertificate> parsed_cert(
      bssl::ParsedCertificate::Create(std::move(buffer), default_options, &errors));
  if (!parsed_cert) {
    *out_diagnostic = errors.ToDebugString();
    return {};
  }
  return parsed_cert;
}

} // namespace

struct CertificateInternals {
  std::shared_ptr<const bssl::ParsedCertificate> cert;
};

Certificate::Certificate(std::unique_ptr<CertificateInternals> internals)
    : internals_(std::move(internals)) {}
Certificate::~Certificate() = default;
Certificate::Certificate(Certificate&& other) = default;

std::optional<std::unique_ptr<Certificate>> Certificate::FromDER(
    std::string_view der, std::string* out_diagnostic) {
  std::optional<
      std::shared_ptr<const bssl::ParsedCertificate>>
      result = ParseCertificateFromDer(der, out_diagnostic);
  if (!result.has_value()) {
    return {};
  }

  auto internals = std::make_unique<CertificateInternals>();
  internals->cert = result.value();
  std::unique_ptr<Certificate> ret(new Certificate(std::move(internals)));
  return std::move(ret);
}

std::optional<std::unique_ptr<Certificate>> Certificate::FromPEM(
    std::string_view pem, std::string *out_diagnostic) {
  bssl::PEMTokenizer tokenizer(pem, {"CERTIFICATE"});
  if (!tokenizer.GetNext()) {
    return {};
  }

  return FromDER(tokenizer.data(), out_diagnostic);
}

bool Certificate::IsSelfIssued() const {
  return internals_->cert->normalized_subject() ==
         internals_->cert->normalized_issuer();
}

Certificate::Validity Certificate::GetValidity() const {
  Certificate::Validity validity;

  // As this is a previously parsed certificate, we know the not_before
  // and not after are valid, so these conversions can not fail.
  (void) GeneralizedTimeToPosixTime(
      internals_->cert->tbs().validity_not_before, &validity.not_before);
  (void) GeneralizedTimeToPosixTime(
      internals_->cert->tbs().validity_not_after, &validity.not_after);
  return validity;
}

std::vector<uint8_t> Certificate::GetSerialNumber() const {
  const uint8_t* data = internals_->cert->tbs().serial_number.UnsafeData();
  const size_t length = internals_->cert->tbs().serial_number.Length();
  return std::vector<uint8_t>(data, data + length);
}

}  // namespace boringssl
