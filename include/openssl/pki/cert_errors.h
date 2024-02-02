// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// ----------------------------
// Overview of error design
// ----------------------------
//
// Certificate path building/validation/parsing may emit a sequence of errors
// and warnings.
//
// Each individual error/warning entry (CertError) is comprised of:
//
//   * A unique identifier.
//
//     This serves similarly to an error code, and is used to query if a
//     particular error/warning occurred.
//
//   * [optional] A parameters object.
//
//     Nodes may attach a heap-allocated subclass of CertErrorParams to carry
//     extra information that is used when reporting the error. For instance
//     a parsing error may describe where in the DER the failure happened, or
//     what the unexpected value was.
//
// A collection of errors is represented by the CertErrors object. This may be
// used to group errors that have a common context, such as all the
// errors/warnings that apply to a specific certificate.
//
// Lastly, CertPathErrors composes multiple CertErrors -- one for each
// certificate in the verified chain.
//
// ----------------------------
// Defining new errors
// ----------------------------
//
// The error IDs are extensible and do not need to be centrally defined.
//
// To define a new error use the macro DEFINE_CERT_ERROR_ID() in a .cc file.
// If consumers are to be able to query for this error then the symbol should
// also be exposed in a header file.
//
// Error IDs are in truth string literals, whose pointer value will be unique
// per process.

#ifndef BSSL_PKI_CERT_ERRORS_H_
#define BSSL_PKI_CERT_ERRORS_H_

#include <memory>
#include <vector>

#include <openssl/base.h>

namespace bssl {

class CertErrorParams;

// Each "class" of certificate error/warning has its own unique ID. This is
// essentially like an error code, however the value is not stable. Under the
// hood these IDs are pointers and use the process's address space to ensure
// uniqueness.
//
// Equality of CertErrorId can be done using the == operator.
//
// To define new error IDs use the macro DEFINE_CERT_ERROR_ID().
using CertErrorId = const void *;

// DEFINE_CERT_ERROR_ID() creates a CertErrorId given a non-null C-string
// literal. The string should be a textual name for the error which will appear
// when pretty-printing errors for debugging. It should be ASCII.
#define DEFINE_CERT_ERROR_ID(name, c_str_literal) \
  const CertErrorId name = c_str_literal

// Returns a debug string for a CertErrorId. In practice this returns the
// string literal given to DEFINE_CERT_ERROR_ID(), which is human-readable.
OPENSSL_EXPORT const char *CertErrorIdToDebugString(CertErrorId id);

// CertError represents either an error or a warning.
struct OPENSSL_EXPORT CertError {
  enum Severity {
    SEVERITY_HIGH,
    SEVERITY_WARNING,
  };

  CertError();
  CertError(Severity severity, CertErrorId id,
            std::unique_ptr<CertErrorParams> params);
  CertError(CertError &&other);
  CertError &operator=(CertError &&);
  ~CertError();

  // Pretty-prints the error and its parameters.
  std::string ToDebugString() const;

  Severity severity;
  CertErrorId id;
  std::unique_ptr<CertErrorParams> params;
};

// CertErrors is a collection of CertError, along with convenience methods to
// add and inspect errors.
class OPENSSL_EXPORT CertErrors {
 public:
  CertErrors();
  CertErrors(CertErrors &&other);
  CertErrors &operator=(CertErrors &&);
  ~CertErrors();

  // Adds an error/warning. |params| may be null.
  void Add(CertError::Severity severity, CertErrorId id,
           std::unique_ptr<CertErrorParams> params);

  // Adds a high severity error.
  void AddError(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddError(CertErrorId id);

  // Adds a low severity error.
  void AddWarning(CertErrorId id, std::unique_ptr<CertErrorParams> params);
  void AddWarning(CertErrorId id);

  // Dumps a textual representation of the errors for debugging purposes.
  std::string ToDebugString() const;

  // Returns true if the error |id| was added to this CertErrors (of any
  // severity).
  bool ContainsError(CertErrorId id) const;

  // Returns true if this contains any errors of the given severity level.
  bool ContainsAnyErrorWithSeverity(CertError::Severity severity) const;

 private:
  std::vector<CertError> nodes_;
};

// CertPathErrors is a collection of CertErrors, to group errors into different
// buckets for different certificates. The "index" should correspond with that
// of the certificate relative to its chain.
class OPENSSL_EXPORT CertPathErrors {
 public:
  CertPathErrors();
  CertPathErrors(CertPathErrors &&other);
  CertPathErrors &operator=(CertPathErrors &&);
  ~CertPathErrors();

  // Gets a bucket to put errors in for |cert_index|. This will lookup and
  // return the existing error bucket if one exists, or create a new one for the
  // specified index. It is expected that |cert_index| is the corresponding
  // index in a certificate chain (with 0 being the target).
  CertErrors *GetErrorsForCert(size_t cert_index);

  // Const version of the above, with the difference that if there is no
  // existing bucket for |cert_index| returns nullptr rather than lazyily
  // creating one.
  const CertErrors *GetErrorsForCert(size_t cert_index) const;

  // Returns a bucket to put errors that are not associated with a particular
  // certificate.
  CertErrors *GetOtherErrors();

  // Returns true if CertPathErrors contains the specified error (of any
  // severity).
  bool ContainsError(CertErrorId id) const;

  // Returns true if this contains any errors of the given severity level.
  bool ContainsAnyErrorWithSeverity(CertError::Severity severity) const;

  // Shortcut for ContainsAnyErrorWithSeverity(CertError::SEVERITY_HIGH).
  bool ContainsHighSeverityErrors() const {
    return ContainsAnyErrorWithSeverity(CertError::SEVERITY_HIGH);
  }

  // Pretty print all the certificate errors for every cert. |cert_names[index]|
  // will be added to the pretty print output for each index if index is less than
  // |cert_names|.size().
  std::string ToDebugString(const std::vector<std::string> &cert_names) const;

 private:
  std::vector<CertErrors> cert_errors_;
  CertErrors other_errors_;
  };

}  // namespace bssl

// Below are the set of "default" certificate errors (those
// defined by the core verification/path building code).
//
// Errors may be defined for other domains.
namespace bssl::cert_errors {

// An internal error occurred which prevented path building or verification
// from finishing.
OPENSSL_EXPORT extern const CertErrorId kInternalError;

// The verification time is after the certificate's notAfter time.
OPENSSL_EXPORT extern const CertErrorId kValidityFailedNotAfter;

// The verification time is before the certificate's notBefore time.
OPENSSL_EXPORT extern const CertErrorId kValidityFailedNotBefore;

// The certificate is actively distrusted by the trust store (this is separate
// from other revocation mechanisms).
OPENSSL_EXPORT extern const CertErrorId kDistrustedByTrustStore;

// The certificate disagrees on what the signature algorithm was
// (Certificate.signatureAlgorithm != TBSCertificate.signature).
OPENSSL_EXPORT extern const CertErrorId kSignatureAlgorithmMismatch;

// Certificate verification was called with an empty chain.
OPENSSL_EXPORT extern const CertErrorId kChainIsEmpty;

// The certificate contains an unknown extension which is marked as critical.
OPENSSL_EXPORT extern const CertErrorId kUnconsumedCriticalExtension;

// The target certificate appears to be a CA (has Basic Constraints CA=true)
// but is being used for TLS client or server authentication.
OPENSSL_EXPORT extern const CertErrorId kTargetCertShouldNotBeCa;

// The certificate is being used to sign other certificates, however the
// keyCertSign KeyUsage was not set.
OPENSSL_EXPORT extern const CertErrorId kKeyCertSignBitNotSet;

// The chain violates the max_path_length from BasicConstraints.
OPENSSL_EXPORT extern const CertErrorId kMaxPathLengthViolated;

// The certificate being used to sign other certificates has a
// BasicConstraints extension, however it sets CA=false
OPENSSL_EXPORT extern const CertErrorId kBasicConstraintsIndicatesNotCa;

// The certificate being used to sign other certificates does not include a
// BasicConstraints extension.
OPENSSL_EXPORT extern const CertErrorId kMissingBasicConstraints;

// The certificate has a subject or subjectAltName that violates an issuer's
// name constraints.
OPENSSL_EXPORT extern const CertErrorId kNotPermittedByNameConstraints;

// The chain has an excessive number of names and/or name constraints.
OPENSSL_EXPORT extern const CertErrorId kTooManyNameConstraintChecks;

// The certificate's issuer field does not match the subject of its alleged
// issuer.
OPENSSL_EXPORT extern const CertErrorId kSubjectDoesNotMatchIssuer;

// Failed to verify the certificate's signature using its issuer's public key.
OPENSSL_EXPORT extern const CertErrorId kVerifySignedDataFailed;

// The certificate encodes its signature differently between
// Certificate.algorithm and TBSCertificate.signature, but it appears
// to be the same algorithm.
OPENSSL_EXPORT extern const CertErrorId kSignatureAlgorithmsDifferentEncoding;

// The certificate verification is being done for serverAuth, however the
// certificate lacks serverAuth in its ExtendedKeyUsages.
OPENSSL_EXPORT extern const CertErrorId kEkuLacksServerAuth;

// The certificate verification is being done for clientAuth, however the
// certificate lacks clientAuth in its ExtendedKeyUsages.
OPENSSL_EXPORT extern const CertErrorId kEkuLacksClientAuth;

// The root certificate in a chain is not trusted.
OPENSSL_EXPORT extern const CertErrorId kCertIsNotTrustAnchor;

// The chain is not valid for any policy, and an explicit policy was required.
// (Either because the relying party requested it during verificaiton, or it was
// requrested by a PolicyConstraints extension).
OPENSSL_EXPORT extern const CertErrorId kNoValidPolicy;

// The certificate is trying to map to, or from, anyPolicy.
OPENSSL_EXPORT extern const CertErrorId kPolicyMappingAnyPolicy;

// The public key in this certificate could not be parsed.
OPENSSL_EXPORT extern const CertErrorId kFailedParsingSpki;

// The certificate's signature algorithm (used to verify its
// signature) is not acceptable by the consumer. What constitutes as
// "acceptable" is determined by the verification delegate.
OPENSSL_EXPORT extern const CertErrorId kUnacceptableSignatureAlgorithm;

// The certificate's public key is not acceptable by the consumer.
// What constitutes as "acceptable" is determined by the verification delegate.
OPENSSL_EXPORT extern const CertErrorId kUnacceptablePublicKey;

// The certificate's EKU is missing serverAuth. However EKU ANY is present
// instead.
OPENSSL_EXPORT extern const CertErrorId kEkuLacksServerAuthButHasAnyEKU;

// The certificate's EKU is missing clientAuth. However EKU ANY is present
// instead.
OPENSSL_EXPORT extern const CertErrorId kEkuLacksClientAuthButHasAnyEKU;

// The certificate's EKU is missing both clientAuth and serverAuth.
OPENSSL_EXPORT extern const CertErrorId kEkuLacksClientAuthOrServerAuth;

// The certificate's EKU has OSCP Signing when it should not.
OPENSSL_EXPORT extern const CertErrorId kEkuHasProhibitedOCSPSigning;

// The certificate's EKU has Time Stamping when it should not.
OPENSSL_EXPORT extern const CertErrorId kEkuHasProhibitedTimeStamping;

// The certificate's EKU has Code Signing when it should not.
OPENSSL_EXPORT extern const CertErrorId kEkuHasProhibitedCodeSigning;

// The certificate does not have EKU.
OPENSSL_EXPORT extern const CertErrorId kEkuNotPresent;

// The certificate has been revoked.
OPENSSL_EXPORT extern const CertErrorId kCertificateRevoked;

// The certificate lacks a recognized revocation mechanism (i.e. OCSP/CRL).
// Emitted as an error when revocation checking expects certificates to have
// such info.
OPENSSL_EXPORT extern const CertErrorId kNoRevocationMechanism;

// The certificate had a revocation mechanism, but when used it was unable to
// affirmatively say whether the certificate was unrevoked.
OPENSSL_EXPORT extern const CertErrorId kUnableToCheckRevocation;

// Path building was unable to find any issuers for the certificate.
OPENSSL_EXPORT extern const CertErrorId kNoIssuersFound;

// Deadline was reached during path building.
OPENSSL_EXPORT extern const CertErrorId kDeadlineExceeded;

// Iteration limit was reached during path building.
OPENSSL_EXPORT extern const CertErrorId kIterationLimitExceeded;

// Depth limit was reached during path building.
OPENSSL_EXPORT extern const CertErrorId kDepthLimitExceeded;

}  // namespace bssl::cert_errors

#endif  // BSSL_PKI_CERT_ERRORS_H_
