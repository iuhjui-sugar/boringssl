// Copyright (c) 2018 Cloudflare, Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// This implements the backend for draft-02 of Delegated credentials for
// TLS (https://tools.ietf.org/html/draft-ietf-tls-subcerts), an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the server may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short-lived signing key pair delegated
// to the server by an entity trusted by the client. This allows a middlebox to
// terminate a TLS connection on behalf of the entity; for example, this can be
// used to delegate TLS termination to a reverse proxy. Credentials can't be
// revoked; in order to mitigate risk in case the middlebox is compromised, the
// credential is only valid for a short time (days, hours, or even minutes).
//
// This package provides functionalities for minting and validating delegated
// credentials. It also implements parts of the X.509 standard for EdDSA
// siganture schemes (draft-04), as needed for minting DCss.

package runner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"boringssl.googlesource.com/boringssl/ssl/test/runner/ed25519"
)

const (
	MaxTTLSeconds     = 60 * 60 * 24 * 7 // 7 days
	MaxTTL            = time.Duration(MaxTTLSeconds * time.Second)
	dcMaxPublicKeyLen = 1 << 24 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes
)

var errNoDelegationUsage = errors.New("certificate not authorized for delegation")

// delegationUsageId is the DelegationUsage X.509 extension OID.
var DelegationUsageId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       DelegationUsageId,
		Critical: false,
		Value:    nil,
	}
}

// IsDelegationCertificate returns true if a certificate can be used for
// delegated credentials.
func IsDelegationCertificate(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (per the spec).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(DelegationUsageId) {
			return true
		}
	}
	return false
}

// Credential structure stores the public components of a credential.
type Credential struct {
	// The serialized form of the credential.
	Raw []byte

	// The amount of time for which the credential is valid. Specifically,
	// the credential expires ValidTime seconds after the notBefore of the
	// delegation certificate. The delegator shall not issue delegated
	// credentials that are valid for more than 7 days from the current time.
	//
	// When this data structure is serialized, this value is converted to a
	// uint32 representing the duration in seconds.
	ValidTime time.Duration

	// The signature scheme associated with the credential public key.
	ExpectedCertVerifyAlgorithm uint16

	// The version of TLS in which the credential will be used.
	ExpectedVersion uint16

	// The credential public key.
	PublicKey crypto.PublicKey
}

// NewCredential generates a key pair for the provided signature algorithm,
// protocol version, and validity time.
func NewCredential(scheme, version uint16, validTime time.Duration) (*Credential, crypto.PrivateKey, error) {
	// The granularity of DC validity in seconds.
	validTime = validTime.Round(time.Second)

	// Generate a new key pair.
	var err error
	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch signatureAlgorithm(scheme) {
	case signatureECDSAWithP256AndSHA256,
		signatureECDSAWithP384AndSHA384,
		signatureECDSAWithP521AndSHA512:
		sk, err = ecdsa.GenerateKey(getCurve(scheme), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.(*ecdsa.PrivateKey).Public()

	case signatureEd25519:
		pk, sk, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil, fmt.Errorf("unsupported signature scheme: 0x%04x", scheme)
	}

	return &Credential{
		ValidTime:                   validTime,
		ExpectedCertVerifyAlgorithm: scheme,
		ExpectedVersion:             version,
		PublicKey:                   pk,
	}, sk, nil
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegation certificate's notBefore field (start)
// plus the validity time. This function simply checks that the current time
// (now) is before the end of the valdity interval.
func (cred *Credential) IsExpired(start, now time.Time) bool {
	end := start.Add(cred.ValidTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than
// the maximum permitted. This is defined by the certificate's notBefore field
// (start) plus the ValidTime, minus the current time (now).
func (cred *Credential) InvalidTTL(start, now time.Time) bool {
	return cred.ValidTime > (now.Sub(start) + MaxTTL).Round(time.Second)
}

// marshalPublicKey returns a DER encoded SubjectPublicKeyInfo structure (as
// defined in the X.509 standard) that encodes the credential public key.
func (cred *Credential) marshalPublicKey() ([]byte, error) {
	switch signatureAlgorithm(cred.ExpectedCertVerifyAlgorithm) {
	case signatureECDSAWithP256AndSHA256,
		signatureECDSAWithP384AndSHA384,
		signatureECDSAWithP521AndSHA512:
		return x509.MarshalPKIXPublicKey(cred.PublicKey)

	case signatureEd25519:
		var key []byte
		pk, ok := cred.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("Not an Ed25519 public key")
		}
		// NOTE: This is how encoding/deocding of Ed25519 public keys seems to
		// happen in this repository. It might be better to do something like
		// this:
		//
		// https://github.com/cloudflare/cfssl/blob/master/helpers/derhelpers/ed25519.go#L31
		key = append(key, ed25519SPKIPrefix...)
		key = append(key, []byte(pk)...)
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported signature scheme: 0x%04x", cred.ExpectedCertVerifyAlgorithm)
	}
}

// Marshal encodes a credential as per the spec.
func (cred *Credential) Marshal() ([]byte, error) {
	credSerial := newByteBuilder()
	credSerial.addU32(uint32(cred.ValidTime / time.Second))
	credSerial.addU16(cred.ExpectedCertVerifyAlgorithm)
	credSerial.addU16(cred.ExpectedVersion)
	// Encode the public key and assert that the encoding is no longer than 2^16
	// bytes (per the spect).
	serializedPublicKey, err := cred.marshalPublicKey()
	if err != nil {
		return nil, err
	}
	if len(serializedPublicKey) > dcMaxPublicKeyLen {
		return nil, errors.New("public key is too long")
	}
	pubKey := credSerial.addU24LengthPrefixed()
	pubKey.addBytes(serializedPublicKey)

	serialized := credSerial.finish()
	copy(cred.Raw, serialized)
	return serialized, nil
}

// UnmarshalCredential decodes a credential and returns it.
func UnmarshalCredential(serialized []byte) (*Credential, error) {
	malformedCred := errors.New("malformed credential")
	reader := (*byteReader)(&serialized)
	// Parse the valid_time, scheme, and version fields.
	var validSecs uint32
	var scheme uint16
	var version uint16
	var pkbytes []byte

	if !reader.readU32(&validSecs) {
		return nil, malformedCred
	}
	if !reader.readU16(&scheme) {
		return nil, malformedCred
	}
	if !reader.readU16(&version) {
		return nil, malformedCred
	}

	// Parse the public key.
	if !reader.readU24LengthPrefixedBytes(&pkbytes) {
		return nil, malformedCred
	}
	pk, err := unmarshalPublicKey(pkbytes)
	if err != nil {
		return nil, err
	}

	return &Credential{
		Raw:                         serialized,
		ValidTime:                   time.Duration(validSecs) * time.Second,
		ExpectedCertVerifyAlgorithm: scheme,
		ExpectedVersion:             version,
		PublicKey:                   pk,
	}, nil
}

// unmarshalPublicKey parses a DER-encoded SubjectPublicKeyInfo
// structure into a public key.
func unmarshalPublicKey(serialized []byte) (crypto.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		publicKey = ed25519.PublicKey(serialized[len(ed25519SPKIPrefix):])
	}

	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		return pk, nil
	case ed25519.PublicKey:
		return pk, nil
	default:
		return nil, fmt.Errorf("unsupported delegation key type: %T", pk)
	}
}

// DelegatedCredential stores a credential and its delegation.
type DelegatedCredential struct {
	// The serialized form of the delegated credential.
	Raw []byte

	// The credential, which contains a public and its validity time.
	Cred *Credential

	// The signature scheme used to sign the credential.
	Algorithm uint16

	// The credential's delegation.
	Signature []byte
}

// ensureCertificateHasLeaf parses the leaf certificate if needed.
func ensureCertificateHasLeaf(cert *Certificate) error {
	var err error
	if cert.Leaf == nil {
		if len(cert.Certificate[0]) == 0 {
			return errors.New("missing leaf certificate")
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
	}
	return nil
}

// Delegate signs a credential using the provided certificate and returns the
// delegated credential.
func Delegate(cert *Certificate, cred *Credential) (*DelegatedCredential, error) {
	var err error
	if err = ensureCertificateHasLeaf(cert); err != nil {
		return nil, err
	}

	// Check that the leaf certificate can be used for delegation.
	if !IsDelegationCertificate(cert.Leaf) {
		return nil, errNoDelegationUsage
	}

	// Extract the delegator signature scheme from the certificate.
	var delegatorAlgorithm signatureAlgorithm
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Ensure the certificate public key type matches the public key.
		if cert.Leaf.PublicKeyAlgorithm != x509.ECDSA {
			return nil, fmt.Errorf("certificate public key type does not match public key")
		}

		// Set the signature algorithm of the delegation certificate.
		pk := sk.Public().(*ecdsa.PublicKey)
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			delegatorAlgorithm = signatureECDSAWithP256AndSHA256
		} else if curveName == "P-384" {
			delegatorAlgorithm = signatureECDSAWithP384AndSHA384
		} else if curveName == "P-521" {
			delegatorAlgorithm = signatureECDSAWithP521AndSHA512
		} else {
			return nil, fmt.Errorf("unrecognized curve %s", curveName)
		}
	default:
		return nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	// Prepare the credential for digital signing.
	rawCred, err := cred.Marshal()
	if err != nil {
		return nil, err
	}
	hash := getHash(uint16(delegatorAlgorithm))
	in := prepareDelegation(hash, rawCred, cert.Leaf.Raw, uint16(delegatorAlgorithm))

	// Sign the credential.
	var sig []byte
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(hash)
		sig, err = sk.Sign(rand.Reader, in, opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported delegation key type: %T", sk)
	}

	return &DelegatedCredential{
		Cred:      cred,
		Algorithm: uint16(delegatorAlgorithm),
		Signature: sig,
	}, nil
}

// NewDelegatedCredential creates a new delegated credential using the provided
// certificate for delegation. It generates a public/private key pair for the
// provided signature algorithm (scheme), validity interval (defined by
// cert.Leaf.notBefore and validTime), and TLS version (version), and signs
// it using the provided certificate.
func NewDelegatedCredential(cert *Certificate, scheme, version uint16, validTime time.Duration) (*DelegatedCredential, crypto.PrivateKey, error) {
	cred, sk, err := NewCredential(scheme, version, validTime)
	if err != nil {
		return nil, nil, err
	}

	dc, err := Delegate(cert, cred)
	if err != nil {
		return nil, nil, err
	}
	return dc, sk, nil
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that the TTL is valid. It also checks that certificate can be
// used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, now time.Time) (bool, error) {
	// Check that the cert can delegate.
	if !IsDelegationCertificate(cert) {
		return false, errNoDelegationUsage
	}

	if dc.Cred.IsExpired(cert.NotBefore, now) {
		return false, errors.New("credential has expired")
	}

	if dc.Cred.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("credential TTL is invalid")
	}

	// Prepare the credential for verification.
	rawCred, err := dc.Cred.Marshal()
	if err != nil {
		return false, err
	}
	hash := getHash(dc.Algorithm)
	in := prepareDelegation(hash, rawCred, cert.Raw, dc.Algorithm)

	switch signatureAlgorithm(dc.Algorithm) {
	case signatureECDSAWithP256AndSHA256,
		signatureECDSAWithP384AndSHA384,
		signatureECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		sig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(dc.Signature, sig); err != nil {
			return false, err
		}
		return ecdsa.Verify(pk, in, sig.R, sig.S), nil
	case signatureEd25519:
		pk, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false, errors.New("invalid key type for Ed25519")
		}

		if !ed25519.Verify(pk, in, dc.Signature) {
			return false, errors.New("invalid Ed25519 signature")
		}

	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Algorithm)
	}
	return false, errors.New("unreachable")
}

// Marshal encodes a DelegatedCredential structure per the spec. It also sets
// dc.Raw to the output as a side effect.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	// The credential.
	serialized := newByteBuilder()
	cred, err := dc.Cred.Marshal()
	if err != nil {
		return nil, err
	}

	serialized.addBytes(cred)
	serialized.addU16(uint16(dc.Algorithm))
	// The signature.
	if len(dc.Signature) > dcMaxSignatureLen {
		return nil, errors.New("signature is too long")
	}
	signature := serialized.addU16LengthPrefixed()
	signature.addBytes(dc.Signature)

	dc.Raw = serialized.finish()
	return dc.Raw, nil
}

// UnmarshalDelegatedCredential decodes a DelegatedCredential structure.
func UnmarshalDelegatedCredential(serialized []byte) (*DelegatedCredential, error) {
	var cred Credential
	var scheme uint16
	var sig []byte
	var serializedR *byteReader
	var validSecs uint32
	var pkbytes []byte

	malformedDC := errors.New("malformed delegated credential")
	serializedR = (*byteReader)(&serialized)
	if !serializedR.readU32(&validSecs) {
		return nil, malformedDC
	}
	if !serializedR.readU16(&cred.ExpectedCertVerifyAlgorithm) {
		return nil, malformedDC
	}
	if !serializedR.readU16(&cred.ExpectedVersion) {
		return nil, malformedDC
	}
	cred.ValidTime = time.Duration(validSecs) * time.Second
	if !serializedR.readU24LengthPrefixedBytes(&pkbytes) {
		return nil, malformedDC
	}
	pk, err := unmarshalPublicKey(pkbytes)
	if err != nil {
		return nil, err
	}
	cred.PublicKey = pk

	if !serializedR.readU16(&scheme) {
		return nil, malformedDC
	}
	if !serializedR.readU16LengthPrefixedBytes(&sig) {
		return nil, malformedDC
	}

	return &DelegatedCredential{
		Raw:       serialized,
		Cred:      &cred,
		Algorithm: scheme,
		Signature: sig,
	}, nil
}

// getCurve maps the SignatureScheme to its corresponding elliptic.Curve.
func getCurve(scheme uint16) elliptic.Curve {
	switch signatureAlgorithm(scheme) {
	case signatureECDSAWithP256AndSHA256:
		return elliptic.P256()
	case signatureECDSAWithP384AndSHA384:
		return elliptic.P384()
	case signatureECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// getHash maps the SignatureScheme to its corresponding hash function.
func getHash(scheme uint16) crypto.Hash {
	switch signatureAlgorithm(scheme) {
	case signatureECDSAWithP256AndSHA256:
		return crypto.SHA256
	case signatureECDSAWithP384AndSHA384:
		return crypto.SHA384
	case signatureECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// prepareDelegation returns a hash of the message that the delegator is to
// sign. The inputs are the credential (cred), the DER-encoded delegator
// certificate (delegatorCert) and the signature scheme of the delegator
// (delegatorScheme).
func prepareDelegation(hash crypto.Hash, cred, delegatorCert []byte, delegatorAlgorithm uint16) []byte {
	h := hash.New()

	// The header.
	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte("TLS, server delegated credentials"))
	h.Write([]byte{0x00})

	// The delegation certificate.
	h.Write(delegatorCert)

	// The credential.
	h.Write(cred)

	// The delegator signature scheme.
	var serializedAlgorithm [2]byte
	binary.BigEndian.PutUint16(serializedAlgorithm[:], uint16(delegatorAlgorithm))
	h.Write(serializedAlgorithm[:])

	return h.Sum(nil)
}
