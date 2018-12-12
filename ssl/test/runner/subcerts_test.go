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

package runner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"boringssl.googlesource.com/boringssl/ssl/test/runner/ed25519"
)

var subcertsDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIQLVIvEpo0/0TzRja4ImvB1TAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDcwMzE2NTE1M1oXDTE5MDcwMzE2NTE1M1ow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOhB
U6adaAgliLaFc1PAo9HBO4Wish1G4df3IK5EXLy+ooYfmkfzT1FxqbNLZufNYzve
25fmpal/1VJAjpVyKq2jVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKwYBBAGC
2kssBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPNwRk6cygm6zO5rjOzohKYWS+1KuWCM
OetDIvU4mdyoAiAGN97y3GJccYn9ZOJS4UOqhr9oO8PuZMLgdq4OrMRiiA==
-----END CERTIFICATE-----
`

var subcertsDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJDVlo+sJolMcNjMkfCGDUjMJcE4UgclcXGCrOtbJAi2oAoGCCqGSM49
AwEHoUQDQgAE6EFTpp1oCCWItoVzU8Cj0cE7haKyHUbh1/cgrkRcvL6ihh+aR/NP
UXGps0tm581jO97bl+alqX/VUkCOlXIqrQ==
-----END EC PRIVATE KEY-----
`

var subcertsNonDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBaTCCAQ6gAwIBAgIQSUo+9uaip3qCW+1EPeHZgDAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDYxMjIzNDAyNloXDTE5MDYxMjIzNDAyNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLf7
fiznPVdc3V5mM3ymswU2/IoJaq/deA6dgdj50ozdYyRiAPjxzcz9zRsZw1apTF/h
yNfiLhV4EE1VrwXcT5OjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0E
AwIDSQAwRgIhANXG0zmrVtQBK0TNZZoEGMOtSwxmiZzXNe+IjdpxO3TiAiEA5VYx
0CWJq5zqpVXbJMeKVMASo2nrXZoA6NhJvFQ97hw=
-----END CERTIFICATE-----
`

var subcertsNonDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMw9DiOfGI1E/XZrrW2huZSjYi0EKwvVjAe+dYtyFsSloAoGCCqGSM49
AwEHoUQDQgAEt/t+LOc9V1zdXmYzfKazBTb8iglqr914Dp2B2PnSjN1jJGIA+PHN
zP3NGxnDVqlMX+HI1+IuFXgQTVWvBdxPkw==
-----END EC PRIVATE KEY-----
`

var subcertsTestDCP256PEM = `-----BEGIN DELEGATED CREDENTIAL-----
AAlKdwQDAwMAAFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOonqCo5WpBO6x
/Dmh9MxAq/eL18f/b8up8LyBn9fGabVfTeIU3wSA4i+NvVJJ1dnxXhUZkqWj28J2
Nme6AdXhBAMASDBGAiEAhfhxsOYss5VNDe+AqDhfk9N/MR5vS/n2GLaTP8GIHdYC
IQCRb/TzCC2eptI4RNfm+h78RmXOwRkQVA2lLH+4fIY1og==
-----END DELEGATED CREDENTIAL-----
`

var subcertsTestDCEd25519PEM = `-----BEGIN DELEGATED CREDENTIAL-----
AAk6gAgHAwQAACwwKjAFBgMrZXADIQC1YbvDQbvCXIyDQ/NoNZOrBPNQQwhylkW/
CLU0A1+51gQDAEcwRQIhAJ58A5ULTysvAHN92WX6Q7BN+lkkL6fsuELjNy1+PQqY
AiAx/n5nG6yDQxxsN8ExiPxdYF8XEgQk6WGJ97yBMBwFxw==
-----END DELEGATED CREDENTIAL-----
`

var subcertsTestCert Certificate
var subcertsTestDelegationCert Certificate
var testNow time.Time

func init() {
	var err error

	// Use a fixed time for testing at which time the test certificates and DCs
	// are valid.
	testNow = time.Date(2018, 07, 03, 18, 0, 0, 234234, time.UTC)

	// The delegation certificate.
	subcertsTestDelegationCert, err = X509KeyPair([]byte(subcertsDelegatorCertPEM), []byte(subcertsDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	subcertsTestDelegationCert.Leaf, err = x509.ParseCertificate(subcertsTestDelegationCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// The standard certificate.
	subcertsTestCert, err = X509KeyPair([]byte(subcertsNonDelegatorCertPEM), []byte(subcertsNonDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	subcertsTestCert.Leaf, err = x509.ParseCertificate(subcertsTestCert.Certificate[0])
	if err != nil {
		panic(err)
	}
}

func checkECDSAPublicKeysEqual(
	publicKey, publicKey2 crypto.PublicKey, scheme uint16) error {

	curve := getCurve(scheme)
	pk := publicKey.(*ecdsa.PublicKey)
	pk2 := publicKey2.(*ecdsa.PublicKey)
	serializedPublicKey := elliptic.Marshal(curve, pk.X, pk.Y)
	serializedPublicKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
	if !bytes.Equal(serializedPublicKey2, serializedPublicKey) {
		return errors.New("PublicKey mismatch")
	}
	return nil
}

func checkEd25519PublicKeysEqual(pk, pk2 crypto.PublicKey) error {
	if !bytes.Equal(pk.(ed25519.PublicKey), pk2.(ed25519.PublicKey)) {
		return errors.New("PublicKey mismatch")
	}
	return nil
}

func checkCredentialsEqual(cred, cred2 *Credential) error {
	if cred2.ValidTime != cred.ValidTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", cred2.ValidTime, cred.ValidTime)
	}
	if cred2.ExpectedCertVerifyAlgorithm != cred.ExpectedCertVerifyAlgorithm {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", cred2.ExpectedCertVerifyAlgorithm, cred.ExpectedCertVerifyAlgorithm)
	}
	if cred2.ExpectedVersion != cred.ExpectedVersion {
		return fmt.Errorf("version mismatch: got %04x; want %04x", cred2.ExpectedVersion, cred.ExpectedVersion)
	}

	switch signatureAlgorithm(cred.ExpectedCertVerifyAlgorithm) {
	case signatureECDSAWithP256AndSHA256,
		signatureECDSAWithP384AndSHA384,
		signatureECDSAWithP521AndSHA512:
		return checkECDSAPublicKeysEqual(cred.PublicKey, cred2.PublicKey, cred.ExpectedCertVerifyAlgorithm)

	case signatureEd25519:
		return checkEd25519PublicKeysEqual(cred.PublicKey, cred2.PublicKey)

	default:
		return fmt.Errorf("Unknown scheme: %04x", cred.ExpectedCertVerifyAlgorithm)
	}
}

// Test decoding of a delegated credential.
func TestSubcertsUnmarshal(t *testing.T) {
	b, _ := pem.Decode([]byte(subcertsTestDCEd25519PEM))
	_, err := UnmarshalDelegatedCredential(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	b, _ = pem.Decode([]byte(subcertsTestDCP256PEM))
	_, err = UnmarshalDelegatedCredential(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
}

// Test encoding/decoding of delegated credentials.
func TestSubcertsMarshalUnmarshal(t *testing.T) {
	cert := &subcertsTestDelegationCert
	deleg, _, err := NewDelegatedCredential(cert,
		uint16(signatureECDSAWithP256AndSHA256),
		VersionTLS12,
		testNow.Sub(cert.Leaf.NotBefore)+MaxTTL)
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := deleg.Marshal()
	if err != nil {
		t.Error(err)
	}

	deleg2, err := UnmarshalDelegatedCredential(serialized)
	if err != nil {
		t.Error(err)
	}

	err = checkCredentialsEqual(deleg.Cred, deleg2.Cred)
	if err != nil {
		t.Error(err)
	}

	if deleg.Algorithm != deleg2.Algorithm {
		t.Errorf("scheme mismatch: got %04x; want %04x",
			deleg2.Algorithm, deleg.Algorithm)
	}

	if !bytes.Equal(deleg2.Signature, deleg.Signature) {
		t.Error("Signature mismatch")
	}
}

// Test delegation and validation of credentials.
func TestSubcertsDelegateValidate(t *testing.T) {
	scheme := uint16(signatureECDSAWithP256AndSHA256)
	ver := uint16(VersionTLS13)
	cert := &subcertsTestDelegationCert

	validTime := testNow.Sub(cert.Leaf.NotBefore) + MaxTTL
	shortValidTime := testNow.Sub(cert.Leaf.NotBefore) + time.Second

	dc, _, err := NewDelegatedCredential(cert, scheme, ver, validTime)
	if err != nil {
		t.Fatal(err)
	}

	// Test validation of good DC.
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of expired DC.
	tooLate := testNow.Add(MaxTTL).Add(time.Nanosecond)
	if v, err := dc.Validate(cert.Leaf, tooLate); err == nil {
		t.Error("expired DC validation succeeded; want failure")
	} else if v {
		t.Error("expired DC is valid; want invalid")
	}

	// Test credential scheme binding.
	dc.Cred.ExpectedCertVerifyAlgorithm = uint16(signatureECDSAWithP384AndSHA384)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with credential scheme is valid; want invalid")
	}
	dc.Cred.ExpectedCertVerifyAlgorithm = scheme

	// Test protocol binding.
	dc.Cred.ExpectedVersion = VersionSSL30
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong version is valid; want invalid")
	}
	dc.Cred.ExpectedVersion = ver

	// Test signature algorithm binding.
	dc.Algorithm = uint16(signatureECDSAWithP521AndSHA512)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong scheme is valid; want invalid")
	}
	dc.Algorithm = uint16(signatureECDSAWithP256AndSHA256)

	// Test delegation certificate binding.
	cert.Leaf.Raw[0] ^= byte(42)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong cert is valid; want invalid")
	}
	cert.Leaf.Raw[0] ^= byte(42)

	// Test validation of DC who's TTL is too long.
	dc2, _, err := NewDelegatedCredential(cert, uint16(signatureECDSAWithP256AndSHA256), ver, validTime+time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := dc2.Validate(cert.Leaf, testNow); err == nil {
		t.Error("DC validation with long TTL succeeded; want failure")
	} else if v {
		t.Error("DC with long TTL is valid; want invalid")
	}

	// Test validation of DC who's TTL is short.
	dc3, _, err := NewDelegatedCredential(cert, uint16(signatureECDSAWithP256AndSHA256), ver, shortValidTime)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := dc3.Validate(cert.Leaf, testNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if v, err := dc.Validate(subcertsTestCert.Leaf, testNow); err != errNoDelegationUsage {
		t.Error("DC validation with non-delegation cert succeeded; want failure")
	} else if v {
		t.Error("DC with non-delegation cert is valid; want invalid")
	}

	cred, _, err := NewCredential(uint16(signatureEd25519), ver, validTime)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := cred.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	cred2, err := UnmarshalCredential(raw)
	if err != nil {
		t.Fatal(err)
	}

	err = checkCredentialsEqual(cred, cred2)
	if err != nil {
		t.Error(err)
	}

	dc, err = Delegate(cert, cred)
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := dc.Validate(cert.Leaf, testNow); !ok {
		t.Error("Validation fails; want success")
	} else if err != nil {
		t.Error(err)
	}
}
