// Copyright (c) 2020, Google Inc.
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

package hpke

import (
	"crypto"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	rfcLabel string = "HPKE-05 "
)

// labeledHKDF implements the LabeledKdf interface for hash-based KDFs.
type labeledHKDF struct {
	h crypto.Hash
}

func NewKDF(kdfID uint16) labeledHKDF {
	switch kdfID {
	case HKDFSHA256:
		return labeledHKDF{h: crypto.SHA256}
	case HKDFSHA384:
		return labeledHKDF{h: crypto.SHA384}
	case HKDFSHA512:
		return labeledHKDF{h: crypto.SHA512}
	}
	panic("unknown KDF")
}

func (h labeledHKDF) Size() int {
	return h.h.Size()
}
func (h labeledHKDF) LabeledExtract(salt, suiteID, label, ikm []byte) []byte {
	labeledIKM := make([]byte, 0)
	labeledIKM = append(labeledIKM, rfcLabel...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(h.h.New, labeledIKM, salt)
}
func (h labeledHKDF) LabeledExpand(prk, suiteID, label, info []byte, length int) []byte {
	lengthU16 := uint16(length)
	if int(lengthU16) != length {
		panic("length must be a valid uint16 value")
	}

	labeledInfo := make([]byte, 0)
	labeledInfo = appendBigEndianUint16(labeledInfo, lengthU16)
	labeledInfo = append(labeledInfo, rfcLabel...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)

	reader := hkdf.Expand(h.h.New, prk, labeledInfo)
	key := make([]uint8, length)
	_, err := reader.Read(key)
	if err != nil {
		panic("failed to perform HKDF expand operation")
	}
	return key
}

// GenerateKeyPair generates a random key pair.
func GenerateKeyPair() (publicKey, secretKeyOut []byte, err error) {
	// Generate a new private key.
	var secretKey [curve25519.ScalarSize]byte
	_, err = rand.Read(secretKey[:])
	if err != nil {
		return
	}
	// Compute the corresponding public key.
	publicKey, err = curve25519.X25519(secretKey[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return publicKey, secretKey[:], nil
}

// x25519Encap returns an ephemeral, fixed-length symmetric key |sharedSecret|
// and a fixed-length encapsulation of that key |enc| that can be decapsulated
// by the receiver with the secret key corresponding to |publicKeyR|.
// Internally, |keygenOptional| is used to generate an ephemeral keypair. If
// |keygenOptional| is nil, |GenerateKeyPair| will be substituted.
func x25519Encap(publicKeyR []byte, keygen GenerateKeyPairFunc) ([]byte, []byte, error) {
	if keygen == nil {
		keygen = GenerateKeyPair
	}
	publicKeyEphem, secretKeyEphem, err := keygen()
	if err != nil {
		return nil, nil, err
	}
	dh, err := curve25519.X25519(secretKeyEphem, publicKeyR)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret := extractAndExpand(dh, publicKeyEphem, publicKeyR)
	return sharedSecret, publicKeyEphem, nil
}

// x25519Decap uses the receiver's secret key |secretKeyR| to recover the
// ephemeral symmetric key contained in |enc|.
func x25519Decap(enc, secretKeyR []byte) ([]byte, error) {
	dh, err := curve25519.X25519(secretKeyR, enc)
	if err != nil {
		return nil, err
	}
	// For simplicity, we recompute the receiver's public key. A production
	// implementation of HPKE should incorporate it into the receiver key
	// and halve the number of point multiplications needed.
	publicKeyR, err := curve25519.X25519(secretKeyR, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return extractAndExpand(dh, enc, publicKeyR[:]), nil
}

func extractAndExpand(dh, enc, publicKeyR []byte) []byte {
	var kemContext []byte
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, publicKeyR...)

	kdf := NewKDF(HKDFSHA256)

	suite := []byte("KEM")
	suite = appendBigEndianUint16(suite, X25519WithHKDFSHA256)

	prk := kdf.LabeledExtract(nil, suite, []byte("eae_prk"), dh)
	return kdf.LabeledExpand(prk, suite, []byte("shared_secret"), kemContext, 32)
}
