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
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	rfcLabel string = "RFCXXXX "
)

func newKdf(kdfID uint16) labeledHKDF {
	switch kdfID {
	case HKDFSHA256:
		return labeledHKDF{h: crypto.SHA256}
	case HKDFSHA384:
		return labeledHKDF{h: crypto.SHA384}
	case HKDFSHA512:
		return labeledHKDF{h: crypto.SHA512}
	}
	panic("Unknown kdfID")
}

// labeledHKDF implements the LabeledKdf interface for hash-based KDFs.
type labeledHKDF struct {
	h crypto.Hash
}

func (h labeledHKDF) Nh() uint16 {
	return uint16(h.h.Size())
}
func (h labeledHKDF) LabeledExtract(salt, suiteID, label, ikm []byte) []byte {
	labeledIKM := concat([]byte(rfcLabel), suiteID, label, ikm)
	return hkdf.Extract(h.h.New, labeledIKM, salt)
}
func (h labeledHKDF) LabeledExpand(prk, suiteID, label, info []byte, length uint16) ([]byte, error) {
	labeledInfo := concat(encodeBigEndianUint16(length), []byte(rfcLabel), suiteID, label, info)
	reader := hkdf.Expand(h.h.New, prk, labeledInfo)
	key := make([]uint8, length)
	_, err := reader.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// dhkemX25519 implements the KEM interface.
type dhkemX25519 struct{}

// The KEM ID.
func (d dhkemX25519) ID() uint16 {
	return X25519WithHKDFSHA256
}

// Length of shared secret produced by this KEM.
func (d dhkemX25519) Nzz() uint16 {
	return 32
}

// GenerateKeyPair generates a random key pair.
func (d dhkemX25519) GenerateKeyPair() (publicKey, secretKeyOut []byte, err error) {
	// Generate a new private key.
	var secretKey [curve25519.ScalarSize]byte
	_, err = rand.Read(secretKey[:])
	if err != nil {
		return
	}
	// Compute the corresponding public key.
	var publicKeyTmp [32]byte
	curve25519.ScalarBaseMult(&publicKeyTmp, &secretKey)
	return publicKeyTmp[:], secretKey[:], nil
}

// Encap returns an ephemeral, fixed-length symmetric key |zz| and a
// fixed-length encapsulation of that key |enc| that can be decapsulated
// by the receiver with the secret key corresponding to |publicKeyR|.
// Internally, |keygenOptional| is used to generate an ephemeral
// keypair. If |keygenOptional| is nil, |GenerateKeyPair| will be
// substituted.
func (d dhkemX25519) Encap(publicKeyR []byte, keygen GenerateKeyPairFunc) ([]byte, []byte, error) {
	if keygen == nil {
		keygen = d.GenerateKeyPair
	}
	publicKeyEphem, secretKeyEphem, err := keygen()
	if err != nil {
		return nil, nil, err
	}
	dh, err := curve25519.X25519(secretKeyEphem, publicKeyR)
	if err != nil {
		return nil, nil, err
	}
	kemContext := concat(publicKeyEphem, publicKeyR)
	zz, err := d.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return zz, publicKeyEphem, nil
}

// Decap uses the receiver's secret key |secretKeyR| to recover the
// ephemeral symmetric key contained in |enc|.
func (d dhkemX25519) Decap(enc, secretKeyR []byte) ([]byte, error) {
	if len(secretKeyR) != curve25519.ScalarSize {
		return nil, errors.New("secretKeyR has wrong length")
	}
	publicKeyEphem := enc
	dh, err := curve25519.X25519(secretKeyR, publicKeyEphem)
	if err != nil {
		return nil, err
	}
	// Compute the public key corresponding to |secretKeyR|.
	var publicKeyR [32]byte
	var secretKeyTmp [curve25519.ScalarSize]byte
	copy(secretKeyTmp[:], secretKeyR[:])
	curve25519.ScalarBaseMult(&publicKeyR, &secretKeyTmp)

	kemContext := concat(enc, publicKeyR[:])
	zz, err := d.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, err
	}
	return zz, nil
}

func (d dhkemX25519) extractAndExpand(dh []byte, kemContext []byte) ([]byte, error) {
	kdf := newKdf(HKDFSHA256)
	suiteID := concat([]byte("KEM"), encodeBigEndianUint16(d.ID()))

	prk := kdf.LabeledExtract(nil, suiteID, []byte("eae_prk"), dh)
	key, err := kdf.LabeledExpand(prk, suiteID, []byte("zz"), kemContext, d.Nzz())
	if err != nil {
		return nil, err
	}
	return key, nil
}
