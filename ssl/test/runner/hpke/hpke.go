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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// KEM scheme IDs.
const (
	HpkeDhkemX25519HkdfSha256 uint16 = 0x0020
)

// HPKE AEAD IDs.
const (
	HpkeAeadAesGcm128        uint16 = 0x0001
	HpkeAeadAesGcm256        uint16 = 0x0002
	HpkeAeadChaCha20Poly1305 uint16 = 0x0003
)

// HPKE KDF IDs.
const (
	HpkeHkdfSha256 uint16 = 0x0001
	HpkeHkdfSha384 uint16 = 0x0002
	HpkeHkdfSha512 uint16 = 0x0003
)

// Internal constants.
const (
	hpkeModeBase uint8 = 0
)

type GenerateKeyPairFun func() (public []byte, secret []byte, e error)

// Kem is a subset of the Key Encapsulation Mechanism (KEM) interface.
type Kem interface {
	ID() uint16   // The KEM ID.
	Nzz() uint16  // Length of shared secret produced by this KEM.
	Nenc() uint16 // Length of encapsulated key produced by this KEM.

	// GenerateKeyPair generates a random key pair.
	GenerateKeyPair() (publicKey, secretKey []byte, err error)

	// Encap returns an ephemeral, fixed-length symmetric key |zz| and a
	// fixed-length encapsulation of that key |enc| that can be decapsulated
	// by the receiver with the secret key corresponding to |publicKeyR|.
	// Internally, |keygenOptional| is used to generate an ephemeral
	// keypair. If |keygenOptional| is nil, |GenerateKeyPair| will be
	// substituted.
	Encap(publicKeyR []byte, keygenOptional GenerateKeyPairFun) (zz, enc []byte, err error)

	// Decap uses the receiver's secret key |secretKeyR| to recover the
	// ephemeral symmetric key contained in |enc|.
	Decap(enc, secretKeyR []byte) ([]byte, error)
}

// Ctx holds the HPKE state for a sender or a receiver.
type Ctx struct {
	kem  Kem
	kdf  labeledKdf
	aead cipher.AEAD

	kdfID  uint16
	aeadID uint16

	key            []byte
	nonce          []byte
	seq            uint64
	exporterSecret []byte

	// For testing:
	keyScheduleContext []byte
	zz                 []byte
}

// SetupBaseSenderX25519 corresponds to the spec's SetupBaseS(), but only
// supports X25519.
func SetupBaseSenderX25519(kdfID, aeadID uint16, publicKeyR, info []byte, ephemKeygen GenerateKeyPairFun) (ctx *Ctx, enc []byte, err error) {
	kem := dhkemX25519{}
	zz, enc, err := kem.Encap(publicKeyR, ephemKeygen)
	if err != nil {
		return nil, nil, err
	}
	ctx, err = keySchedule(kem, kdfID, aeadID, zz, info)
	if err != nil {
		return nil, nil, err
	}
	return ctx, enc, nil
}

// SetupBaseReceiverX25519 corresponds to the spec's SetupBaseS(), but only
// supports X25519.
func SetupBaseReceiverX25519(kdfID, aeadID uint16, enc, secretKeyR, info []byte) (ctx *Ctx, err error) {
	kem := dhkemX25519{}
	zz, err := kem.Decap(enc, secretKeyR)
	if err != nil {
		return nil, err
	}
	ctx, err = keySchedule(kem, kdfID, aeadID, zz, info)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func (c *Ctx) Seal(additionalData, plaintext []byte) []byte {
	ciphertext := c.aead.Seal(nil, c.computeNonce(), plaintext, additionalData)
	c.incrementSeq()
	return ciphertext
}

func (c *Ctx) Open(additionalData, ciphertext []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, c.computeNonce(), ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	c.incrementSeq()
	return plaintext, nil
}

func (c Ctx) Export(exporterContext []byte, length uint16) ([]byte, error) {
	suiteID := buildSuiteID(c.kem.ID(), c.kdfID, c.aeadID)
	return c.kdf.LabeledExpand(c.exporterSecret, suiteID, []byte("sec"), exporterContext, length)
}

func buildSuiteID(kemID, kdfID, aeadID uint16) []byte {
	return concat(
		[]byte("HPKE"), encodeBigEndianUint16(kemID),
		encodeBigEndianUint16(kdfID),
		encodeBigEndianUint16(aeadID))
}

func newAead(aeadID uint16, key []byte) (cipher.AEAD, error) {
	if len(key) != int(expectedKeyLength(aeadID)) {
		return nil, errors.New("Wrong key length for specified aeadID")
	}
	switch aeadID {
	case HpkeAeadAesGcm128:
		fallthrough
	case HpkeAeadAesGcm256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return aead, nil
	case HpkeAeadChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return aead, nil
	}
	return nil, errors.New("Unsupported aeadID")
}

func keySchedule(kem Kem, kdfID, aeadID uint16, zz, info []byte) (*Ctx, error) {
	kdf := newKdf(kdfID)
	suiteID := buildSuiteID(kem.ID(), kdfID, aeadID)

	pskIDHash := kdf.LabeledExtract(nil, suiteID, []byte("pskID_hash"), nil)
	infoHash := kdf.LabeledExtract(nil, suiteID, []byte("info_hash"), info)
	keyScheduleContext := concat([]byte{hpkeModeBase}, pskIDHash, infoHash)

	pskHash := kdf.LabeledExtract(nil, suiteID, []byte("psk_hash"), nil)
	secret := kdf.LabeledExtract(pskHash, suiteID, []byte("secret"), zz)

	key, err := kdf.LabeledExpand(secret, suiteID, []byte("key"), keyScheduleContext, expectedKeyLength(aeadID))
	if err != nil {
		return nil, err
	}
	nonce, err := kdf.LabeledExpand(secret, suiteID, []byte("nonce"), keyScheduleContext, expectedNonceLength(aeadID))
	if err != nil {
		return nil, err
	}
	exporterSecret, err := kdf.LabeledExpand(secret, suiteID, []byte("exp"), keyScheduleContext, kdf.Nh())
	if err != nil {
		return nil, err
	}

	aead, err := newAead(aeadID, key)
	if err != nil {
		return nil, err
	}
	return &Ctx{
		kem:                kem,
		kdf:                kdf,
		aead:               aead,
		kdfID:              kdfID,
		aeadID:             aeadID,
		key:                key,
		nonce:              nonce,
		seq:                0,
		exporterSecret:     exporterSecret,
		keyScheduleContext: keyScheduleContext,
		zz:                 zz,
	}, nil
}

func (c Ctx) computeNonce() []byte {
	newNonce := make([]byte, len(c.nonce))
	// Write the Big Endian |c.seq| value at the *end* of |newNonce|.
	nonceSeqSlice := newNonce[len(newNonce)-8:]
	binary.BigEndian.PutUint64(nonceSeqSlice, c.seq)
	// XOR the Big Endian |seq| with |c.nonce|.
	for i, origNonceByte := range c.nonce {
		newNonce[i] ^= origNonceByte
	}
	return newNonce
}

func (c *Ctx) incrementSeq() {
	c.seq++
	if c.seq == 0 {
		panic("Sequence overflow")
	}
}

func expectedKeyLength(aeadID uint16) uint16 {
	switch aeadID {
	case HpkeAeadAesGcm128:
		return 128 / 8
	case HpkeAeadAesGcm256:
		return 256 / 8
	case HpkeAeadChaCha20Poly1305:
		return chacha20poly1305.KeySize
	}
	panic("Unsupported aeadID")
}

func expectedNonceLength(aeadID uint16) uint16 {
	switch aeadID {
	case HpkeAeadAesGcm128:
		return 12
	case HpkeAeadAesGcm256:
		return 12
	case HpkeAeadChaCha20Poly1305:
		return chacha20poly1305.NonceSize
	}
	panic("Unsupported aeadID")
}

func concat(pieces ...[]byte) []byte {
	return bytes.Join(pieces, []byte{})
}

func encodeBigEndianUint16(n uint16) []byte {
	return []byte{uint8((n & 0xff00) >> 8), uint8(n & 0x00ff)}
}
