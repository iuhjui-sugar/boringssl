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

// Kem is a subset of the Key Encapsulation Mechanism (KEM) interface.
type Kem interface {
	ID() uint16
	GenerateKeyPair() (publicKey, secretKey []byte, err error)
	Encap(publicKeyR []byte) (zz []byte, enc []byte, err error)
	Decap(enc, secretKeyR []byte) ([]byte, error)

	Nzz() uint16  // Length of shared secret produced by this KEM.
	Nenc() uint16 // Length of encapsulated key produced by this KEM.
}

// HpkeCtx holds the HPKE state for a sender or a receiver.
type HpkeCtx struct {
	kem  Kem
	kdf  labeledKdf
	aead cipher.AEAD

	kdfID  uint16
	aeadID uint16

	key            []byte
	nonce          []byte
	seq            uint64
	exporterSecret []byte
}

// SetupBaseSenderX25519 corresponds to the spec's SetupBaseS(), but only supports X25519.
func SetupBaseSenderX25519(kdfID, aeadID uint16, publicKeyR, info []byte) (ctx *HpkeCtx, enc []byte, err error) {
	kem := dhkemX25519{}
	zz, enc, err := kem.Encap(publicKeyR)
	if err != nil {
		return nil, nil, err
	}
	ctx, err = keySchedule(kem, kdfID, aeadID, zz, info)
	if err != nil {
		return nil, nil, err
	}
	return ctx, enc, nil
}

// SetupBaseReceiverX25519 corresponds to the spec's SetupBaseS(), but only supports X25519.
func SetupBaseReceiverX25519(kdfID, aeadID uint16, enc, secretKeyR, info []byte) (ctx *HpkeCtx, err error) {
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

func (c HpkeCtx) Seal(additionalData, plaintext []byte) []byte {
	ciphertext := c.aead.Seal(nil, c.computeNonce(), plaintext, additionalData)
	c.incrementSeq()
	return ciphertext
}

func (c HpkeCtx) Open(additionalData, ciphertext []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, c.computeNonce(), ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	c.incrementSeq()
	return plaintext, nil
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
		return nil, errors.New("HpkeAeadChaCha20Poly1305 support TBD")
	}
	return nil, errors.New("Unsupported aeadID")
}

func keySchedule(kem Kem, kdfID, aeadID uint16, zz, info []byte) (*HpkeCtx, error) {
	kdf := newKdf(kdfID)
	pskIDHash := kdf.LabeledExtract(nil, []byte("pskID_hash"), nil)
	infoHash := kdf.LabeledExtract(nil, []byte("info_hash"), nil)
	keyScheduleContext := concat([]byte{hpkeModeBase}, pskIDHash, infoHash)

	pskHash := kdf.LabeledExtract(nil, []byte("psk_hash"), nil)
	secret := kdf.LabeledExtract(pskHash, []byte("secret"), zz)

	key, err := kdf.LabeledExpand(secret, []byte("key"), keyScheduleContext, expectedKeyLength(aeadID))
	if err != nil {
		return nil, err
	}
	nonce, err := kdf.LabeledExpand(secret, []byte("nonce"), keyScheduleContext, expectedNonceLength(aeadID))
	if err != nil {
		return nil, err
	}
	exporterSecret, err := kdf.LabeledExpand(secret, []byte("exp"), keyScheduleContext, kdf.Nh())
	if err != nil {
		return nil, err
	}
	// Build the HpkeCtx.
	aead, err := newAead(aeadID, key)
	if err != nil {
		return nil, err
	}
	return &HpkeCtx{
		kem:            kem,
		kdf:            kdf,
		aead:           aead,
		kdfID:          kdfID,
		aeadID:         aeadID,
		key:            key,
		nonce:          nonce,
		seq:            0,
		exporterSecret: exporterSecret,
	}, nil
}

func (c HpkeCtx) computeNonce() []byte {
	newNonce := make([]byte, len(c.nonce))
	binary.BigEndian.PutUint64(newNonce, c.seq)
	for i, origNonceByte := range c.nonce {
		newNonce[i] ^= origNonceByte
	}
	return newNonce
}

func (c HpkeCtx) incrementSeq() {
	c.seq++
	if c.seq == 0 {
		panic("Sequence overflow")
	}
}

// Misc helper functions.

func concat(pieces ...[]byte) []byte {
	return bytes.Join(pieces, []byte{})
}

func encodeBigEndianUint16(n uint16) []byte {
	return []byte{uint8((n & 0xff00) >> 8), uint8(n & 0x00ff)}
}

func expectedKeyLength(aeadID uint16) uint16 {
	switch aeadID {
	case HpkeAeadAesGcm128:
		return 128 / 8
	case HpkeAeadAesGcm256:
		return 256 / 8
	case HpkeAeadChaCha20Poly1305:
		return 32
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
		return 12
	}
	panic("Unsupported aeadID")
}
