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

// Package hpke implements Hybrid Public Key Encryption (HPKE).
//
// See https://tools.ietf.org/html/draft-irtf-cfrg-hpke-05.
package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// KEM scheme IDs.
const (
	X25519WithHKDFSHA256 uint16 = 0x0020
)

// HPKE AEAD IDs.
const (
	AES128GCM        uint16 = 0x0001
	AES256GCM        uint16 = 0x0002
	ChaCha20Poly1305 uint16 = 0x0003
)

// HPKE KDF IDs.
const (
	HKDFSHA256 uint16 = 0x0001
	HKDFSHA384 uint16 = 0x0002
	HKDFSHA512 uint16 = 0x0003
)

// Internal constants.
const (
	hpkeModeBase uint8 = 0
	hpkeModePSK  uint8 = 1
)

type GenerateKeyPairFunc func() (public []byte, secret []byte, e error)

// Context holds the HPKE state for a sender or a receiver.
type Context struct {
	KEM  uint16
	KDF  uint16
	AEAD uint16

	kdf  labeledHKDF
	aead cipher.AEAD

	key            []byte
	baseNonce      []byte
	seq            uint64
	exporterSecret []byte
}

// SetupBaseSenderX25519 corresponds to the spec's SetupBaseS(), but only
// supports X25519.
func SetupBaseSenderX25519(KDF, AEAD uint16, publicKeyR, info []byte, ephemKeygen GenerateKeyPairFunc) (context *Context, enc []byte, err error) {
	kem := dhkemX25519{}
	sharedSecret, enc, err := kem.Encap(publicKeyR, ephemKeygen)
	if err != nil {
		return nil, nil, err
	}
	context, err = keySchedule(hpkeModeBase, kem.ID(), KDF, AEAD, sharedSecret, info, nil, nil)
	return
}

// SetupBaseReceiverX25519 corresponds to the spec's SetupBaseR(), but only
// supports X25519.
func SetupBaseReceiverX25519(KDF, AEAD uint16, enc, secretKeyR, info []byte) (context *Context, err error) {
	kem := dhkemX25519{}
	sharedSecret, err := kem.Decap(enc, secretKeyR)
	if err != nil {
		return nil, err
	}
	context, err = keySchedule(hpkeModeBase, kem.ID(), KDF, AEAD, sharedSecret, info, nil, nil)
	if err != nil {
		return nil, err
	}
	return context, nil
}

// SetupPSKSenderX25519 corresponds to the spec's SetupPSKS(), but only supports
// X25519.
func SetupPSKSenderX25519(KDF, AEAD uint16, publicKeyR, info, psk, pskID []byte, ephemKeygen GenerateKeyPairFunc) (context *Context, enc []byte, err error) {
	kem := dhkemX25519{}
	sharedSecret, enc, err := kem.Encap(publicKeyR, ephemKeygen)
	if err != nil {
		return nil, nil, err
	}
	context, err = keySchedule(hpkeModePSK, kem.ID(), KDF, AEAD, sharedSecret, info, psk, pskID)
	return
}

// SetupPSKReceiverX25519 corresponds to the spec's SetupPSKR(), but only
// supports X25519.
func SetupPSKReceiverX25519(KDF, AEAD uint16, enc, secretKeyR, info, psk, pskID []byte) (context *Context, err error) {
	kem := dhkemX25519{}
	sharedSecret, err := kem.Decap(enc, secretKeyR)
	if err != nil {
		return nil, err
	}
	context, err = keySchedule(hpkeModePSK, kem.ID(), KDF, AEAD, sharedSecret, info, psk, pskID)
	if err != nil {
		return nil, err
	}
	return context, nil
}

func (c *Context) Seal(additionalData, plaintext []byte) []byte {
	ciphertext := c.aead.Seal(nil, c.computeNonce(), plaintext, additionalData)
	c.incrementSeq()
	return ciphertext
}

func (c *Context) Open(additionalData, ciphertext []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, c.computeNonce(), ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	c.incrementSeq()
	return plaintext, nil
}

func (c *Context) Export(exporterContext []byte, length int) []byte {
	suiteID := buildSuiteID(c.KEM, c.KDF, c.AEAD)
	return c.kdf.LabeledExpand(c.exporterSecret, suiteID, []byte("sec"), exporterContext, length)
}

func buildSuiteID(KEM, KDF, AEAD uint16) []byte {
	ret := make([]byte, 0, 10)
	ret = append(ret, "HPKE"...)
	ret = appendBigEndianUint16(ret, KEM)
	ret = appendBigEndianUint16(ret, KDF)
	ret = appendBigEndianUint16(ret, AEAD)
	return ret
}

func newAEAD(AEAD uint16, key []byte) (cipher.AEAD, error) {
	if len(key) != expectedKeyLength(AEAD) {
		return nil, errors.New("wrong key length for specified AEAD")
	}
	switch AEAD {
	case AES128GCM, AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return aead, nil
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return aead, nil
	}
	return nil, errors.New("unsupported AEAD")
}

func verifyPSKInputs(mode uint8, psk, pskID []byte) {
	switch mode {
	case hpkeModeBase:
		if len(psk) > 0 || len(pskID) > 0 {
			panic("unnecessary psk inputs were provided")
		}
	case hpkeModePSK:
		if len(psk) == 0 || len(pskID) == 0 {
			panic("missing psk inputs")
		}
	default:
		panic("unknown mode")
	}
}

func keySchedule(mode uint8, KEM, KDF, AEAD uint16, sharedSecret, info, psk, pskID []byte) (*Context, error) {
	verifyPSKInputs(mode, psk, pskID)

	kdf := newKDF(KDF)
	suiteID := buildSuiteID(KEM, KDF, AEAD)
	pskIDHash := kdf.LabeledExtract(nil, suiteID, []byte("psk_id_hash"), pskID)
	infoHash := kdf.LabeledExtract(nil, suiteID, []byte("info_hash"), info)

	keyScheduleContext := make([]byte, 0)
	keyScheduleContext = append(keyScheduleContext, mode)
	keyScheduleContext = append(keyScheduleContext, pskIDHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)

	pskHash := kdf.LabeledExtract(nil, suiteID, []byte("psk_hash"), psk)
	secret := kdf.LabeledExtract(pskHash, suiteID, []byte("secret"), sharedSecret)
	key := kdf.LabeledExpand(secret, suiteID, []byte("key"), keyScheduleContext, expectedKeyLength(AEAD))

	aead, err := newAEAD(AEAD, key)
	if err != nil {
		return nil, err
	}

	nonce := kdf.LabeledExpand(secret, suiteID, []byte("nonce"), keyScheduleContext, aead.NonceSize())
	exporterSecret := kdf.LabeledExpand(secret, suiteID, []byte("exp"), keyScheduleContext, kdf.Size())

	return &Context{
		KEM:            KEM,
		KDF:            KDF,
		AEAD:           AEAD,
		kdf:            kdf,
		aead:           aead,
		key:            key,
		baseNonce:      nonce,
		seq:            0,
		exporterSecret: exporterSecret,
	}, nil
}

func (c Context) computeNonce() []byte {
	nonce := make([]byte, len(c.baseNonce))
	// Write the big-endian |c.seq| value at the *end* of |baseNonce|.
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], c.seq)
	// XOR the big-endian |seq| with |c.baseNonce|.
	for i, b := range c.baseNonce {
		nonce[i] ^= b
	}
	return nonce
}

func (c *Context) incrementSeq() {
	c.seq++
	if c.seq == 0 {
		panic("sequence overflow")
	}
}

func expectedKeyLength(AEAD uint16) int {
	switch AEAD {
	case AES128GCM:
		return 128 / 8
	case AES256GCM:
		return 256 / 8
	case ChaCha20Poly1305:
		return chacha20poly1305.KeySize
	}
	panic("unsupported AEAD")
}

func appendBigEndianUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
