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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
)

// Simple round-trip test for fixed kem, aead, kdf, plaintext, etc.
func TestHpkeSimple(t *testing.T) {
	publicKeyR, secretKeyR, err := dhkemX25519{}.GenerateKeyPair()
	check(t, err)

	// Set up the sender and receiver contexts.
	senderCtx, enc, err := SetupBaseSenderX25519(HpkeHkdfSha256, HpkeAeadAesGcm256, publicKeyR, nil, nil)
	check(t, err)
	receiverCtx, err := SetupBaseReceiverX25519(HpkeHkdfSha256, HpkeAeadAesGcm256, enc, secretKeyR, nil)
	check(t, err)

	// Seal() our plaintext with the sender context, then Open() the
	// ciphertext with the receiver context.
	plaintext := []byte("foobar")
	ciphertext := senderCtx.Seal(nil, plaintext)
	decrypted, err := receiverCtx.Open(nil, ciphertext)
	check(t, err)
	checkBytesEqual(t, "decrypted", decrypted, plaintext)
}

// HpkeTestVector defines the subset of test-vectors.json that we read.
type HpkeTestVector struct {
	KemID              uint16                 `json:"kemID"`
	Mode               uint8                  `json:"mode"`
	KdfID              uint16                 `json:"kdfID"`
	AeadID             uint16                 `json:"aeadID"`
	KeyScheduleContext Hexstring              `json:"keyScheduleContext"`
	ZZ                 Hexstring              `json:"zz"`
	Info               Hexstring              `json:"info"`
	Nonce              Hexstring              `json:"nonce"`
	ExporterSecret     Hexstring              `json:"exporterSecret"`
	SecretKeyR         Hexstring              `json:"skRm"`
	SecretKeyE         Hexstring              `json:"skEm"`
	PublicKeyR         Hexstring              `json:"pkRm"`
	PublicKeyE         Hexstring              `json:"pkEm"`
	Enc                Hexstring              `json:"enc"`
	Encryptions        []EncryptionTestVector `json:"encryptions"`
	Exports            []ExportTestVector     `json:"exports"`
}
type EncryptionTestVector struct {
	Plaintext      Hexstring `json:"plaintext"`
	AdditionalData Hexstring `json:"aad"`
	Nonce          Hexstring `json:"nonce"`
	Ciphertext     Hexstring `json:"ciphertext"`
}
type ExportTestVector struct {
	ExportContext Hexstring `json:"exportContext"`
	ExportLength  uint16    `json:"exportLength"`
	ExportValue   Hexstring `json:"exportValue"`
}

// TestAllHpkeTestVectors checks all relevant test vectors in test-vectors.json.
func TestAllHpkeTestVectors(t *testing.T) {
	jsonStr, err := ioutil.ReadFile("test-vectors.json")
	check(t, err)

	var testVectors []HpkeTestVector
	err = json.Unmarshal(jsonStr, &testVectors)
	check(t, err)

	for _, testVec := range testVectors {
		// Skip this vector if it specifies an unsupported KEM or Mode.
		if testVec.KemID != HpkeDhkemX25519HkdfSha256 ||
			testVec.Mode != hpkeModeBase {
			continue
		}
		testVec.Run(t)
	}
}

// Run tests the test vector |h|.
func (h HpkeTestVector) Run(t *testing.T) {
	senderCtx, enc, err := SetupBaseSenderX25519(h.KdfID, h.AeadID, h.PublicKeyR, h.Info,
		func() ([]byte, []byte, error) {
			return h.PublicKeyE, h.SecretKeyE, nil
		})
	check(t, err)
	checkBytesEqual(t, "sender keyScheduleContext", senderCtx.keyScheduleContext, h.KeyScheduleContext)
	checkBytesEqual(t, "sender nonce", senderCtx.nonce, h.Nonce)
	checkBytesEqual(t, "sender exporterSecret", senderCtx.exporterSecret, h.ExporterSecret)
	checkBytesEqual(t, "sender enc", enc, h.Enc)
	checkBytesEqual(t, "sender zz", senderCtx.zz, h.ZZ)

	receiverCtx, err := SetupBaseReceiverX25519(h.KdfID, h.AeadID, enc, h.SecretKeyR, h.Info)
	checkBytesEqual(t, "receiver keyScheduleContext", receiverCtx.keyScheduleContext, h.KeyScheduleContext)
	checkBytesEqual(t, "receiver nonce", receiverCtx.nonce, h.Nonce)
	checkBytesEqual(t, "receiver exporterSecret", receiverCtx.exporterSecret, h.ExporterSecret)
	checkBytesEqual(t, "receiver zz", receiverCtx.zz, h.ZZ)
	check(t, err)

	for _, e := range h.Encryptions {
		ciphertext := senderCtx.Seal(e.AdditionalData, e.Plaintext)
		checkBytesEqual(t, "ciphertext", ciphertext, e.Ciphertext)

		decrypted, err := receiverCtx.Open(e.AdditionalData, ciphertext)
		check(t, err)
		checkBytesEqual(t, "decrypted plaintext", decrypted, e.Plaintext)
	}

	for _, ex := range h.Exports {
		ex.Run(t, senderCtx)
		ex.Run(t, receiverCtx)
	}
}

// Run tests a single Export operation for the given |ctx|.
func (ex ExportTestVector) Run(t *testing.T, ctx *Ctx) {
	exportValue, err := ctx.Export(ex.ExportContext, ex.ExportLength)
	check(t, err)
	checkBytesEqual(t, "exportValue", exportValue, ex.ExportValue)
}

// Hexstring enables us to unmarshal JSON strings containing hex byte strings.
type Hexstring []byte

func (h *Hexstring) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("missing double quotes")
	}
	// Hack off the double quotes.
	data = data[1 : len(data)-1]
	// Decode as a hex string.
	*h = make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(*h, data)
	return err
}

// String produces a hexadecimal string representation of the Hexstring, which
// is more compact and regularly-shaped than the default []byte representation.
func (h Hexstring) String() string {
	return fmt.Sprintf("[N=%d: %x]", len(h), []byte(h))
}

func check(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}
func checkBytesEqual(t *testing.T, name string, actual, expected []byte) {
	if !bytes.Equal(actual, expected) {
		fmt.Printf("#### wrong %s\n", name)

		fmt.Printf("> %s actual: %x\n", name, actual)
		fmt.Printf("> %s expect: %x\n", name, expected)

		t.Errorf("Wrong %s", name)
	}
}
