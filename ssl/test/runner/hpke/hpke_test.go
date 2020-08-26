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
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

var (
	testDataDir = flag.String("testdata", "testdata", "The path to the test vector JSON file.")
)

// Simple round-trip test for fixed inputs.
func TestRoundTrip(t *testing.T) {
	publicKeyR, secretKeyR, err := GenerateKeyPair()
	if err != nil {
		t.Errorf("failed to generate key pair: %s", err)
		return
	}

	// Set up the sender and receiver contexts.
	senderContext, enc, err := SetupBaseSenderX25519(HKDFSHA256, AES256GCM, publicKeyR, nil, nil)
	if err != nil {
		t.Errorf("failed to set up sender: %s", err)
		return
	}
	receiverContext, err := SetupBaseReceiverX25519(HKDFSHA256, AES256GCM, enc, secretKeyR, nil)
	if err != nil {
		t.Errorf("failed to set up receiver: %s", err)
		return
	}

	// Seal() our plaintext with the sender context, then Open() the
	// ciphertext with the receiver context.
	plaintext := []byte("foobar")
	ciphertext := senderContext.Seal(nil, plaintext)
	decrypted, err := receiverContext.Open(nil, ciphertext)
	if err != nil {
		t.Errorf("encryption round trip failed: %s", err)
		return
	}
	checkBytesEqual(t, "decrypted", decrypted, plaintext)
}

// HpkeTestVector defines the subset of test-vectors.json that we read.
type HpkeTestVector struct {
	KEM         uint16                 `json:"kem_id"`
	Mode        uint8                  `json:"mode"`
	KDF         uint16                 `json:"kdf_id"`
	AEAD        uint16                 `json:"aead_id"`
	Info        HexString              `json:"info"`
	PSK         HexString              `json:"psk"`
	PSKID       HexString              `json:"psk_id"`
	SecretKeyR  HexString              `json:"skRm"`
	SecretKeyE  HexString              `json:"skEm"`
	PublicKeyR  HexString              `json:"pkRm"`
	PublicKeyE  HexString              `json:"pkEm"`
	Enc         HexString              `json:"enc"`
	Encryptions []EncryptionTestVector `json:"encryptions"`
	Exports     []ExportTestVector     `json:"exports"`
}
type EncryptionTestVector struct {
	Plaintext      HexString `json:"plaintext"`
	AdditionalData HexString `json:"aad"`
	Ciphertext     HexString `json:"ciphertext"`
}
type ExportTestVector struct {
	ExportContext HexString `json:"exportContext"`
	ExportLength  int       `json:"exportLength"`
	ExportValue   HexString `json:"exportValue"`
}

// TestVectors checks all relevant test vectors in test-vectors.json.
func TestVectors(t *testing.T) {
	jsonStr, err := ioutil.ReadFile(filepath.Join(*testDataDir, "test-vectors.json"))
	if err != nil {
		t.Errorf("error reading test vectors: %s", err)
		return
	}

	var testVectors []HpkeTestVector
	err = json.Unmarshal(jsonStr, &testVectors)
	if err != nil {
		t.Errorf("error parsing test vectors: %s", err)
		return
	}

	var numSkippedTests = 0

	for testNum, testVec := range testVectors {
		// Skip this vector if it specifies an unsupported KEM or Mode.
		if testVec.KEM != X25519WithHKDFSHA256 ||
			(testVec.Mode != hpkeModeBase && testVec.Mode != hpkeModePSK) {
			numSkippedTests++
			continue
		}

		testVec := testVec // capture the range variable
		t.Run(fmt.Sprintf("test%d,KDF=%d,AEAD=%d", testNum, testVec.KDF, testVec.AEAD), func(t *testing.T) {
			var senderContext *Context
			var receiverContext *Context
			var enc []byte
			var err error

			switch testVec.Mode {
			case hpkeModeBase:
				senderContext, enc, err = SetupBaseSenderX25519(testVec.KDF, testVec.AEAD, testVec.PublicKeyR, testVec.Info,
					func() ([]byte, []byte, error) {
						return testVec.PublicKeyE, testVec.SecretKeyE, nil
					})
				if err != nil {
					t.Errorf("failed to set up sender: %s", err)
					return
				}
				checkBytesEqual(t, "sender enc", enc, testVec.Enc)

				receiverContext, err = SetupBaseReceiverX25519(testVec.KDF, testVec.AEAD, enc, testVec.SecretKeyR, testVec.Info)
				if err != nil {
					t.Errorf("failed to set up receiver: %s", err)
					return
				}
			case hpkeModePSK:
				senderContext, enc, err = SetupPSKSenderX25519(testVec.KDF, testVec.AEAD, testVec.PublicKeyR, testVec.Info, testVec.PSK, testVec.PSKID,
					func() ([]byte, []byte, error) {
						return testVec.PublicKeyE, testVec.SecretKeyE, nil
					})
				if err != nil {
					t.Errorf("failed to set up sender: %s", err)
					return
				}
				checkBytesEqual(t, "sender enc", enc, testVec.Enc)

				receiverContext, err = SetupPSKReceiverX25519(testVec.KDF, testVec.AEAD, enc, testVec.SecretKeyR, testVec.Info, testVec.PSK, testVec.PSKID)
				if err != nil {
					t.Errorf("failed to set up receiver: %s", err)
					return
				}
			default:
				panic("unsupported mode")
			}

			for encryptionNum, e := range testVec.Encryptions {
				ciphertext := senderContext.Seal(e.AdditionalData, e.Plaintext)
				checkBytesEqual(t, "ciphertext", ciphertext, e.Ciphertext)

				decrypted, err := receiverContext.Open(e.AdditionalData, ciphertext)
				if err != nil {
					t.Errorf("decryption %d failed: %s", encryptionNum, err)
					return
				}
				checkBytesEqual(t, "decrypted plaintext", decrypted, e.Plaintext)
			}

			for _, ex := range testVec.Exports {
				exportValue := senderContext.Export(ex.ExportContext, ex.ExportLength)
				checkBytesEqual(t, "exportValue", exportValue, ex.ExportValue)

				exportValue = receiverContext.Export(ex.ExportContext, ex.ExportLength)
				checkBytesEqual(t, "exportValue", exportValue, ex.ExportValue)
			}
		})
	}

	if numSkippedTests == len(testVectors) {
		panic("no test vectors were used")
	}
}

// HexString enables us to unmarshal JSON strings containing hex byte strings.
type HexString []byte

func (h *HexString) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("missing double quotes")
	}
	var err error
	*h, err = hex.DecodeString(string(data[1 : len(data)-1]))
	return err
}

func checkBytesEqual(t *testing.T, name string, actual, expected []byte) {
	if !bytes.Equal(actual, expected) {
		t.Errorf("%s = %x; want %x", name, actual, expected)
	}
}
