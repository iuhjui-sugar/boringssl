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
	publicKeyR, secretKeyR, err := dhkemX25519{}.GenerateKeyPair()
	if err != nil {
		t.Errorf("Error in TestRoundTrip: %s", err)
		return
	}

	// Set up the sender and receiver contexts.
	senderContext, enc, err := SetupBaseSenderX25519(HKDFSHA256, AES256GCM, publicKeyR, nil, nil)
	if err != nil {
		t.Errorf("Error in TestRoundTrip: %s", err)
		return
	}
	receiverContext, err := SetupBaseReceiverX25519(HKDFSHA256, AES256GCM, enc, secretKeyR, nil)
	if err != nil {
		t.Errorf("Error in TestRoundTrip: %s", err)
		return
	}

	// Seal() our plaintext with the sender context, then Open() the
	// ciphertext with the receiver context.
	plaintext := []byte("foobar")
	ciphertext := senderContext.Seal(nil, plaintext)
	decrypted, err := receiverContext.Open(nil, ciphertext)
	if err != nil {
		t.Errorf("Error in TestRoundTrip: %s", err)
		return
	}
	checkBytesEqual(t, "decrypted", decrypted, plaintext)
}

// HpkeTestVector defines the subset of test-vectors.json that we read.
type HpkeTestVector struct {
	KEMID       uint16                 `json:"kemID"`
	Mode        uint8                  `json:"mode"`
	KDFID       uint16                 `json:"kdfID"`
	AEADID      uint16                 `json:"aeadID"`
	Info        HexString              `json:"info"`
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
	ExportLength  uint16    `json:"exportLength"`
	ExportValue   HexString `json:"exportValue"`
}

// TestVectors checks all relevant test vectors in test-vectors.json.
func TestVectors(t *testing.T) {
	jsonStr, err := ioutil.ReadFile(filepath.Join(*testDataDir, "test-vectors.json"))
	if err != nil {
		t.Errorf("Error in TestVectors: %s", err)
		return
	}

	var testVectors []HpkeTestVector
	err = json.Unmarshal(jsonStr, &testVectors)
	if err != nil {
		t.Errorf("Error in TestVectors: %s", err)
		return
	}

	for testNum, testVec := range testVectors {
		// Skip this vector if it specifies an unsupported KEM or Mode.
		if testVec.KEMID != X25519WithHKDFSHA256 ||
			testVec.Mode != hpkeModeBase {
			continue
		}

		testVec := testVec // capture the range variable
		t.Run(fmt.Sprintf("test%d,KDF=%d,AEAD=%d", testNum, testVec.KDFID, testVec.AEADID), func(t *testing.T) {
			senderContext, enc, err := SetupBaseSenderX25519(testVec.KDFID, testVec.AEADID, testVec.PublicKeyR, testVec.Info,
				func() ([]byte, []byte, error) {
					return testVec.PublicKeyE, testVec.SecretKeyE, nil
				})
			if err != nil {
				t.Errorf("Error in testvector %d: %s", testNum, err)
				return
			}
			checkBytesEqual(t, "sender enc", enc, testVec.Enc)

			receiverContext, err := SetupBaseReceiverX25519(testVec.KDFID, testVec.AEADID, enc, testVec.SecretKeyR, testVec.Info)
			if err != nil {
				t.Errorf("Error in testvector %d: %s", testNum, err)
				return
			}

			for encryptionNum, e := range testVec.Encryptions {
				ciphertext := senderContext.Seal(e.AdditionalData, e.Plaintext)
				checkBytesEqual(t, "ciphertext", ciphertext, e.Ciphertext)

				decrypted, err := receiverContext.Open(e.AdditionalData, ciphertext)
				if err != nil {
					t.Errorf("Error in testvector %d, encryption %d: %s", testNum, encryptionNum, err)
					return
				}
				checkBytesEqual(t, "decrypted plaintext", decrypted, e.Plaintext)
			}

			for exportNum, ex := range testVec.Exports {
				exportValue, err := senderContext.Export(ex.ExportContext, ex.ExportLength)
				if err != nil {
					t.Errorf("Error in testvector %d, export %d: %s", testNum, exportNum, err)
					return
				}
				checkBytesEqual(t, "exportValue", exportValue, ex.ExportValue)

				exportValue, err = receiverContext.Export(ex.ExportContext, ex.ExportLength)
				if err != nil {
					t.Errorf("Error in testvector %d, export %d: %s", testNum, exportNum, err)
					return
				}
				checkBytesEqual(t, "exportValue", exportValue, ex.ExportValue)
			}
		})
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

// String produces a hexadecimal string representation of the HexString, which
// is more compact and regularly-shaped than the default []byte representation.
func (h HexString) String() string {
	return fmt.Sprintf("[N=%d: %x]", len(h), []byte(h))
}

func checkBytesEqual(t *testing.T, name string, actual, expected []byte) {
	if !bytes.Equal(actual, expected) {
		t.Errorf("%s = %x; want %x", name, actual, expected)
	}
}
