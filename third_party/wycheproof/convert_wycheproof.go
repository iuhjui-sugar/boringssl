/* Copyright (c) 2018, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// convert_wycheproof.go converts Wycheproof test vectors into a format more
// easily consumed by BoringSSL.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

type wycheproofTest struct {
	Algorithm        string            `json:"algorithm"`
	GeneratorVersion string            `json:"generatorVersion"`
	NumberOfTests    int               `json:"numberOfTests"`
	Notes            map[string]string `json:"notes"`
	Header           []string          `json:"header"`
	// encoding/json does not support collecting unused keys, so we leave
	// everything past this point as generic.
	TestGroups []map[string]interface{} `json:"testGroups"`
}

func sortedKeys(m map[string]interface{}) []string {
	var keys []string
	for k, _ := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func printAttribute(w io.Writer, key string, valueI interface{}, isInstruction bool) {
	switch value := valueI.(type) {
	case float64:
		if float64(int(value)) != value {
			panic(key + "was not an integer.")
		}
		if isInstruction {
			fmt.Fprintf(w, "[%s = %d]\n", key, int(value))
		} else {
			fmt.Fprintf(w, "%s = %d\n", key, int(value))
		}
	case string:
		if strings.Contains(value, "\n") {
			panic(key + " contained a newline.")
		}
		if isInstruction {
			fmt.Fprintf(w, "[%s = %s]\n", key, value)
		} else {
			fmt.Fprintf(w, "%s = %s\n", key, value)
		}
	case map[string]interface{}:
		for _, k := range sortedKeys(value) {
			printAttribute(w, key+"."+k, value[k], isInstruction)
		}
	default:
		panic("Unknown type for " + key)
	}
}

func printComment(w io.Writer, in string) {
	const width = 80 - 2
	lines := strings.Split(in, "\n")
	for _, line := range lines {
		for {
			if len(line) <= width {
				fmt.Fprintf(w, "# %s\n", line)
				break
			}

			// Find the last space we can break at.
			n := strings.LastIndexByte(line[:width+1], ' ')
			if n < 0 {
				// The next word is too long. Wrap as soon as that word ends.
				n = strings.IndexByte(line[width+1:], ' ')
				if n < 0 {
					// This was the last word.
					fmt.Fprintf(w, "# %s\n", line)
					break
				}
				n += width + 1
			}
			fmt.Fprintf(w, "# %s\n", line[:n])
			line = line[n+1:] // Ignore the space.
		}
	}
}

func isSupportedCurve(curve string) bool {
	switch curve {
	case "brainpoolP224r1", "brainpoolP224t1", "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1", "brainpoolP512r1", "brainpoolP512t1", "secp256k1":
		return false
	case "edwards25519", "curve25519", "secp224r1", "secp256r1", "secp384r1", "secp521r1":
		return true
	default:
		panic("Unknown curve: " + curve)
	}
}

func convertWycheproof(jsonPath, txtPath string) error {
	jsonData, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		return err
	}

	var w wycheproofTest
	if err := json.Unmarshal(jsonData, &w); err != nil {
		return err
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# Imported from Wycheproof %s\n", "blah")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# Algorithm: %s\n", w.Algorithm)
	fmt.Fprintf(&b, "# Generator version: %s\n", w.GeneratorVersion)
	fmt.Fprintf(&b, "\n")

	for _, group := range w.TestGroups {
		// Skip tests with unsupported curves. We filter these out at
		// conversion time to avoid unnecessarily inflating
		// crypto_test_data.cc.
		if curve, ok := group["curve"]; ok && !isSupportedCurve(curve.(string)) {
			continue
		}
		if keyI, ok := group["key"]; ok {
			if key, ok := keyI.(map[string]interface{}); ok {
				if curve, ok := key["curve"]; ok && !isSupportedCurve(curve.(string)) {
					continue
				}
			}
		}

		for _, k := range sortedKeys(group) {
			// Wycheproof files always include both keyPem and
			// keyDer. Skip keyPem as they contain newlines. We
			// process keyDer more easily.
			if k == "type" || k == "tests" || k == "keyPem" {
				continue
			}
			printAttribute(&b, k, group[k], true)
		}
		fmt.Fprintf(&b, "\n")
		tests := group["tests"].([]interface{})
		for _, testI := range tests {
			test := testI.(map[string]interface{})
			// Skip tests with unsupported curves.
			if curve, ok := test["curve"]; ok && !isSupportedCurve(curve.(string)) {
				continue
			}
			if comment, ok := test["comment"]; ok {
				printComment(&b, comment.(string))
			}
			for _, k := range sortedKeys(test) {
				if k == "comment" || k == "flags" || k == "tcId" {
					continue
				}
				printAttribute(&b, k, test[k], false)
			}
			if flags, ok := test["flags"]; ok {
				for _, flag := range flags.([]interface{}) {
					if note, ok := w.Notes[flag.(string)]; ok {
						printComment(&b, note)
					}
				}
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	return ioutil.WriteFile(txtPath, b.Bytes(), 0666)
}

func main() {
	jsonPaths := []string{
		"ecdsa_secp224r1_sha224_test.json",
		"ecdsa_secp224r1_sha256_test.json",
		"ecdsa_secp256r1_sha256_test.json",
		"ecdsa_secp384r1_sha384_test.json",
		"ecdsa_secp384r1_sha512_test.json",
		"ecdsa_secp521r1_sha512_test.json",
		"rsa_signature_test.json",
		"x25519_test.json",

		// TODO(davidben): The following tests still need test drivers.
		// "aes_cbc_pkcs5_test.json",
		// "aes_gcm_siv_test.json",
		// "aes_gcm_test.json",
		// "chacha20_poly1305_test.json",
		// "dsa_test.json",
		// "ecdh_test.json",
		// "eddsa_test.json",
	}
	for _, jsonPath := range jsonPaths {
		if !strings.HasSuffix(jsonPath, ".json") {
			panic(jsonPath)
		}
		txtPath := jsonPath[:len(jsonPath)-len(".json")] + ".txt"
		if err := convertWycheproof(jsonPath, txtPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error converting %s: %s\n", jsonPath, err)
			os.Exit(1)
		}
	}
}
