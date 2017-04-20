// Copyright (c) 2017, Google Inc.
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

// The make_cavp utility generates cipher_test input files from NIST CAVP Known
// Answer Test response (.rsp) files.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	cipher             = flag.String("cipher", "", "The name of the cipher/mode (supported: aes, tdes, gcm). Required.")
	cmdLineLabelStr    = flag.String("extra-labels", "", "Comma-separated list of additional label pairs to add (e.g. 'Cipher=AES-128-CBC,Operation=ENCRYPT')")
	swapIVAndPlaintext = flag.Bool("swap-iv-plaintext", false, "When processing CBC vector files for CTR mode, swap IV and plaintext.")
)

type kvPair struct {
	key, value string
}

type kvPairTransform func(k, v string) []kvPair

// Test generates a FileTest file from a CAVP response file.
type Test struct {
	translations map[kvPair]kvPair
	transform    kvPairTransform
	defaults     map[string]string
	// The character to delimit key-value pairs throughout the file ('=' or ':').
	kvDelim rune
}

func (t *Test) parseKeyValue(s string) (key, value string) {
	if t.kvDelim == 0 {
		i := strings.IndexAny(s, "=:")
		if i != -1 {
			t.kvDelim = rune(s[i])
		}
	}
	if i := strings.IndexRune(s, t.kvDelim); t.kvDelim != 0 && i != -1 {
		key, value = s[:i], s[i+1:]
		if len(value) == 0 || len(strings.TrimSpace(value)) == 0 {
			value = " "
		} else {
			value = strings.TrimSpace(value)
		}
	} else {
		key = s
	}
	key = strings.TrimSpace(key)
	return strings.TrimSpace(key), value
}

func (t *Test) translateKeyValue(key, value string) (string, string) {
	if kv, ok := t.translations[kvPair{key, ""}]; ok {
		if len(kv.value) == 0 && len(value) != 0 {
			return kv.key, value
		}
		return kv.key, kv.value
	}
	if kv, ok := t.translations[kvPair{key, value}]; ok {
		return kv.key, kv.value
	}
	return key, value
}

func printKeyValue(key, value string) {
	if len(value) == 0 {
		fmt.Println(key)
	} else {
		// Omit the value if it is " ", i.e. print "key: ", not "key:  ".
		value = strings.TrimSpace(value)
		fmt.Printf("%s: %s\n", key, value)
	}
}

func (t *Test) generate(r io.Reader, cmdLineLabelStr string) {
	s := bufio.NewScanner(r)

	// Label blocks consist of lines of the form "[key]" or "[key =
	// value]". |labels| holds keys and values of the most recent block
	// of labels.
	var labels map[string]string

	// Auxiliary labels passed as a flag.
	cmdLineLabels := make(map[string]string)
	if len(cmdLineLabelStr) != 0 {
		pairs := strings.Split(cmdLineLabelStr, ",")
		for _, p := range pairs {
			key, value := t.parseKeyValue(p)
			cmdLineLabels[key] = value
		}
	}

	t.kvDelim = 0 // Reset kvDelim for scanning the file.

	// Whether we are in a test or a label section.
	inLabels := false
	inTest := false

	n := 0
	var currentKv map[string]string
	for s.Scan() {
		n++
		line := s.Text()
		l := strings.TrimSpace(line)
		l = strings.SplitN(l, "#", 2)[0] // Trim trailing comments.

		// Blank line.
		if len(l) == 0 {
			if inTest {
				// Fill in missing defaults.
				for k, v := range t.defaults {
					if _, ok := currentKv[k]; !ok {
						printKeyValue(k, v)
					}
				}

				fmt.Println()
			}
			inTest = false
			currentKv = make(map[string]string)
			inLabels = false
			continue
		}

		// Label section.
		if l[0] == '[' {
			if l[len(l)-1] != ']' {
				log.Fatalf("line #%d invalid: %q", n, line)
			}
			if !inLabels {
				labels = make(map[string]string)
				inLabels = true
			}

			k, v := t.parseKeyValue(l[1 : len(l)-1])
			k, v = t.translateKeyValue(k, v)
			if len(k) != 0 {
				labels[k] = v
			}

			continue
		}

		// Repeat the label map at the beginning of each test section.
		if !inTest {
			inTest = true
			for k, v := range cmdLineLabels {
				printKeyValue(k, v)
				currentKv[k] = v
			}
			for k, v := range labels {
				printKeyValue(k, v)
				currentKv[k] = v
			}
		}

		// Look up translation and apply transformation (if any).
		k, v := t.parseKeyValue(l)
		k, v = t.translateKeyValue(k, v)
		kvPairs := []kvPair{{k, v}}
		if t.transform != nil {
			kvPairs = t.transform(k, v)
		}

		for _, kv := range kvPairs {
			k, v := kv.key, kv.value
			if *cipher == "tdes" && k == "Key" {
				v += v + v // Key1=Key2=Key3
			}
			if len(k) != 0 {
				printKeyValue(k, v)
				currentKv[k] = v
			}
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: make_cavp <file 1> [<file 2> ...]")
	flag.PrintDefaults()
}

func maybeSwapIVAndPlaintext(k, v string) []kvPair {
	if *swapIVAndPlaintext {
		if k == "Plaintext" {
			return []kvPair{{"IV", v}}
		} else if k == "IV" {
			return []kvPair{{"Plaintext", v}}
		}
	}
	return []kvPair{{k, v}}
}

// Test generator for different values of the -cipher flag.
var testMap = map[string]Test{
	// Generate cipher_test input file from AESVS .rsp file.
	"aes": Test{
		translations: map[kvPair]kvPair{
			{"ENCRYPT", ""}:    {"Operation", "ENCRYPT"},
			{"DECRYPT", ""}:    {"Operation", "DECRYPT"},
			{"COUNT", ""}:      {"Count", ""},
			{"KEY", ""}:        {"Key", ""}, // AES
			{"PLAINTEXT", ""}:  {"Plaintext", ""},
			{"CIPHERTEXT", ""}: {"Ciphertext", ""},
			{"COUNT", ""}:      {"", ""}, // delete
		},
		transform: maybeSwapIVAndPlaintext,
	},
	// Generate cipher_test input file from TMOVS .rsp file.
	"tdes": Test{
		translations: map[kvPair]kvPair{
			{"ENCRYPT", ""}:    {"Operation", "ENCRYPT"},
			{"DECRYPT", ""}:    {"Operation", "DECRYPT"},
			{"COUNT", ""}:      {"Count", ""},
			{"KEY", ""}:        {"Key", ""}, // AES
			{"PLAINTEXT", ""}:  {"Plaintext", ""},
			{"CIPHERTEXT", ""}: {"Ciphertext", ""},
			{"COUNT", ""}:      {"", ""}, // delete
		},
		transform: maybeSwapIVAndPlaintext,
	},
	// Generate aead_test input file from GCMVS .rsp file.
	"gcm": Test{
		translations: map[kvPair]kvPair{
			{"Keylen", ""}: {"", ""}, // delete
			{"IVlen", ""}:  {"", ""}, // delete
			{"PTlen", ""}:  {"", ""}, // delete
			{"AADlen", ""}: {"", ""}, // delete
			{"Taglen", ""}: {"", ""}, // delete
			{"Count", ""}:  {"", ""}, // delete
			{"Key", ""}:    {"KEY", ""},
			{"IV", ""}:     {"NONCE", ""},
			{"PT", ""}:     {"IN", ""},
			{"AAD", ""}:    {"AD", ""},
			{"Tag", ""}:    {"TAG", ""},
			{"FAIL", ""}:   {"FAILS", " "},
		},
		transform: func(k, v string) []kvPair {
			if k == "FAILS" {
				// FAIL cases only appear in the decrypt rsp files. Skip encryption for
				// these.
				return []kvPair{{"FAILS", " "}, {"NO_SEAL", " "}}
			}
			return []kvPair{{k, v}}
		},
		defaults: map[string]string{
			"IN": " ", // FAIL tests don't have IN
		},
	},
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "no input files\n\n")
		flag.Usage()
		os.Exit(1)
	}

	test, ok := testMap[*cipher]
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid cipher: %q\n\n", *cipher)
		flag.Usage()
		os.Exit(1)
	}

	args := append([]string{"make_cavp"}, os.Args[1:]...)
	fmt.Printf("# Generated by %q\n\n", strings.Join(args, " "))

	for i, p := range flag.Args() {
		f, err := os.Open(p)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		fmt.Printf("# File %d: %s\n\n", i+1, p)
		test.generate(f, *cmdLineLabelStr)
	}
}
