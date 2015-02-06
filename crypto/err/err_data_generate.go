package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// libraryNames must be kept in sync with the enum in err.h. The generated code
// will contain static assertion to enforce this.
var libraryNames = []string{
	"NONE",
	"SYS",
	"BN",
	"RSA",
	"DH",
	"EVP",
	"BUF",
	"OBJ",
	"PEM",
	"DSA",
	"X509",
	"ASN1",
	"CONF",
	"CRYPTO",
	"EC",
	"SSL",
	"BIO",
	"PKCS7",
	"PKCS8",
	"X509V3",
	"RAND",
	"ENGINE",
	"OCSP",
	"UI",
	"COMP",
	"ECDSA",
	"ECDH",
	"HMAC",
	"DIGEST",
	"CIPHER",
	"USER",
	"HKDF",
	"LIBS",
}

type stringTree struct {
	entries         []uint32
	internedStrings map[string]uint32
	stringData      []byte
}

func newStringTree() *stringTree {
	return &stringTree{
		internedStrings: make(map[string]uint32),
	}
}

const offsetMask = 0x7fff

func (st *stringTree) Add(key uint32, value string) error {
	if key&offsetMask != 0 {
		return errors.New("need bottom 15 bits of the key for the offset")
	}
	offset, ok := st.internedStrings[value]
	if !ok {
		offset = uint32(len(st.stringData))
		if offset&offsetMask != offset {
			return errors.New("stringTree overflow")
		}
		st.stringData = append(st.stringData, []byte(value)...)
		st.stringData = append(st.stringData, 0)
		st.internedStrings[value] = offset
	}

	for _, existing := range st.entries {
		if existing>>15 == key>>15 {
			panic("duplicate entry")
		}
	}
	st.entries = append(st.entries, key|offset)
	return nil
}

type keySlice []uint32

func (ks keySlice) Len() int {
	return len(ks)
}

func (ks keySlice) Less(i, j int) bool {
	return (ks[i] >> 15) < (ks[j] >> 15)
}

func (ks keySlice) Swap(i, j int) {
	ks[i], ks[j] = ks[j], ks[i]
}

func writeTree(out *[]uint32, values []uint32) (offset uint16) {
	switch len(values) {
	case 0:
		return 0xffff
	case 1:
		offset = uint16(len(*out))
		*out = append(*out, values[0])
		return offset
	default:
		l := len(*out)
		offset = uint16(l) | 0x8000
		mid := len(values) / 2
		*out = append(*out, values[mid], 0)
		childIndex := l + 1
		leftOffset := writeTree(out, values[:mid])
		rightOffset := writeTree(out, values[mid+1:])
		(*out)[childIndex] = uint32(leftOffset)<<16 | uint32(rightOffset)
		return offset
	}
}

func (st *stringTree) buildTree() []uint32 {
	sort.Sort(keySlice(st.entries))
	out := make([]uint32, 0, len(st.entries))
	writeTree(&out, st.entries)
	return out
}

type stringWriter interface {
	io.Writer
	WriteString(string) (int, error)
}

func (st *stringTree) WriteTo(out stringWriter, name string) {
	tree := st.buildTree()
	fmt.Fprintf(os.Stderr, "%s: %d bytes of tree and %d bytes of string data.\n", name, 4*len(tree), len(st.stringData))

	out.WriteString("static const uint32_t k" + name + "Tree[] = {\n")
	for _, v := range tree {
		fmt.Fprintf(out, "0x%x, ", v)
	}
	out.WriteString("\n};\n\n")

	out.WriteString("static const char k" + name + "StringData[] = \"")
	for i, c := range st.stringData {
		if c == 0 {
			out.WriteString("\\0")
			continue
		}
		out.Write(st.stringData[i : i+1])
	}
	out.WriteString("\";\n\n")
}

type errorData struct {
	functions, reasons *stringTree
	libraryMap         map[string]uint32
}

func (e *errorData) readErrorDataFile(filename string) error {
	inFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	comma := []byte(",")

	lineNo := 0
	for scanner.Scan() {
		lineNo++

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		parts := bytes.Split(line, comma)
		if len(parts) != 4 {
			return fmt.Errorf("bad line %d in %s: found %d values but want 4", lineNo, filename, len(parts))
		}
		libNum, ok := e.libraryMap[string(parts[0])]
		if !ok {
			return fmt.Errorf("bad line %d in %s: unknown library", lineNo, filename)
		}
		if libNum >= 64 {
			return fmt.Errorf("bad line %d in %s: library value too large", lineNo, filename)
		}
		key, err := strconv.ParseUint(string(parts[2]), 10 /* base */, 32 /* bit size */)
		if err != nil {
			return fmt.Errorf("bad line %d in %s: %s", lineNo, filename, err)
		}
		if key >= 2048 {
			return fmt.Errorf("bad line %d in %s: key too large", lineNo, filename)
		}
		value := string(parts[3])

		treeKey := libNum<<26 | uint32(key)<<15

		switch string(parts[1]) {
		case "function":
			err = e.functions.Add(treeKey, value)
		case "reason":
			err = e.reasons.Add(treeKey, value)
		default:
			return fmt.Errorf("bad line %d in %s: bad value type", lineNo, filename)
		}

		if err != nil {
			return err
		}
	}

	return scanner.Err()
}

func main() {
	e := &errorData{
		functions:  newStringTree(),
		reasons:    newStringTree(),
		libraryMap: make(map[string]uint32),
	}
	for i, name := range libraryNames {
		e.libraryMap[name] = uint32(i) + 1
	}

	cwd, err := os.Open(".")
	if err != nil {
		panic(err)
	}
	names, err := cwd.Readdirnames(-1)
	if err != nil {
		panic(err)
	}

	for _, name := range names {
		if !strings.HasSuffix(name, ".errordata") {
			continue
		}
		if err := e.readErrorDataFile(name); err != nil {
			panic(err)
		}
	}

	out := os.Stdout

	out.WriteString(`/* Copyright (c) 2014, Google Inc.
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

 /* This file was generated by err_data_generate.go. */

#include <openssl/base.h>


`)

	e.functions.WriteTo(out, "Function")
	e.reasons.WriteTo(out, "Reason")
}
