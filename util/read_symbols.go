// Copyright (c) 2018, Google Inc.
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

// read_symbols.go scans one or more .a files and, for each object contained in
// the .a files, reads the list of symbols in that object file.
package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

var outFlag = flag.String("out", "-", "File to write output symbols")

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-out OUT] <archive file> [<archive file> [...]]\n", os.Args[0])
		os.Exit(1)
	}
	archiveFiles := flag.Args()

	out := os.Stdout
	if *outFlag != "-" {
		var err error
		out, err = os.Create(*outFlag)
		nilOrPanic(err, "failed to open output file")
		defer out.Close()
	}

	var symbols []string
	// Only add first instance of any symbol; keep track of them in this map.
	added := make(map[string]bool)
	for _, archive := range archiveFiles {
		f, err := os.Open(archive)
		nilOrPanic(err, "failed to open archive file %s", archive)
		objectFiles, err := parseAR(f)
		nilOrPanic(err, "failed to read archive file %s", archive)

		for name, contents := range objectFiles {
			if !strings.HasSuffix(name, ".o") {
				continue
			}
			for _, s := range listSymbols(name, contents) {
				if !added[s] {
					added[s] = true
					symbols = append(symbols, s)
				}
			}
		}
	}
	sort.Strings(symbols)
	for _, s := range symbols {
		// Filter out C++ mangled names.
		//
		// TODO(joshlf): Figure out a better way to do this
		if !strings.Contains(s, "$") {
			fmt.Fprintln(out, s)
		}
	}
}

// listSymbols lists the exported symbols from an object file.
func listSymbols(name string, contents []byte) []string {
	switch runtime.GOOS {
	case "linux":
		return listSymbolsElf(name, contents)
	case "darwin":
		return listSymbolsMachO(name, contents)
	default:
		panic(fmt.Errorf("unsupported OS %v", runtime.GOOS))
	}
}

func listSymbolsElf(name string, contents []byte) []string {
	f, err := elf.NewFile(bytes.NewReader(contents))
	nilOrPanic(err, "failed to parse ELF file %s", name)
	syms, err := f.Symbols()
	nilOrPanic(err, "failed to read symbol names from ELF file %s", name)

	var names []string
	for _, sym := range syms {
		// Only include exported, defined symbols
		if elf.ST_BIND(sym.Info) != elf.STB_LOCAL && sym.Section != elf.SHN_UNDEF {
			names = append(names, sym.Name)
		}
	}
	return names
}

func listSymbolsMachO(name string, contents []byte) []string {
	f, err := macho.NewFile(bytes.NewReader(contents))
	nilOrPanic(err, "failed to parse Mach-O file %s", name)
	if f.Symtab == nil {
		return nil
	}
	var names []string
	for _, sym := range f.Symtab.Syms {
		// Source: https://opensource.apple.com/source/xnu/xnu-3789.51.2/EXTERNAL_HEADERS/mach-o/nlist.h.auto.html
		const (
			N_PEXT uint8 = 0x10 // Private external symbol bit
			N_EXT  uint8 = 0x01 // External symbol bit, set for external symbols
			N_TYPE uint8 = 0x0e // mask for the type bits

			N_UNDF uint8 = 0x0 // undefined, n_sect == NO_SECT
			N_ABS  uint8 = 0x2 // absolute, n_sect == NO_SECT
			N_SECT uint8 = 0xe // defined in section number n_sect
			N_PBUD uint8 = 0xc // prebound undefined (defined in a dylib)
			N_INDR uint8 = 0xa // indirect
		)

		// Only include exported, defined symbols.
		if sym.Type&N_EXT != 0 && sym.Type&N_TYPE != N_UNDF {
			if len(sym.Name) == 0 || sym.Name[0] != '_' {
				panic(fmt.Errorf("unexpected symbol without underscore prefix: %v", sym.Name))
			}
			names = append(names, sym.Name[1:])
		}
	}
	return names
}

func nilOrPanic(err error, f string, args ...interface{}) {
	if err != nil {
		panic(fmt.Errorf(f+": %v", append(args, err)...))
	}
}

// parseAR parses an archive file from r and returns a map from filename to
// contents, or else an error.
func parseAR(r io.Reader) (map[string][]byte, error) {
	// See https://en.wikipedia.org/wiki/Ar_(Unix)#File_format_details
	const expectedMagic = "!<arch>\n"
	var magic [len(expectedMagic)]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if string(magic[:]) != expectedMagic {
		return nil, errors.New("ar: not an archive file")
	}

	const filenameTableName = "//"
	const symbolTableName = "/"
	var longFilenameTable []byte
	ret := make(map[string][]byte)

	for {
		var header [60]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.New("ar: error reading file header: " + err.Error())
		}

		name := strings.TrimRight(string(header[:16]), " ")
		sizeStr := strings.TrimRight(string(header[48:58]), "\x00 ")
		size, err := strconv.ParseUint(sizeStr, 10, 64)
		if err != nil {
			return nil, errors.New("ar: failed to parse file size: " + err.Error())
		}

		// File contents are padded to a multiple of two bytes
		storedSize := size
		if storedSize%2 == 1 {
			storedSize++
		}

		contents := make([]byte, storedSize)
		if _, err := io.ReadFull(r, contents); err != nil {
			return nil, errors.New("ar: error reading file contents: " + err.Error())
		}
		contents = contents[:size]

		switch {
		case name == filenameTableName:
			if longFilenameTable != nil {
				return nil, errors.New("ar: two filename tables found")
			}
			longFilenameTable = contents
			continue

		case name == symbolTableName:
			continue

		case len(name) > 1 && name[0] == '/':
			if longFilenameTable == nil {
				return nil, errors.New("ar: long filename reference found before filename table")
			}

			// A long filename is stored as "/" followed by a
			// base-10 offset in the filename table.
			offset, err := strconv.ParseUint(name[1:], 10, 64)
			if err != nil {
				return nil, errors.New("ar: failed to parse filename offset: " + err.Error())
			}
			if offset > uint64((^uint(0))>>1) {
				return nil, errors.New("ar: filename offset overflow")
			}

			if int(offset) > len(longFilenameTable) {
				return nil, errors.New("ar: filename offset out of bounds")
			}

			filename := longFilenameTable[offset:]
			if i := bytes.IndexByte(filename, '/'); i < 0 {
				return nil, errors.New("ar: unterminated filename in table")
			} else {
				filename = filename[:i]
			}

			name = string(filename)

		default:
			name = strings.TrimRight(name, "/")
		}

		// Post-processing for BSD:
		// https://en.wikipedia.org/wiki/Ar_(Unix)#BSD_variant
		//
		// If the name is of the form #1/XXX, XXX identifies the length of the
		// name, and the name itself is stored as a prefix of the data, possibly
		// null-padded.

		var namelen uint
		n, err := fmt.Sscanf(name, "#1/%d", &namelen)
		if err == nil && n == 1 && len(contents) >= int(namelen) {
			name = string(contents[:namelen])
			contents = contents[namelen:]

			// names can be null padded; find the first null (if any)
			var null int
			for ; null < len(name); null++ {
				if name[null] == 0 {
					break
				}
			}
			name = name[:null]
		}

		ret[name] = contents
	}

	return ret, nil
}
