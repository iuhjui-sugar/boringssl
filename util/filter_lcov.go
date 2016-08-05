// Copyright (c) 2016, Google Inc.
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

// filter_lcov rewrites an LCOV trace file, canonicalizing file paths and
// discarding those which do not correspond to a project file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	srcFlag   = flag.String("src", ".", "the path to source directory")
	buildFlag = flag.String("build", "build", "the path to build directory")
	inFlag    = flag.String("in", "coverage.info", "the path to the input LCOV file")
	outFlag   = flag.String("out", "coverage-filtered.info", "the path to the output LCOV file")
)

func main() {
	flag.Parse()

	buildDir, err := filepath.Abs(*buildFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error canonicalizing %q: %s.\n", *buildFlag, err)
		os.Exit(1)
	}

	srcDir, err := filepath.Abs(*srcFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error canonicalizing %q: %s.\n", *srcFlag, err)
		os.Exit(1)
	}
	if runtime.GOOS == "windows" {
		srcDir = strings.ToLower(srcDir)
	}

	inFile, err := os.Open(*inFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %s.\n", *inFlag, err)
		os.Exit(1)
	}
	defer inFile.Close()

	outFile, err := os.Create(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening %s: %s.\n", *outFlag, err)
		os.Exit(1)
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	var skipSection bool
	for scanner.Scan() {
		line := scanner.Text()

		// SF lines denote the start of a new section.
		if strings.HasPrefix(line, "SF:") {
			path := line[3:]

			// Debug symbols from cmake end up using relative paths,
			// so canonicalize and make paths absolute.
			if !filepath.IsAbs(path) {
				path = filepath.Join(buildDir, path)
			}
			path = filepath.Clean(path)

			if runtime.GOOS == "windows" {
				path = strings.ToLower(path)
			}

			// Discard everything outside the source directory. Note
			// this assumes the build directory is inside the source
			// directory for the generated assembly files.
			if !strings.HasPrefix(path, srcDir) {
				skipSection = true
			}

			// Discard files that do not exist. Debug symbols from
			// some gcc files end up using relative paths, resulting
			// in they appearing to be in the source tree.
			if _, err := os.Stat(path); os.IsNotExist(err) {
				skipSection = true
			}

			// Rewrite the SF line.
			line = "SF:" + path
		}

		if !skipSection {
			_, err := fmt.Fprintf(outFile, "%s\n", line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to %s: %s.\n", *outFlag, err)
				os.Exit(1)
			}
		}

		if line == "end_of_record" {
			skipSection = false
		}
	}

	if scanner.Err() != nil {
		fmt.Fprintf(os.Stderr, "Error reading from %s: %s.\n", *inFlag, scanner.Err())
		os.Exit(1)
	}
}
