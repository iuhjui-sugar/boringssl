// Copyright (c) 2021, Google Inc.
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

package main

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	toolPath       *string = flag.String("tool", "", "Path to acvptool binary")
	moduleWrappers *string = flag.String("module-wrappers", "", "Comma-separated list of name:path pairs for known module wrappers")
	testsPath      *string = flag.String("tests", "", "Path to JSON file listing tests")
	update         *bool   = flag.Bool("update", false, "If true then write updated outputs")
)

type invocation struct {
	toolPath     string
	wrapperPath  string
	inPath       string
	expectedPath string
}

func main() {
	flag.Parse()

	if len(*toolPath) == 0 {
		log.Fatal("-tool must be given")
	}

	if len(*moduleWrappers) == 0 {
		log.Fatal("-module-wrappers must be given")
	}

	wrappers := make(map[string]string)
	pairs := strings.Split(*moduleWrappers, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if _, ok := wrappers[parts[0]]; ok {
			log.Fatalf("wrapper %q defined twice", parts[0])
		}
		wrappers[parts[0]] = parts[1]
	}

	if len(*testsPath) == 0 {
		log.Fatal("-tests must be given")
	}

	testsFile, err := os.Open(*testsPath)
	if err != nil {
		log.Fatal(err)
	}
	defer testsFile.Close()

	decoder := json.NewDecoder(testsFile)
	var tests []struct {
		Wrapper string
		In      string
		Out     string // Optional, may be empty.
	}
	if err := decoder.Decode(&tests); err != nil {
		log.Fatal(err)
	}

	work := make(chan invocation, runtime.NumCPU())
	var numFailed uint32

	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go worker(&wg, work, &numFailed)
	}

	for _, test := range tests {
		wrapper, ok := wrappers[test.Wrapper]
		if !ok {
			log.Fatalf("wrapper %q not specified on command line", test.Wrapper)
		}
		work <- invocation{
			toolPath:     *toolPath,
			wrapperPath:  wrapper,
			inPath:       test.In,
			expectedPath: test.Out,
		}
	}

	close(work)
	wg.Wait()

	n := atomic.LoadUint32(&numFailed)
	if n > 0 {
		log.Printf("Failed %d tests", n)
		os.Exit(1)
	} else {
		log.Printf("%d ACVP tests matched expectations", len(tests))
	}
}

func worker(wg *sync.WaitGroup, work <-chan invocation, numFailed *uint32) {
	defer wg.Done()

	for test := range work {
		if err := doTest(test); err != nil {
			log.Printf("Test failed for %q: %s", test.inPath, err)
			atomic.AddUint32(numFailed, 1)
		}
	}
}

func doTest(test invocation) error {
	input, err := os.Open(test.inPath)
	if err != nil {
		return fmt.Errorf("Failed to open %q: %s", test.inPath, err)
	}
	defer input.Close()

	tempFile, err := ioutil.TempFile("", "boringssl-check_expected-")
	if err != nil {
		return fmt.Errorf("Failed to create temp file: %s", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	decompressor := bzip2.NewReader(input)
	if _, err := io.Copy(tempFile, decompressor); err != nil {
		return fmt.Errorf("Failed to decompress %q: %s", test.inPath, err)
	}

	cmd := exec.Command(test.toolPath, "-wrapper", test.wrapperPath, "-json", tempFile.Name())
	result, err := cmd.CombinedOutput()
	if err != nil {
		os.Stderr.Write(result)
		return fmt.Errorf("Failed to process %q", test.inPath)
	}

	if len(test.expectedPath) == 0 {
		// This test has variable output and thus cannot be compared against a fixed
		// result.
		return nil
	}

	expected, err := os.Open(test.expectedPath)
	if err != nil {
		if *update {
			writeUpdate(test.expectedPath, result)
		}
		return fmt.Errorf("Failed to open %q: %s", test.expectedPath, err)
	}
	defer expected.Close()

	decompressor = bzip2.NewReader(expected)

	var expectedBuf bytes.Buffer
	if _, err := io.Copy(&expectedBuf, decompressor); err != nil {
		return fmt.Errorf("Failed to decompress %q: %s", test.expectedPath, err)
	}

	if !bytes.Equal(expectedBuf.Bytes(), result) {
		if *update {
			writeUpdate(test.expectedPath, result)
		}
		return fmt.Errorf("Mismatch for %q", test.expectedPath)
	}

	return nil
}

func writeUpdate(path string, contents []byte) {
	if err := ioutil.WriteFile(path, contents, 0644); err != nil {
		log.Printf("Failed to create missing file %q: %s", path, err)
	} else {
		log.Printf("Wrote %q", path)
	}
}
