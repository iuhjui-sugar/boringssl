package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

var (
	buildDir = flag.String("build-dir", "build", "Specifies the build directory to push.")
	device   = flag.String("device", "", "Specifies the device or emulator. See adb's -s argument.")
	aarch64  = flag.Bool("aarch64", false, "Build the test runners for aarch64 instead of arm.")
	arm      = flag.Int("arm", 7, "Which arm revision to build for.")
)

func adb(args ...string) error {
	if len(*device) > 0 {
		args = append([]string{"-s", *device}, args...)
	}
	cmd := exec.Command("adb", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func goTool(args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if *aarch64 {
		cmd.Env = append(cmd.Env, "GOARCH=arm64")
	} else {
		cmd.Env = append(cmd.Env, "GOARCH=arm")
		cmd.Env = append(cmd.Env, fmt.Sprintf("GOARM=%d", *arm))
	}
	return cmd.Run()
}

// setWorkingDirectory walks up directories as needed until the current working
// directory is the top of a BoringSSL checkout.
func setWorkingDirectory() {
	for i := 0; i < 64; i++ {
		if _, err := os.Stat("BUILDING.md"); err == nil {
			return
		}
		os.Chdir("..")
	}

	panic("Couldn't find BUILDING.md in a parent directory!")
}

type test []string

func parseTestConfig(filename string) ([]test, error) {
	in, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	decoder := json.NewDecoder(in)
	var result []test
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func main() {
	flag.Parse()
	setWorkingDirectory()

	tests, err := parseTestConfig("util/all_tests.json")
	if err != nil {
		fmt.Printf("Failed to parse input: %s\n", err)
		os.Exit(1)
	}

	// Clear the target directory.
	if err := adb("shell", "rm -Rf /data/local/tmp/boringssl-tmp"); err != nil {
		fmt.Printf("Failed to clear target directory: %s\n", err)
		os.Exit(1)
	}

	seenBinary := make(map[string]struct{})
	binaries := []string{"ssl/test/bssl_shim"}
	files := []string{
		"BUILDING.md",
		"util/all_tests.json",
		"ssl/test/runner/cert.pem",
		"ssl/test/runner/channel_id_key.pem",
		"ssl/test/runner/ecdsa_cert.pem",
		"ssl/test/runner/ecdsa_key.pem",
		"ssl/test/runner/key.pem",
	}
	for _, test := range tests {
		if _, ok := seenBinary[test[0]]; !ok {
			binaries = append(binaries, test[0])
			seenBinary[test[0]] = struct{}{}
		}
		for _, arg := range test[1:] {
			if strings.Contains(arg, "/") {
				files = append(files, arg)
			}
		}
	}

	for i, binary := range binaries {
		fmt.Printf("Pushing %s (%d/%d)...\n", binary, i+1, len(binaries))
		if err := adb("push", "-p", filepath.Join(*buildDir, binary), path.Join("/data/local/tmp/boringssl-tmp/build/", binary)); err != nil {
			fmt.Printf("Failed to push %s: %s\n", binary, err)
			os.Exit(1)
		}
	}

	for i, file := range files {
		fmt.Printf("Pushing %s (%d/%d)...\n", file, i+1, len(files))
		if err := adb("push", "-p", file, path.Join("/data/local/tmp/boringssl-tmp", file)); err != nil {
			fmt.Printf("Failed to push %s: %s\n", file, err)
			os.Exit(1)
		}
	}

	tmpDir, err := ioutil.TempDir("", "boringssl-android")
	if err != nil {
		fmt.Printf("Error making temporary directory: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	fmt.Printf("Building all_tests...\n")
	allTests := filepath.Join(tmpDir, "all_tests")
	if err := goTool("build", "-o", allTests, "util/all_tests.go"); err != nil {
		fmt.Printf("Error building all_tests.go: %s\n", err)
		os.Exit(1)
	}
	if err := adb("push", "-p", allTests, "/data/local/tmp/boringssl-tmp/util/all_tests"); err != nil {
		fmt.Printf("Failed to push all_tests: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Building runner...\n")
	runner := filepath.Join(tmpDir, "runner")
	if err := goTool("test", "-c", "-o", runner, "./ssl/test/runner/"); err != nil {
		fmt.Printf("Error building runner: %s\n", err)
		os.Exit(1)
	}
	if err := adb("push", "-p", runner, "/data/local/tmp/boringssl-tmp/ssl/test/runner/runner"); err != nil {
		fmt.Printf("Failed to push runner: %s\n", err)
		os.Exit(1)
	}

	// Finally, run the tests.
	if err := adb("shell", "cd /data/local/tmp/boringssl-tmp && ./util/all_tests"); err != nil {
		fmt.Printf("Failed to run unit tests: %s\n", err)
		os.Exit(1)
	}
	if err := adb("shell", "cd /data/local/tmp/boringssl-tmp/ssl/test/runner && ./runner"); err != nil {
		fmt.Printf("Failed to run SSL tests: %s\n", err)
		os.Exit(1)
	}
}
