// Copyright (c) 2014, Google Inc.
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

// This package generates chacha_vec_arm.S from chacha_vec.c. Install the
// arm-linux-gnueabihf-gcc compiler as described in BUILDING.md. Then:
// `(cd crypto/chacha && go run chacha_vec_arm_generate.go)`.

package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
)

const defaultCompiler = "/opt/gcc-linaro-4.9-2014.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc"

func main() {
	compiler := defaultCompiler
	if len(os.Args) > 1 {
		compiler = os.Args[1]
	}

	args := []string{
		"-O3",
		"-mcpu=cortex-a8",
		"-mfpu=neon",
		"-fpic",
		"-DASM_GEN",
		"-I", "../../include",
		"-S", "chacha_vec.c",
		"-o", "-",
	}

	output, err := os.OpenFile("chacha_vec_arm.S", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer output.Close()

	output.WriteString(preamble)
	output.WriteString(compiler)
	output.WriteString(" ")
	output.WriteString(strings.Join(args, " "))
	output.WriteString("\n\n#if !defined(OPENSSL_NO_ASM)\n")
	output.WriteString("#if defined(__arm__) || defined(__aarch64__)\n\n")

	cmd := exec.Command(compiler, args...)
	cmd.Stderr = os.Stderr
	asm, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	attr28 := []byte(".eabi_attribute 28,")
	globalDirective := []byte(".global\t")
	newLine := []byte("\n")
	attr28Handled := false

	scanner := bufio.NewScanner(asm)
	for scanner.Scan() {
		line := scanner.Bytes()

		if bytes.Contains(line, attr28) {
			output.WriteString(attr28Block)
			attr28Handled = true
			continue
		}

		output.Write(line)
		output.Write(newLine)

		if i := bytes.Index(line, globalDirective); i >= 0 {
			output.Write(line[:i])
			output.WriteString(".hidden\t")
			output.Write(line[i+len(globalDirective):])
			output.Write(newLine)
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	if !attr28Handled {
		panic("EABI attribute 28 not seen in processing")
	}

	if err := cmd.Wait(); err != nil {
		panic(err)
	}

	output.WriteString(trailer)
}

const preamble = `# Copyright (c) 2014, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This file contains a pre-compiled version of chacha_vec.c for ARM. This is
# needed to support switching on NEON code at runtime. If the whole of OpenSSL
# were to be compiled with the needed flags to build chacha_vec.c, then it
# wouldn't be possible to run on non-NEON systems.
#
# This file was generated by chacha_vec_arm_generate.go using the following
# compiler command:
#
#     `

const attr28Block = `
# EABI attribute 28 sets whether VFP register arguments were used to build this
# file. If object files are inconsistent on this point, the linker will refuse
# to link them. Thus we report whatever the compiler expects since we don't use
# VFP arguments.

#if defined(__ARM_PCS_VFP)
	.eabi_attribute 28, 1
#else
	.eabi_attribute 28, 0
#endif

`

const trailer = `
#endif  /* __arm__ || __aarch64__ */
#endif  /* !OPENSSL_NO_ASM */
`
