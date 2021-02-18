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

package runner

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"
)

func TestAll(t *testing.T) {
	main()
}

func cleanHexdump(dump string) string {
	re, err := regexp.Compile("[0-9A-F]{2}")
	if err != nil {
		panic(err)
	}
	cleaned := re.FindAll([]byte(dump), -1)

	var out string
	for _, hexByte := range cleaned {
		out += string(hexByte)
	}

	return out
}

func hexdumpToCHOAAD(dump string) {
	cleanDump := cleanHexdump(dump)

	data, err := hex.DecodeString(cleanHexdump(cleanDump))
	if err != nil {
		panic(err)
	}

	//bogusPrefix := []byte{42, 42, 42, 42}
	//data = append(bogusPrefix, data...)

	fmt.Println("data: ", hex.Dump(data))

	var choaad clientECH
	if !choaad.unmarshal(data) {
		panic("failed to parse")
	}
	fmt.Printf("CHOAAD: %v\n", choaad)
}

func Disabled_TestTmp(t *testing.T) {
	clientDump := `
00 01 00 01 08 51 7c e5  8e 2f d7 33 17 00 20 a6
74 44 e8 54 23 2b ca f1  09 09 2d 3e a0 60 08 82
87 1a 42 a6 31 51 0d 9a  2f 7a 02 73 90 d5 77 00
00 f8 03 03 db d5 93 f9  a7 94 d9 f5 cb e7 22 19
9e a2 36 61 58 e8 0d ec  38 c9 d3 b3 51 b8 77 2a
1a 14 45 8e 20 ec 64 ba  5e 16 47 85 c4 69 1e 26
4a 88 21 67 f8 70 b2 af  2c ae 1f 52 39 d5 f2 88
03 c1 b6 3e 03 00 24 13  01 13 02 13 03 c0 2b c0
2f c0 2c c0 30 cc a9 cc  a8 c0 09 c0 13 c0 0a c0
14 00 9c 00 9d 00 2f 00  35 00 0a 01 00 00 8b 00
00 00 13 00 11 00 00 0e  70 75 62 6c 69 63 2e 65
78 61 6d 70 6c 65 00 17  00 00 ff 01 00 01 00 00
0a 00 08 00 06 00 1d 00  17 00 18 00 0b 00 02 01
00 00 23 00 00 00 0d 00  14 00 12 04 03 08 04 04
01 05 03 08 05 05 01 08  06 06 01 02 01 00 33 00
26 00 24 00 1d 00 20 2c  2e bf bd 1b c6 f7 cc 09
db 3a 60 d2 c5 19 33 e4  db 03 e3 93 60 a9 24 b7
33 66 b7 ef d9 4c 1f 00  2d 00 02 01 01 00 2b 00
09 08 03 04 03 03 03 02  03 01
`

	bogoServerDump := `
00 01 00 01 08 51 7c e5  8e 2f d7 33 17 00 20 a6
74 44 e8 54 23 2b ca f1  09 09 2d 3e a0 60 08 82
87 1a 42 a6 31 51 0d 9a  2f 7a 02 73 90 d5 77 00
00 f8 03 03 db d5 93 f9  a7 94 d9 f5 cb e7 22 19
9e a2 36 61 58 e8 0d ec  38 c9 d3 b3 51 b8 77 2a
1a 14 45 8e 20 ec 64 ba  5e 16 47 85 c4 69 1e 26
4a 88 21 67 f8 70 b2 af  2c ae 1f 52 39 d5 f2 88
03 c1 b6 3e 03 00 24 13  01 13 02 13 03 c0 2b c0
2f c0 2c c0 30 cc a9 cc  a8 c0 09 c0 13 c0 0a c0
14 00 9c 00 9d 00 2f 00  35 00 0a 01 00 00 8b 00
00 00 13 00 11 00 00 0e  70 75 62 6c 69 63 2e 65
78 61 6d 70 6c 65 00 17  00 00 ff 01 00 01 00 00
0a 00 08 00 06 00 1d 00  17 00 18 00 0b 00 02 01
00 00 23 00 00 00 0d 00  14 00 12 04 03 08 04 04
01 05 03 08 05 05 01 08  06 06 01 02 01 00 33 00
26 00 24 00 1d 00 20 b9  f1 20 3d 83 5f 5b d5 93
4c 05 88 ca f9 99 6d d2  89 fe 4f 99 10 20 ef bf
6e b3 78 d4 9a c9 28 00  2d 00 02 01 01 00 2b 00
09 08 03 04 03 03 03 02  03 01
`

	fmt.Println("***** Client")
	hexdumpToCHOAAD(clientDump)

	fmt.Println("***** BoGo")
	hexdumpToCHOAAD(bogoServerDump)
}
