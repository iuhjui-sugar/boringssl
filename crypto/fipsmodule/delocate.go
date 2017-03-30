package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	arInput := flag.String("a", "", "Path to a .a file")
	outFile := flag.String("o", "", "Path to output assembly")
	asmFiles := flag.String("as", "", "Comma separated list of assembly inputs")

	flag.Parse()

	var lines []string
	var err error
	if len(*arInput) > 0 {
		lines, err = arLines(lines, *arInput)
		if err != nil {
			panic(err)
		}
	}

	asPaths := strings.Split(*asmFiles, ",")
	for _, path := range asPaths {
		lines, err = asLines(lines, path)
		if err != nil {
			panic(err)
		}
	}

	symbols := definedSymbols(lines)
	lines = transform(lines, symbols)

	out, err := os.OpenFile(*outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	for _, line := range lines {
		out.WriteString(line)
		out.WriteString("\n")
	}
}

func isSymbolDef(line string) (string, bool) {
	if len(line) > 0 && line[len(line)-1] == ':' && line[0] != '.' {
		symbol := line[:len(line)-1]
		if alphaNum(symbol) {
			return symbol, true
		}
	}

	return "", false
}

func definedSymbols(lines []string) map[string]bool {
	globalSymbols := make(map[string]struct{})
	symbols := make(map[string]bool)

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		if symbol, ok := isSymbolDef(line); ok {
			_, isGlobal := globalSymbols[symbol]
			symbols[symbol] = isGlobal
		}

		parts := strings.Fields(strings.TrimSpace(line))
		if parts[0] == ".globl" {
			globalSymbols[parts[1]] = struct{}{}
		}
	}

	return symbols
}

func transform(lines []string, symbols map[string]bool) (ret []string) {
	ret = append(ret, ".text", "BORINGSSL_bcm_text_start:")

	redirectors := make(map[string]string)

	for lineNo, line := range lines {
		if symbol, ok := isSymbolDef(line); ok {
			if isGlobal := symbols[symbol]; isGlobal {
				ret = append(ret, symbol+"_local_target:")
			}
		}

		parts := strings.Fields(strings.TrimSpace(line))

		if len(parts) == 0 {
			ret = append(ret, line)
			continue
		}

		switch parts[0] {
		case "call":
			target := parts[1]
			println(target)
			if isGlobal, ok := symbols[target]; ok {
				if isGlobal {
					ret = append(ret, "\tcall "+target+"_local_target")
				} else {
					ret = append(ret, "\tcall "+target)
				}
				continue
			}

			redirectorName := "bcm_redirector_" + target

			if strings.HasSuffix(target, "@PLT") {
				withoutPLT := target[:len(target)-4]
				if isGlobal, ok := symbols[withoutPLT]; ok {
					if isGlobal {
						ret = append(ret, "\tcall "+withoutPLT+"_local_target")
					} else {
						ret = append(ret, "\tcall "+withoutPLT)
					}
					continue
				}

				redirectorName = redirectorName[:len(redirectorName)-4]
			}

			ret = append(ret, "\tcall "+redirectorName)
			redirectors[redirectorName] = target
			continue

		case ".section":
			switch parts[1] {
			case ".data":
				panic(fmt.Sprintf("bad section %q on line %d", parts[1], lineNo+1))
			case ".rodata":
				break
			default:
				ret = append(ret, line)
			}

		default:
			ret = append(ret, line)
		}
	}

	ret = append(ret, "BORINGSSL_bcm_text_end:")

	for redirectorName, target := range redirectors {
		ret = append(ret, ".hidden "+redirectorName)
		ret = append(ret, ".type "+redirectorName+", @function")
		ret = append(ret, redirectorName+":")
		ret = append(ret, "\tjmp "+target)
	}

	return ret
}

func asLines(lines []string, path string) ([]string, error) {
	asFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer asFile.Close()

	scanner := bufio.NewScanner(asFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func arLines(lines []string, arPath string) ([]string, error) {
	arFile, err := os.Open(arPath)
	if err != nil {
		return nil, err
	}
	defer arFile.Close()

	ar := NewAR(arFile)

	for {
		header, err := ar.Next()
		if err == io.EOF {
			return lines, nil
		}
		if err != nil {
			return nil, err
		}

		if !strings.HasSuffix(header.Name, ".o") {
			continue
		}

		scanner := bufio.NewScanner(ar)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
}

func alphaNum(s string) bool {
	if len(s) == 0 {
		return false
	}
	switch {
	case 'a' <= s[0] && s[0] <= 'z':
	case 'A' <= s[0] && s[0] <= 'Z':
	case s[0] == '_':
	default:
		return false
	}

	return strings.IndexFunc(s, func(r rune) bool {
		switch {
		case 'a' <= r && r <= 'z':
		case 'A' <= r && r <= 'Z':
		case '0' <= r && r <= '9':
		case r == '_':
		default:
			return true
		}
		return false
	}) == -1
}

const (
	// the string which begins a proper archive
	arMagic = "!<arch>\n"

	// the magic numbers for individual file headers
	fileMagic = "`\n"

	headerSize = 60
)

// An ARHeader represents a single header in an ar archive.
type ARHeader struct {
	Name    string
	ModTime time.Time
	UID     int
	GID     int
	Mode    os.FileMode
	Size    int64
}

type slicer []byte

func (sp *slicer) next(n int) (b []byte) {
	s := *sp
	b, *sp = s[0:n], s[n:]
	return
}

// A Reader provides sequential access to the contents of an ar archive.
// The Next method advances to the next file in the archive (including
// the first), and then it can be treated as an io.Reader to access the
// file's data.
type AR struct {
	r   io.Reader
	err error
	nb  int64 // number of unread bytes for current file entry
	pad int   // amount of padding after current file entry
}

// NewReader returns a reader for the members of the provided ar archive.
func NewAR(r io.Reader) *AR {
	magiclen := len(arMagic)
	buf := make([]byte, magiclen)
	_, err := io.ReadFull(r, buf)
	if err != nil || arMagic != string(buf) {
		err = fmt.Errorf("ar: bad magic number %v in ar file header", buf)
	}
	return &AR{r: r, err: err}
}

// Next advances the reader to the next file in the archive.
func (ar *AR) Next() (*ARHeader, error) {
	var hdr *ARHeader
	if ar.err == nil {
		ar.skipUnread()
	}
	if ar.err == nil {
		hdr = ar.readHeader()
	}
	return hdr, ar.err
}

func (ar *AR) cvt(b []byte, base int) int64 {
	// Removing leading spaces
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	// Removing trailing NULs and spaces.
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\x00') {
		b = b[:len(b)-1]
	}
	x, err := strconv.ParseUint(string(b), base, 64)
	if err != nil {
		ar.err = err
	}
	return int64(x)
}

// Skip any unused bytes in the existing file entry, as well as any alignment padding.
func (ar *AR) skipUnread() {
	nr := ar.nb + int64(ar.pad)
	ar.nb, ar.pad = 0, 0
	if sr, ok := ar.r.(io.Seeker); ok {
		if _, err := sr.Seek(nr, io.SeekCurrent); err == nil {
			return
		}
	}
	_, ar.err = io.CopyN(ioutil.Discard, ar.r, nr)
}

func (ar *AR) readHeader() *ARHeader {
	var n int
	header := make([]byte, headerSize)
	n, ar.err = io.ReadFull(ar.r, header)
	if ar.err == io.ErrUnexpectedEOF {
		ar.err = fmt.Errorf("ar: short header in ar archive; got %d bytes, want %d", n, headerSize)
	}
	if ar.err != nil {
		// io.EOF will get passed through
		return nil
	}

	hdr := new(ARHeader)
	s := slicer(header)

	hdr.Name = strings.TrimRight(string(s.next(16)), " ")
	hdr.Name = strings.TrimRight(hdr.Name, "/")
	hdr.ModTime = time.Unix(ar.cvt(s.next(12), 10), 0)
	hdr.UID = int(ar.cvt(s.next(6), 10))
	hdr.GID = int(ar.cvt(s.next(6), 10))
	hdr.Mode = os.FileMode(ar.cvt(s.next(8), 8))
	hdr.Size = ar.cvt(s.next(10), 10)
	magic := string(s.next(2))
	if magic != fileMagic {
		ar.err = fmt.Errorf("ar: bad magic number %v in ar member header", magic)
		return nil
	}

	ar.nb = int64(hdr.Size)
	// at most one pad byte just to be even
	ar.pad = int(ar.nb & 1)

	return hdr
}

// Read reads from the current entry in the ar archive.
// It returns 0, io.EOF when it reaches the end of that entry,
// until Next is called to advance to the next entry.
func (ar *AR) Read(b []byte) (n int, err error) {
	if ar.nb == 0 {
		// file consumed
		return 0, io.EOF
	}

	// trim read to the amount available
	if int64(len(b)) > ar.nb {
		b = b[0:ar.nb]
	}

	n, err = ar.r.Read(b)
	ar.nb -= int64(n)
	if err == io.EOF && ar.nb > 0 {
		// archive ended while more file contents expected
		err = io.ErrUnexpectedEOF
	}
	ar.err = err
	return
}
