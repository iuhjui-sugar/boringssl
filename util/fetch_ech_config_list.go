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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	httpsType             = 65 // RRTYPE for HTTPS records.
	httpsKeyECHConfigList = 5  // SvcParamKey for ECHConfigList
)

var (
	flagName             = flag.String("name", "", "The name to look up in DNS. Required.")
	flagServer           = flag.String("server", "8.8.8.8:53", "Comma-separated host and UDP port that defines the DNS server to query.")
	flagOutFile          = flag.String("out-file", "", "The file path where the ECHConfigList will be written. If unspecified, bytes are hexdumped to stdout.")
	flagPrintHTTPSRecord = flag.Bool("print-https-record", false, "If true, hexdump the HTTPS record to stdout and exit without extracting the ECHConfigList.")
)

// dnsQueryForHTTPS queries the DNS server over UDP for any HTTPS records
// associated with |domain|. It scans the response's answers and returns the
// first HTTPS record it finds. Returns an error if any connection steps fail or
// if the response does not contain any HTTPS records.
func dnsQueryForHTTPS(domain string) ([]byte, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", *flagServer)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %s", err)
	}
	defer conn.Close()

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0xbeef,
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              0,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain),
				Type:  httpsType,
				Class: dnsmessage.ClassINET,
			}},
		Answers:     []dnsmessage.Resource{},
		Authorities: []dnsmessage.Resource{},
		Additionals: []dnsmessage.Resource{},
	}
	packedMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack msg: %s", err)
	}

	_, err = conn.Write(packedMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to send the DNS query: %s", err)
	}

	response := make([]byte, 512)
	_, err = conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read the DNS response: %s", err)
	}

	var p dnsmessage.Parser
	if _, err := p.Start(response); err != nil {
		return nil, err
	}
	for {
		_, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	// Return the first HTTPS record present in the answers section.
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}

		switch h.Type {
		case httpsType:
			// This should continue to work when golang.org/x/net/dns/dnsmessage
			// adds support for HTTPS records.
			r, err := p.UnknownResource()
			if err != nil {
				return nil, err
			}
			return r.Data, nil
		default:
			p.SkipAnswer()
		}
	}
	return nil, errors.New("dns response did not contain any HTTPS records")
}

// extractECHConfigList parses an HTTPS record (draft-ietf-dnsop-svcb-https-05)
// from |httpsRecord| and returns the bytes of the "ech" SvcParam, which we
// expect to be a valid ECHConfigList. If the SvcParam is not present, it
// returns an error.
func extractECHConfigList(httpsRecord []byte) ([]byte, error) {
	reader := bytes.NewReader(httpsRecord)

	var priority uint16
	err := binary.Read(reader, binary.BigEndian, &priority)
	if err != nil {
		return nil, err
	}

	// Read the TargetName.
	for {
		var labelLen uint8
		err := binary.Read(reader, binary.BigEndian, &labelLen)
		if err != nil {
			return nil, err
		}
		if labelLen == 0 {
			break
		}
		_, err = reader.Seek(int64(labelLen), io.SeekCurrent)
		if err != nil {
			return nil, err
		}
	}

	// Read the SvcParams.
	var extractedECHConfigList []byte
	for reader.Len() > 0 {
		var svcParamKey uint16
		err := binary.Read(reader, binary.BigEndian, &svcParamKey)
		if err != nil {
			return nil, err
		}
		var svcParamValueLen uint16
		err = binary.Read(reader, binary.BigEndian, &svcParamValueLen)
		if err != nil {
			return nil, err
		}
		svcParamValue := make([]byte, svcParamValueLen)
		n, err := reader.Read(svcParamValue)
		if err != nil {
			return nil, err
		}
		if n != int(svcParamValueLen) {
			err = fmt.Errorf("short read while parsing SvcParamValue for SvcParamKey %d", svcParamKey)
			return nil, err
		}
		if svcParamKey == httpsKeyECHConfigList {
			extractedECHConfigList = svcParamValue
		}
	}
	if extractedECHConfigList != nil {
		return extractedECHConfigList, nil
	}
	err = errors.New("no ECHConfigList found in HTTPS record")
	return nil, err
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	if len(*flagName) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	httpsRecord, err := dnsQueryForHTTPS(*flagName)
	if err != nil {
		log.Printf("Error querying %q: %s\n", *flagName, err)
		os.Exit(1)
	}

	if *flagPrintHTTPSRecord {
		fmt.Print(hex.Dump(httpsRecord))
		return
	}

	echConfigList, err := extractECHConfigList(httpsRecord)
	if err != nil {
		log.Printf("Failed to extract an ECHConfigList from the HTTPS record: %s\n", err)
		os.Exit(1)
	}

	if len(*flagOutFile) == 0 {
		fmt.Print(hex.Dump(echConfigList))
		return
	}

	err = ioutil.WriteFile(*flagOutFile, echConfigList, 0644)
	if err != nil {
		log.Println("Failed to write file:", err)
		os.Exit(1)
	}
}
