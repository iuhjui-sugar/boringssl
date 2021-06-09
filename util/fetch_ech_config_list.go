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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	httpsType   = 65 // RRTYPE for HTTPS records.
	httpsKeyECH = 5  // SvcParamKey for "ech".
)

var (
	name             = flag.String("name", "", "The name to look up in DNS. Required.")
	server           = flag.String("server", "8.8.8.8:53", "Comma-separated host and UDP port that defines the DNS server to query.")
	outDir           = flag.String("out-dir", "", "The directory where ECHConfigList values will be written. If unspecified, bytes are hexdumped to stdout.")
	printHTTPSRecord = flag.Bool("print-https-record", false, "If true, hexdump each HTTPS record to stdout without extracting ECHConfigList values.")
)

// dnsQueryForHTTPS queries the DNS server over UDP for any HTTPS records
// associated with |domain|. It scans the response's answers and returns all the
// HTTPS records it finds. It returns an error if any connection steps fail.
func dnsQueryForHTTPS(domain string) ([][]byte, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %s", err)
	}
	defer conn.Close()

	// Domain name must be canonical or message packing will fail.
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	dnsName, err := dnsmessage.NewName(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS name from %q: %s", domain, err)
	}
	question := dnsmessage.Question{
		Name:  dnsName,
		Type:  httpsType,
		Class: dnsmessage.ClassINET,
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{question},
	}
	packedMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack msg: %s", err)
	}

	if _, err = conn.Write(packedMsg); err != nil {
		return nil, fmt.Errorf("failed to send the DNS query: %s", err)
	}

	for {
		response := make([]byte, 512)
		n, err := conn.Read(response)
		if err != nil {
			return nil, fmt.Errorf("failed to read the DNS response: %s", err)
		}
		response = response[:n]

		var p dnsmessage.Parser
		header, err := p.Start(response)
		if err != nil {
			return nil, err
		}
		if !header.Response {
			return nil, errors.New("received DNS message is not a response")
		}
		if header.RCode != dnsmessage.RCodeSuccess {
			return nil, fmt.Errorf("response from DNS has non-success RCode: %s", header.RCode.String())
		}
		if header.ID != 0 {
			return nil, errors.New("received a DNS response with the wrong ID")
		}
		if !header.RecursionAvailable {
			return nil, errors.New("server does not support recursion")
		}
		// Verify that this response answers the question that we asked in the
		// query. If the resolver encountered any CNAMEs, it's not guaranteed
		// that the response will contain a question with the same QNAME as our
		// query. However, RFC8499 Section 4 indicates that in general use, the
		// response's QNAME should match the query, so we will make that
		// assumption.
		q, err := p.Question()
		if err != nil {
			return nil, err
		}
		if q != question {
			return nil, fmt.Errorf("response answers the wrong question: %v", q)
		}
		if q, err = p.Question(); err != dnsmessage.ErrSectionDone {
			return nil, fmt.Errorf("response contains an unexpected question: %v", q)
		}

		var httpsRecords [][]byte
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
				httpsRecords = append(httpsRecords, r.Data)
			default:
				if _, err := p.UnknownResource(); err != nil {
					return nil, err
				}
			}
		}
		return httpsRecords, nil
	}
	panic("unreachable")
}

// extractECHConfigList parses an HTTPS record (draft-ietf-dnsop-svcb-https-05,
// Section 2.2) from |httpsRecord|. If there are syntax errors, it returns an
// error. If the record contains an "ech" SvcParam, it returns the value in
// |echConfigList| and true in |found|.
func extractECHConfigList(httpsRecord []byte) (echConfigList []byte, found bool, err error) {
	reader := cryptobyte.String(httpsRecord)

	var priority uint16
	if !reader.ReadUint16(&priority) {
		return nil, false, errors.New("failed to parse HTTPS record priority")
	}

	// Read the TargetName.
	var dottedDomain string
	for {
		var label cryptobyte.String
		if !reader.ReadUint8LengthPrefixed(&label) {
			return nil, false, errors.New("failed to parse HTTPS record TargetName")
		}
		if label.Empty() {
			break
		}
		dottedDomain += string(label) + "."
	}

	if priority == 0 {
		// TODO(dmcardle) Recursively follow AliasForm records.
		return nil, false, fmt.Errorf("received an AliasForm HTTPS record with TargetName=%q", dottedDomain)
	}

	// Read the SvcParams.
	var lastSvcParamKey uint16
	for svcParamCount := 0; !reader.Empty(); svcParamCount++ {
		var svcParamKey uint16
		var svcParamValue cryptobyte.String
		if !reader.ReadUint16(&svcParamKey) ||
			!reader.ReadUint16LengthPrefixed(&svcParamValue) {
			return nil, false, errors.New("failed to parse HTTPS record SvcParam")
		}
		if svcParamCount > 0 && svcParamKey <= lastSvcParamKey {
			return nil, false, errors.New("malformed HTTPS record contains out-of-order SvcParamKey")
		}
		switch svcParamKey {
		case httpsKeyECH:
			found = true
			echConfigList = svcParamValue
		}
	}
	return echConfigList, found, nil
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	if len(*name) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	httpsRecords, err := dnsQueryForHTTPS(*name)
	if err != nil {
		log.Printf("Error querying %q: %s\n", *name, err)
		os.Exit(1)
	}
	if len(httpsRecords) == 0 {
		log.Println("Zero HTTPS records found in DNS response.")
		os.Exit(1)
	}

	if len(*outDir) > 0 {
		if err = os.Mkdir(*outDir, 0775); err != nil {
			log.Printf("Failed to create out directory %q: %s\n", *outDir, err)
			os.Exit(1)
		}
	}

	var echConfigListCount int
	for i, httpsRecord := range httpsRecords {
		if *printHTTPSRecord {
			fmt.Printf("HTTPS Record %d:\n", i)
			fmt.Print(hex.Dump(httpsRecord))
			continue
		}

		echConfigList, found, err := extractECHConfigList(httpsRecord)
		if err != nil {
			log.Printf("Failed to parse HTTPS record", err)
			os.Exit(1)
		}
		if !found {
			log.Printf("Failed to extract an ECHConfigList from the HTTPS record\n")
			continue
		}
		if len(echConfigList) < 2 {
			// By definition, ECHConfigList begins with a two-byte length prefix, so
			// an empty one is malformed (see draft-ietf-tls-esni-10, Section 4).
			log.Printf("found malformed ECHCOnfigList")
			os.Exit(1)
		}

		if len(*outDir) == 0 {
			fmt.Printf("ECHConfigList %d:\n", echConfigListCount)
			fmt.Print(hex.Dump(echConfigList))
			return
		}

		outFile := path.Join(*outDir, fmt.Sprintf("ech-config-list-%d", echConfigListCount))
		if err = ioutil.WriteFile(outFile, echConfigList, 0644); err != nil {
			log.Printf("Failed to write file: %s\n", err)
			os.Exit(1)
		}
		echConfigListCount++
	}
}
