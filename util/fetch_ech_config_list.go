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
	httpsType = 65 // RRTYPE for HTTPS records.

	// SvcParamKey codepoints defined in draft-ietf-dnsop-svcb-https-05.
	httpsKeyMandatory     = 0
	httpsKeyALPN          = 1
	httpsKeyNoDefaultALPN = 2
	httpsKeyPort          = 3
	httpsKeyIPV4Hint      = 4
	httpsKeyECH           = 5
	httpsKeyIPV6Hint      = 6
)

var (
	name   = flag.String("name", "", "The name to look up in DNS. Required.")
	server = flag.String("server", "8.8.8.8:53", "Comma-separated host and UDP port that defines the DNS server to query.")
	outDir = flag.String("out-dir", "", "The directory where ECHConfigList values will be written. If unspecified, bytes are hexdumped to stdout.")
)

type httpsRecord struct {
	priority   uint16
	targetName string

	// SvcParams:
	mandatory     []uint16
	alpn          []string
	noDefaultALPN []string
	hasPort       bool
	port          uint16
	ipv4hint      []net.IP
	ech           []byte
	ipv6hint      []net.IP
	unknownParams map[uint16][]byte
}

// string pretty-prints |h| as a multi-line string with bullet points.
func (h *httpsRecord) string() string {
	s := fmt.Sprintf("HTTPS SvcPriority:%d TargetName:%q", h.priority, h.targetName)
	if h.mandatory != nil {
		s += fmt.Sprintf("\n  * mandatory: %v", h.mandatory)
	}
	if h.alpn != nil {
		s += fmt.Sprintf("\n  * alpn: %q", h.alpn)
	}
	if h.noDefaultALPN != nil {
		s += fmt.Sprintf("\n  * no-default-alpn: %v", h.noDefaultALPN)
	}
	if h.hasPort {
		s += fmt.Sprintf("\n  * port: %d", h.port)
	}
	if h.ipv4hint != nil {
		s += fmt.Sprintf("\n  * ipv4hint:")
		for _, address := range h.ipv4hint {
			s += fmt.Sprintf("\n    - %s", address)
		}
	}
	if h.ech != nil {
		s += fmt.Sprintf("\n  * ech: %x", h.ech)
	}
	if h.ipv6hint != nil {
		s += fmt.Sprintf("\n  * ipv6hint:")
		for _, address := range h.ipv6hint {
			s += fmt.Sprintf("\n    - %s", address)
		}
	}
	if h.unknownParams != nil {
		s += "\n  * unknown SvcParams:"
		for key, value := range h.unknownParams {
			s += fmt.Sprintf("\n    - %d: %x", key, value)
		}
	}
	return s
}

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

// parseHTTPSRecord parses an HTTPS record (draft-ietf-dnsop-svcb-https-05,
// Section 2.2) from |raw|. If there are syntax errors, it returns an error.
func parseHTTPSRecord(raw []byte) (httpsRecord, error) {
	reader := cryptobyte.String(raw)

	var priority uint16
	if !reader.ReadUint16(&priority) {
		return httpsRecord{}, errors.New("failed to parse HTTPS record priority")
	}

	// Read the TargetName.
	var dottedDomain string
	for {
		var label cryptobyte.String
		if !reader.ReadUint8LengthPrefixed(&label) {
			return httpsRecord{}, errors.New("failed to parse HTTPS record TargetName")
		}
		if label.Empty() {
			break
		}
		dottedDomain += string(label) + "."
	}

	if priority == 0 {
		// TODO(dmcardle) Recursively follow AliasForm records.
		return httpsRecord{}, fmt.Errorf("received an AliasForm HTTPS record with TargetName=%q", dottedDomain)
	}

	record := httpsRecord{
		priority:   priority,
		targetName: dottedDomain,
	}

	// Read the SvcParams.
	var lastSvcParamKey uint16
	for svcParamCount := 0; !reader.Empty(); svcParamCount++ {
		var svcParamKey uint16
		var svcParamValue cryptobyte.String
		if !reader.ReadUint16(&svcParamKey) ||
			!reader.ReadUint16LengthPrefixed(&svcParamValue) {
			return httpsRecord{}, errors.New("failed to parse HTTPS record SvcParam")
		}
		if svcParamCount > 0 && svcParamKey <= lastSvcParamKey {
			return httpsRecord{}, errors.New("malformed HTTPS record contains out-of-order SvcParamKey")
		}
		lastSvcParamKey = svcParamKey

		switch svcParamKey {
		case httpsKeyMandatory:
			for !svcParamValue.Empty() {
				var key uint16
				if !svcParamValue.ReadUint16(&key) {
					return httpsRecord{}, errors.New("malformed HTTPS record")
				}
				record.mandatory = append(record.mandatory, key)
			}
		case httpsKeyALPN:
			for !svcParamValue.Empty() {
				var alpn cryptobyte.String
				if !svcParamValue.ReadUint8LengthPrefixed(&alpn) {
					return httpsRecord{}, errors.New("malformed HTTPS record")
				}
				record.alpn = append(record.alpn, string(alpn))
			}
		case httpsKeyNoDefaultALPN:
			for !svcParamValue.Empty() {
				var alpn cryptobyte.String
				if !svcParamValue.ReadUint8LengthPrefixed(&alpn) {
					return httpsRecord{}, errors.New("malformed HTTPS record")
				}
				record.noDefaultALPN = append(record.noDefaultALPN, string(alpn))
			}
		case httpsKeyPort:
			record.hasPort = true
			if !svcParamValue.ReadUint16(&record.port) {
				return httpsRecord{}, errors.New("malformed HTTPS record")
			}
		case httpsKeyIPV4Hint:
			for !svcParamValue.Empty() {
				var address []byte
				if !svcParamValue.ReadBytes(&address, 4) {
					return httpsRecord{}, errors.New("malformed HTTPS record")
				}
				record.ipv4hint = append(record.ipv4hint, address)
			}
		case httpsKeyECH:
			record.ech = svcParamValue
		case httpsKeyIPV6Hint:
			for !svcParamValue.Empty() {
				var address []byte
				if !svcParamValue.ReadBytes(&address, 16) {
					return httpsRecord{}, errors.New("malformed HTTPS record")
				}
				record.ipv6hint = append(record.ipv6hint, address)
			}
		default:
			if record.unknownParams == nil {
				record.unknownParams = make(map[uint16][]byte)
			}
			record.unknownParams[svcParamKey] = svcParamValue
		}
	}
	return record, nil
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
	for _, httpsRecord := range httpsRecords {
		record, err := parseHTTPSRecord(httpsRecord)
		if err != nil {
			log.Printf("Failed to parse HTTPS record: %s", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", record.string())
		if record.ech == nil {
			log.Printf("Failed to extract an ECHConfigList from the HTTPS record\n")
			continue
		}
		if len(record.ech) < 2 {
			// By definition, ECHConfigList begins with a two-byte length prefix, so
			// an empty one is malformed (see draft-ietf-tls-esni-10, Section 4).
			log.Printf("found malformed ECHCOnfigList")
			os.Exit(1)
		}

		if len(*outDir) == 0 {
			fmt.Printf("ECHConfigList %d:\n", echConfigListCount)
			fmt.Print(hex.Dump(record.ech))
			return
		}

		outFile := path.Join(*outDir, fmt.Sprintf("ech-config-list-%d", echConfigListCount))
		if err = ioutil.WriteFile(outFile, record.ech, 0644); err != nil {
			log.Printf("Failed to write file: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nWrote extracted ECHConfigList to %q\n", outFile)
		echConfigListCount++
	}
}
