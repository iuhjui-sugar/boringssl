package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	httpsType          = 65 // RRTYPE for HTTPS records.
	httpsKeyECHConfigs = 5  // SvcParamKey for ECHConfigs
)

var (
	flagDomain  = flag.String("domain", "", "Required. Domain whose HTTPS records we will fetch.")
	flagOutFile = flag.String("out-file", "", "File where raw ECHConfigs will be written. If unspecified, bytes are hexdumped to stdout.")
)

// DOHResponse helps parse the JSON response from the Google DoH resolver.
// See https://developers.google.com/speed/public-dns/docs/doh/json.
type DOHResponse struct {
	Status int
	Answer []DOHAnswer
}

type DOHAnswer struct {
	Type int
	Name string
	Data string
	TTL  int
}

// dohQueryHTTPS queries the Google DoH resolver for |domain| returns the
// bytes of the HTTPS record or an error.
func dohQueryHTTPS(domain string) ([]byte, error) {
	url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=TYPE65", domain)
	var body io.Reader
	req, err := http.NewRequest("GET", url, body)
	if err != nil {
		panic(err) // This is an internal error.
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Language", "*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("http request failed:", err)
		return nil, err
	}
	msgBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("failed to read http response:", err)
		return nil, err
	}
	var response DOHResponse
	err = json.Unmarshal(msgBytes, &response)
	if err != nil {
		log.Println("failed to unmarshal JSON response:", err)
		return nil, err
	}
	if response.Status != 0 {
		err = fmt.Errorf("DNS response status (%d) is not NOERROR", response.Status)
		log.Println(err)
		return nil, err
	}

	// Scan the answers section for an HTTPS record.
	for _, answer := range response.Answer {
		if answer.Type != httpsType {
			continue
		}
		// Now that we've found an HTTPS record, extract the bytes from the
		// record's string representation.
		pieces := strings.Fields(answer.Data)
		if len(pieces) < 2 || pieces[0] != "\\#" {
			err = errors.New("bad rdata string for HTTPS record")
			log.Println(err)
			return nil, err
		}
		size, err := strconv.Atoi(pieces[1])
		if err != nil {
			err = errors.New("failed to parse length")
			log.Println(err)
			return nil, err
		}

		var rdata []byte
		for _, chunk := range pieces[2:] {
			decoded, err := hex.DecodeString(chunk)
			if err != nil {
				err = errors.New("failed to decode chunk")
				log.Println(err)
				return nil, err
			}
			rdata = append(rdata, decoded...)
		}
		if size != len(rdata) {
			err = errors.New("incorrect length")
			log.Println(err)
			return nil, err
		}

		fmt.Printf("Found an HTTPS record (TTL=%d) for %s\n", answer.TTL, answer.Name)
		return rdata, nil
	}
	return nil, errors.New("no HTTPS record in DoH response's answers")
}

// extractECHConfigs parses an HTTPS record (draft-ietf-dnsop-svcb-https-02)
// from |httpsRecord| and returns the bytes of the ECHConfigs SvcParam. If the
// SvcParam is not present, returns an error.
func extractECHConfigs(httpsRecord []byte) ([]byte, error) {
	reader := bytes.NewReader(httpsRecord)

	var priority uint16
	err := binary.Read(reader, binary.BigEndian, &priority)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Read the TargetName.
	for {
		var labelLen uint8
		err := binary.Read(reader, binary.BigEndian, &labelLen)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		if labelLen == 0 {
			break
		}
		_, err = reader.Seek(int64(labelLen), io.SeekCurrent)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	}

	// Read the SvcParams.
	var extractedECHConfigs []byte
	for reader.Len() > 0 {
		var svcParamKey uint16
		err := binary.Read(reader, binary.BigEndian, &svcParamKey)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		var svcParamValueLen uint16
		err = binary.Read(reader, binary.BigEndian, &svcParamValueLen)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		svcParamValue := make([]byte, svcParamValueLen)
		n, err := reader.Read(svcParamValue)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		if n != int(svcParamValueLen) {
			err = fmt.Errorf("short read while parsing SvcParamValue for SvcParamKey %d", svcParamKey)
			log.Println(err)
			return nil, err
		}
		if svcParamKey == httpsKeyECHConfigs {
			extractedECHConfigs = svcParamValue
		}
	}
	if extractedECHConfigs != nil {
		return extractedECHConfigs, nil
	}
	err = errors.New("no ECHConfigs found in HTTPS record")
	log.Println(err)
	return nil, err
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	if flagDomain == nil || len(*flagDomain) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	httpsRecord, err := dohQueryHTTPS(*flagDomain)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	echConfigs, err := extractECHConfigs(httpsRecord)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if flagOutFile == nil || len(*flagOutFile) == 0 {
		fmt.Print(hex.Dump(echConfigs))
		return
	}

	err = ioutil.WriteFile(*flagOutFile, echConfigs, 0644)
	if err != nil {
		log.Println("Failed to write file:", err)
	}
}
