package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"

	runner ".."
)

type testConfig struct {
	isServer bool
	port int
	keyFile string
	certFile string
}

var errorMap = map[string]string{
	"ECDSA signature contained zero or negative values": ":BAD_SIGNATURE:",
	"ECDSA verification failure": ":BAD_SIGNATURE:",
	"local error: record overflow": ":DATA_LENGTH_TOO_LONG:",
	"tls: no certificates sent": ":DECODE_ERROR:",
	"local error: bad record MAC": ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	"tls: invalid version in RSA premaster": ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:",
	"tls: client's Finished message is incorrect": ":DIGEST_CHECK_FAILED:",
	"tls: client's Finished message was incorrect": ":DIGEST_CHECK_FAILED:",
	"tls: server's Finished message was incorrect": ":DIGEST_CHECK_FAILED:",
	"tls: renegotiation info sent in TLS 1.3": ":ERROR_PARSING_EXTENSION:",
	"tls: server advertised extended master secret over TLS 1.3": ":ERROR_PARSING_EXTENSION:",
	"remote error: handshake failure": ":HANDSHAKE_FAILURE_ON_CLIENT_HELLO:",
	"tls: fallback SCSV found when not expected": ":INAPPROPRIATE_FALLBACK:",
	"tls: invalid peer key": ":INVALID_ENCODING:",
	"tls: outer record type is not application data": ":INVALID_OUTER_RECORD_TYPE:",
	"tls: KeyShare from HelloRetryRequest not present in new ClientHello": ":MISSING_KEY_SHARE:",
	"tls: server omitted the key share extension": ":MISSING_KEY_SHARE:",
	// TODO(nharper): This one seems wrong
	"remote error: bad certificate": ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	"tls: no common signature algorithms": ":NO_COMMON_SIGNATURE_ALGORITHMS:",
	"tls: unexpected post-handshake message": ":NO_RENEGOTIATION:",
	"tls: no cipher suite supported by both client and server": ":NO_SHARED_CIPHER:",
	"remote error: record overflow": ":TLSV1_ALERT_RECORD_OVERFLOW:",

	// TODO(nharper): Clean up the error here - bogo isn't returning
	// something fine-grained enough, so this is possibly masking
	// errors.
	"local error: unexpected message": ":UNEXPECTED_MESSAGE:UNEXPECTED_RECORD:BAD_ALERT:",

	"missing ServerKeyExchange message": ":UNEXPECTED_MESSAGE:",
	"tls: unexpected ServerKeyExchange": ":UNEXPECTED_MESSAGE:",

	// TODO(nharper): Clean up the error here - bogo doesn't check
	// what kind of other thing it might have received.
	"tls: first record does not look like a TLS handshake": ":UNEXPECTED_RECORD:HTTP_REQUEST:",

	"tls: server selected an unsupported cipher suite": ":UNKNOWN_CIPHER_RETURNED:",
	"tls: ECDHE ECDSA requires a ECDSA server public key": ":WRONG_CERTIFICATE_TYPE:",
	"tls: ECDHE RSA requires a RSA server public key": ":WRONG_CERTIFICATE_TYPE:",
	"tls: server selected an unsupported group": ":WRONG_CURVE:",
	"tls: server selected unsupported curve": ":WRONG_CURVE:",
	"invalid key type for ECDSA": ":WRONG_SIGNATURE_TYPE:",
	// TODO(nharper): Is this one correct?
	"tls: unsupported signature algorithm": "':WRONG_SIGNATURE_TYPE:",
}

var errorRegexes = map[string]string {
	// TODO(nharper): This error message doesn't provide enough
	// detail. I'm probably masking errors here.
	"tls: oversized record received with length \\d+": ":ENCRYPTED_LENGTH_TOO_LONG:HTTPS_PROXY_REQUEST:HTTP_REQUEST:WRONG_VERSION_NUMBER:",
	"tls: received unexpected (handshake )?message of type .* when waiting for .*": ":UNEXPECTED_MESSAGE:",
	"tls: client offered an unsupported, maximum protocol version of [0-9a-f]+": ":UNSUPPORTED_PROTOCOL:",
	"tls: downgrade from .* detected": ":DOWNGRADE_DETECTED:",
	"tls: server sent non-matching version [0-9a-f]+ vs [0-9a-f]+": ":WRONG_VERSION_NUMBER:",
}

// formatError takes an error from the TLS stack and munges it into an
// error string that might be outputted by OpenSSL (so that the test
// runner can match against what this shim outputs).
func formatError(err string) string {
	if out, ok := errorMap[err]; ok {
		return fmt.Sprintf("%s (%s)", out, err)
	}

	for regex, out := range errorRegexes {
		if ok, _ := regexp.MatchString(fmt.Sprintf("^%s$", regex), err); ok {
			return fmt.Sprintf("%s (%s)", out, err)
		}
	}

	return err
}

func main() {
	var config testConfig
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.BoolVar(&config.isServer, "server", false, "")
	flags.IntVar(&config.port, "port", 0, "")
	flags.StringVar(&config.keyFile, "key-file", "", "")
	flags.StringVar(&config.certFile, "cert-file", "", "")

	if flags.Parse(os.Args[1:]) != nil {
		os.Exit(89)
	}

	err := doExchange(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", formatError(err.Error()))
		os.Exit(1)
	}
}

func doExchange(config testConfig) error {
	runnerConfig := &runner.Config{}
	var conn *runner.Conn
	netConn, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: config.port})
	if err != nil {
		return err
	}
	defer netConn.Close()
	if config.isServer {
		cert, err := runner.LoadX509KeyPair(config.certFile, config.keyFile)
		if err != nil {
			return err
		}
		runnerConfig.Certificates = []runner.Certificate{cert}

		conn = runner.Server(netConn, runnerConfig)
	} else {
		runnerConfig.InsecureSkipVerify = true
		conn = runner.Client(netConn, runnerConfig)
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	for {
		buf := make([]byte, 16384)
		n, err := conn.Read(buf[:512])
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		for i := 0; i < n; i++ {
			buf[i] ^= 0xff
		}
		writer := bufio.NewWriter(conn)
		if _, err := writer.Write(buf[:n]); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
	return nil
}
