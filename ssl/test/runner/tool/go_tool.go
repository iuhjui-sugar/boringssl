package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"boringssl.googlesource.com/boringssl/ssl/test/runner"
)

func PrintConnectionInfo(msg_chan chan testerMsg, tls_conn *runner.Conn) {
	// TODO(nharper): Finish implementing this.
	state := tls_conn.ConnectionState()
	version := "unknown"
	switch state.Version {
	case runner.VersionTLS13:
		version = "TLSv1.3"
	case runner.VersionTLS12:
		version = "TLSv1.2"
	case runner.VersionTLS11:
		version = "TLSv1.1"
	case runner.VersionTLS10:
		version = "TLSv1.0"
	case runner.VersionSSL30:
		version = "SSLv3"
	}
	msg_chan <- testerMsg{msg: fmt.Sprintf("  Version: %s\n", version)}
	resumed := "no"
	if state.DidResume {
		resumed = "yes"
	}
	msg_chan <- testerMsg{msg: fmt.Sprintf("  Resumed session: %s\n", resumed)}
	msg_chan <- testerMsg{msg: fmt.Sprintf("  Cipher: %04x\n", state.CipherSuite)}
}

func accept(port int) (net.Conn, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	return ln.Accept()
}

func copyStream(out io.Writer, in io.Reader, err chan error) {
	_, e := io.Copy(out, in)
	err <- e
}

func nc(prefix string, msg_chan chan testerMsg, conn io.ReadWriter) {
	writer := make(chan error)
	reader := make(chan error)
	go copyStream(conn, os.Stdin, writer)
	go copyStream(os.Stdout, conn, reader)
	select {
	case e := <-writer:
		if e != nil {
			msg_chan <- testerMsg{msg: fmt.Sprintf("[%s] Received error writing: %v\n", prefix, e), err: e}
		}
	case e := <-reader:
		if e != nil {
			msg_chan <- testerMsg{msg: fmt.Sprintf("[%s] Received error reading: %v\n", prefix, e), err: e}
		}
	}
}

func main() {
	EsniTester()
}

type testerMsg struct {
	err error
	msg string
}

type keypair struct {
	private *[32]byte
	public  [32]byte
}

type ToolArgs struct {
	host           string
	useOldKeys     bool
	port           int
	serverKeyFile  string
	serverCertFile string
}

func EsniTester() {
	var args ToolArgs
	flag.StringVar(&args.host, "host", "", "Host to listen on (or connect to)")
	flag.IntVar(&args.port, "port", 0, "Port that server listens on (or connect to)")
	flag.StringVar(&args.serverKeyFile, "key", "", "Path to the server's private key file")
	flag.StringVar(&args.serverCertFile, "cert", "", "Path to the server's cert file")
	flag.BoolVar(&args.useOldKeys, "useOldKeys", false, "When set, simulates client with old ESNI keys")
	flag.Parse()

	fmt.Printf("host = %s\n", args.host)

	esniKeys, privKeys := runner.GetTestEsniKeys()

	var wg sync.WaitGroup
	wg.Add(3)

	msg_chan := make(chan testerMsg)
	go Server(&wg, msg_chan, esniKeys, privKeys, args)
	go Client(&wg, msg_chan, esniKeys, args)

	go func() {
		for msg := range msg_chan {
			fmt.Fprint(os.Stderr, msg.msg)
			if msg.err != nil {
				panic(msg.err)
			}
		}
		wg.Done()
	}()

	wg.Wait()
	close(msg_chan)
}

func Server(wg *sync.WaitGroup, msg_chan chan testerMsg, esniKeys []runner.EsniKeys, privKeys [][32]byte, args ToolArgs) {
	defer wg.Done()

	if len(args.host) == 0 || args.port == 0 || len(args.serverKeyFile) == 0 || len(args.serverCertFile) == 0 {
		fmt.Println("Server requires host, port, serverKeyFile, and serverCertFile")
	}

	conn, err := accept(args.port)
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error listening: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[server] passed accept\n"}

	config := runner.Config{
		EsniKeys:        esniKeys,
		EsniPrivateKeys: privKeys,
		MinVersion:      runner.VersionTLS13,
		MaxVersion:      runner.VersionTLS13,
	}
	cert, err := runner.LoadX509KeyPair(args.serverCertFile, args.serverKeyFile)
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error loading cert: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[server] passed runner.LoadX509KeyPair\n"}
	config.Certificates = []runner.Certificate{cert}
	tls_conn := runner.Server(conn, &config)
	msg_chan <- testerMsg{msg: "[server] passed runner.Server\n"}
	err = tls_conn.Handshake()
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error handshaking: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[server] passed tls_conn.Handshake\n"}

	msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Connected.\n")}
	PrintConnectionInfo(msg_chan, tls_conn)

	nc("server", msg_chan, tls_conn)
}

func Client(wg *sync.WaitGroup, msg_chan chan testerMsg, esniKeys []runner.EsniKeys, args ToolArgs) {
	defer wg.Done()

	if len(args.host) == 0 || args.port == 0 {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Require host and port\n")}
		return
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", args.host, args.port))
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Error connecting: %s\n", err), err: err}
		return
	}

	// Simulate the case where the client has old ESNIKeys
	if args.useOldKeys {
		fmt.Println("USING OLD ESNI KEYS")
		esniKeys, _ = runner.GetTestEsniKeys()
	}

	msg_chan <- testerMsg{msg: "[client] passed net.Dial\n"}

	var config = runner.Config{
		InsecureSkipVerify:         true,
		MinVersion:                 runner.VersionTLS13,
		MaxVersion:                 runner.VersionTLS13,
		EsniKeys:                   esniKeys,
		ServerName:                 "foo.bar.example",
		EsniClientSendRecordDigest: true,
		Bugs:                       runner.ProtocolBugs{EsniSendPlaintextServerName: "oops"},
	}
	tls_conn := runner.Client(conn, &config)
	msg_chan <- testerMsg{msg: "[client] passed runner.Client\n"}
	err = tls_conn.Handshake()
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Error handshaking: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[client] passed tls_conn.Handshake\n"}
	fmt.Fprintf(os.Stderr, "Connected.\n")
	PrintConnectionInfo(msg_chan, tls_conn)

	nc("client", msg_chan, tls_conn)
}
