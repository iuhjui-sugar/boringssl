package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"sync"

	"boringssl.googlesource.com/boringssl/ssl/test/runner"
)

const (
	outDir = "ech-keys"
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
	ECHTester()
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
	host               string
	useOldKeys         bool
	clientGrease       bool
	port               int
	serverKeyFile      string
	serverCertFile     string
	writeECHConfigAndKey bool
	publicName         string
	serverMode         bool
	clientMode         bool
	echConfigOutFile   string
}

func ECHTester() {
	var args ToolArgs
	flag.StringVar(&args.host, "host", "", "Host to listen on (or connect to)")
	flag.IntVar(&args.port, "port", 0, "Port that server listens on (or connect to)")
	flag.StringVar(&args.serverKeyFile, "key", "", "Path to the server's private key file")
	flag.StringVar(&args.serverCertFile, "cert", "", "Path to the server's cert file")
	flag.BoolVar(&args.useOldKeys, "useOldKeys", false, "When set, simulates client with old ECH keys")
	flag.BoolVar(&args.clientGrease, "clientGrease", false, "When set, simulates client with no ECH keys (sends GREASE)")
	flag.BoolVar(&args.writeECHConfigAndKey, "writeECHConfigAndKey", false, "When set, tool will generate an ECHConfig and private key files for the specified public name")
	flag.StringVar(&args.echConfigOutFile, "echConfigOutFile", "", "When non-empty, tool will write serialized ECH to this file")
	flag.BoolVar(&args.serverMode, "serverMode", false, "When set, tool will run a server")
	flag.BoolVar(&args.clientMode, "clientMode", false, "When set, tool will run a client")
	flag.StringVar(&args.publicName, "publicName", "", "The public name for the generated ECHConfig")
	flag.Parse()

	fmt.Printf("Invoked with args: %#v\n", args)

	echConfig, echPrivateKey, err := runner.GenerateECHConfigAndPrivateKey(args.publicName)
	if err != nil {
		panic(err)
	}

	// Write an ECHConfig and private key to the out directory.
	if args.writeECHConfigAndKey {
		fileBaseName := path.Join(outDir, args.echConfigOutFile)
		if len(args.echConfigOutFile) == 0 {
			panic("must specify non-empty -echConfigOutFile")
		}
		_ = os.Mkdir(outDir, 0744)
		err = ioutil.WriteFile(fmt.Sprintf("%s", fileBaseName), echConfig.Marshal(), 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(fmt.Sprintf("%s.priv", fileBaseName), echPrivateKey, 0644)
		if err != nil {
			panic(err)
		}
		return
	}

	var wg sync.WaitGroup
	msg_chan := make(chan testerMsg)

	if args.serverMode {
		wg.Add(1)
		go Server(&wg, msg_chan, echConfig, echPrivateKey, args)
	}

	if args.clientMode {
		wg.Add(1)
		go Client(&wg, msg_chan, echConfig, args)
	}

	wg.Add(1)
	go func() {
		for msg := range msg_chan {
			fmt.Fprint(os.Stderr, msg.msg)
			if msg.err != nil {
				// Don't kill the whole process just because one
				// server instance had an error
				fmt.Fprintf(os.Stderr, "%s\n", msg.err)
			}
		}
		wg.Done()
	}()

	wg.Wait()
	close(msg_chan)
}

func Server(wg *sync.WaitGroup, msg_chan chan testerMsg, echConfig *runner.EchConfig, echPrivateKey []byte, args ToolArgs) {
	defer wg.Done()

	if len(args.host) == 0 || args.port == 0 || len(args.serverKeyFile) == 0 || len(args.serverCertFile) == 0 {
		fmt.Println("Server requires host, port, serverKeyFile, and serverCertFile")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", args.host, args.port))
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error listening on port"), err: err}
		return
	}

	for {
		conn, err := listener.Accept()
		wg.Add(1)

		// Spawn connection handler
		go func() {
			defer wg.Done()

			msg_chan <- testerMsg{msg: "[server] accepted new conn\n"}

			if err != nil {
				msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error listening: %s\n", err), err: err}
				return
			}
			msg_chan <- testerMsg{msg: "[server] passed accept\n"}

			config := runner.Config{
				EchEnabled: true,
				EchConfigs: []runner.EchConfig{*echConfig},
				MinVersion: runner.VersionTLS13,
				MaxVersion: runner.VersionTLS13,
				ServerName: "foo.bar.example",
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
		}()
	}
}

func Client(wg *sync.WaitGroup, msg_chan chan testerMsg, echConfig *runner.EchConfig, args ToolArgs) {
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
		var err error
		echConfig, _, err = runner.GenerateECHConfigAndPrivateKey("foo.example")
		if err != nil {
			panic(err)
		}
	}

	if args.clientGrease {
		echConfig = nil
	}

	msg_chan <- testerMsg{msg: "[client] passed net.Dial\n"}

	var config = runner.Config{
		InsecureSkipVerify: true,
		MinVersion:         runner.VersionTLS13,
		MaxVersion:         runner.VersionTLS13,
		EchEnabled:         true,
		EchConfigs:         []runner.EchConfig{*echConfig},
		ServerName:         "foo.bar.example",
		Bugs: runner.ProtocolBugs {
			DisableDelegatedCredentials: true,
		},
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
