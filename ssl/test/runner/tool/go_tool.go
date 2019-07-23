package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"boringssl.googlesource.com/boringssl/ssl/test/runner"
)

type Tool struct {
	tool func(map[string]string)
	name string
}

func findTool(tools []Tool, name string) *Tool {
	for _, tool := range tools {
		if tool.name == name {
			return &tool
		}
	}
	return nil
}

func readArgs(argList []string) map[string]string {
	args := make(map[string]string)
	haveArg := false
	argName := ""
	for _, arg := range argList {
		if !haveArg {
			for len(arg) > 0 && arg[0] == '-' {
				arg = arg[1:]
			}
			if len(arg) == 0 {
				continue
			}
			if split := strings.SplitN(arg, "=", 2); len(split) == 2 {
				args[split[0]] = split[1]
				continue
			}
			haveArg = true
			argName = arg
		} else {
			args[argName] = arg
			haveArg = false
		}
	}
	return args
}

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
	tools := []Tool{
		Tool{EsniTester, "esni-tester"},
		//Tool{Server, "server"},
		//Tool{Client, "client"},
	}

	var tool *Tool
	if len(os.Args) > 1 {
		tool = findTool(tools, os.Args[1])
	}
	if tool == nil {
		fmt.Printf("Usage: %s COMMAND\n", os.Args[0])
		fmt.Printf("\nAvailable commands:\n")
		for _, tool := range tools {
			fmt.Printf("    %s\n", tool.name)
		}
		os.Exit(1)
	}

	tool.tool(readArgs(os.Args[2:]))
}

func requireArg(args map[string]string, name string) string {
	if args[name] == "" {
		fmt.Fprintf(os.Stderr, "Missing -%s flag", name)
		os.Exit(1)
	}
	return args[name]
}

type testerMsg struct {
	err error
	msg string
}

type keypair struct {
	private *[32]byte
	public  [32]byte
}

func EsniTester(args map[string]string) {
	// Generate keypair

	/*
		var privateKey [32]byte
		_, err := rand.Read(privateKey[:])
		//_, err := io.ReadFull(rand, privateKey[:])
		if err != nil {
			panic(err)
		}
		var publicKey [32]byte
		curve25519.ScalarBaseMult(&publicKey, &privateKey)

		keypair := keypair{private: &privateKey, public: &publicKey}
	*/
	esniKeys, privKeys := runner.GetTestEsniKeys()

	var wg sync.WaitGroup
	wg.Add(3)

	msg_chan := make(chan testerMsg)
	go Server(&wg, msg_chan, esniKeys, privKeys, map[string]string{
		"port": "8080",
		"key":  "../key.pem",
		"cert": "../cert.pem",
	})

	go Client(&wg, msg_chan, esniKeys, map[string]string{
		"connect": "localhost:8080",
	})

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

func Server(wg *sync.WaitGroup, msg_chan chan testerMsg, esniKeys []runner.EsniKeys, privKeys [][32]byte, args map[string]string) {
	defer wg.Done()

	port_str := requireArg(args, "port")
	server_key_file := requireArg(args, "key")
	server_cert_file := requireArg(args, "cert")

	port, err := strconv.Atoi(port_str)
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Invalid arg (%s) to -port: %s\n", port_str, err), err: err}
		return
	}

	conn, err := accept(port)
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error listening: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[server] passed accept\n"}

	config := runner.Config{
		EsniKeys:        esniKeys,
		EsniPrivateKeys: privKeys,
	}
	cert, err := runner.LoadX509KeyPair(server_cert_file, server_key_file)
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

func Client(wg *sync.WaitGroup, msg_chan chan testerMsg, esniKeys []runner.EsniKeys, args map[string]string) {
	defer wg.Done()

	if _, present := args["connect"]; !present {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Missing -connect host:port flag\n")}
		return
	}

	conn, err := net.Dial("tcp", args["connect"])
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Error connecting: %s\n", err), err: err}
		return
	}

	msg_chan <- testerMsg{msg: "[client] passed net.Dial\n"}

	//serverEsniKeys := runner.GetTestEsniKeys()
	//msg_chan <- testerMsg{msg: "[client] passed runner.GetTestEsniKeys\n"}

	var config = runner.Config{
		InsecureSkipVerify:         true,
		EsniKeys:                   esniKeys,
		ServerName:                 "foo.example",
		EsniClientSendRecordDigest: true,
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
