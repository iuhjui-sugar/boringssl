package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	runner ".."
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

func PrintConnectionInfo(tls_conn *runner.Conn) {
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
	fmt.Fprintf(os.Stderr, "  Version: %s\n", version)
	resumed := "no"
	if state.DidResume {
		resumed = "yes"
	}
	fmt.Fprintf(os.Stderr, "  Resumed session: %s\n", resumed)
	fmt.Fprintf(os.Stderr, "  Cipher: %04x\n", state.CipherSuite)
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

func nc(conn io.ReadWriter) {
	writer := make(chan error)
	reader := make(chan error)
	go copyStream(conn, os.Stdin, writer)
	go copyStream(os.Stdout, conn, reader)
	select {
	case e := <-writer:
		if e != nil {
			fmt.Fprintf(os.Stderr, "Received error writing: %v\n", e)
		}
	case e := <-reader:
		if e != nil {
			fmt.Fprintf(os.Stderr, "Received error reading: %v\n", e)
		}
	}
}

func main() {
	tools := []Tool{
		Tool{Server, "server"},
		Tool{Client, "client"},
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

func Server(args map[string]string) {
	if args["accept"] == "" || args["key"] == "" {
		fmt.Fprintf(os.Stderr, "Missing -accept or -key flag\n")
		os.Exit(1)
	}
	port, err := strconv.Atoi(args["accept"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid arg (%s) to -accept: %s\n", args["accept"], err)
		os.Exit(1)
	}
	var server_cert_file = args["key"]
	var server_key_file = args["key"]

	conn, err := accept(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening: %s\n", err)
		os.Exit(1)
	}

	var config runner.Config
	cert, err := runner.LoadX509KeyPair(server_cert_file, server_key_file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading cert: %s\n", err)
		os.Exit(1)
	}
	config.Certificates = []runner.Certificate{cert}
	tls_conn := runner.Server(conn, &config)
	err = tls_conn.Handshake()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error handshaking: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Connected.\n")
	PrintConnectionInfo(tls_conn)

	nc(tls_conn)
}

func Client(args map[string]string) {
	if _, present := args["connect"]; !present {
		fmt.Fprintf(os.Stderr, "Missing -connect host:port flag\n")
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", args["connect"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %s\n", err)
		os.Exit(1)
	}

	var config = runner.Config{
		InsecureSkipVerify: true,
	}
	tls_conn := runner.Client(conn, &config)
	err = tls_conn.Handshake()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error handshaking: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Connected.\n")
	PrintConnectionInfo(tls_conn)

	nc(tls_conn)
}
