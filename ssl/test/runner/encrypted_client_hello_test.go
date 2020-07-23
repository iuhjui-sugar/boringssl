// Copyright (c) 2020, Google Inc.
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

package runner

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
)

type testerMsg struct {
	err error
	msg string
}

// Test that BoGo can establish a connection with itself when specifying ECH.
func TestGoSelfInterop(t *testing.T) {
	publicName := "innocuous.example"

	echConfigWithSecret, err := GenerateECHConfigWithSecretKey(publicName)
	if err != nil {
		panic(err)
	}

	publicECHConfig := *echConfigWithSecret
	publicECHConfig.secretKey = nil

	var wg sync.WaitGroup
	msg_chan := make(chan testerMsg)

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error listening on port"), err: err}
		return
	}
	port := listener.Addr().(*net.TCPAddr).Port

	wg.Add(1)
	go echServer(&wg, msg_chan, listener, echConfigWithSecret)

	wg.Add(1)
	go echClient(&wg, msg_chan, port, &publicECHConfig)

	go func(wg *sync.WaitGroup) {
		for msg := range msg_chan {
			fmt.Fprint(os.Stderr, msg.msg)
			if msg.err != nil {
				// Don't kill the whole process just because one
				// server instance had an error
				fmt.Fprintf(os.Stderr, "%s\n", msg.err)
			}
		}
	}(&wg)

	wg.Wait()
	close(msg_chan)
}

// echServer runs a TLS server that accepts ECH and accepts a single connection.
func echServer(wg *sync.WaitGroup, msg_chan chan testerMsg, listener *net.TCPListener, echConfig *EchConfig) {
	defer wg.Done()

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

		config := Config{
			EchEnabled: true,
			EchConfigs: []EchConfig{*echConfig},
			MinVersion: VersionTLS13,
			MaxVersion: VersionTLS13,
			ServerName: "secret.example",
		}
		cert, err := LoadX509KeyPair(rsaCertificateFile, rsaKeyFile)
		if err != nil {
			msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error loading cert: %s\n", err), err: err}
			return
		}
		msg_chan <- testerMsg{msg: "[server] passed LoadX509KeyPair\n"}
		config.Certificates = []Certificate{cert}
		tls_conn := Server(conn, &config)
		msg_chan <- testerMsg{msg: "[server] passed Server\n"}
		err = tls_conn.Handshake()
		if err != nil {
			msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Error handshaking: %s\n", err), err: err}
			return
		}
		msg_chan <- testerMsg{msg: "[server] passed tls_conn.Handshake\n"}

		msg_chan <- testerMsg{msg: fmt.Sprintf("[server] Connected.\n")}

		tls_conn.Close()
	}()
}

// echClient establishes a single TLS connection with ECH to the server.
func echClient(wg *sync.WaitGroup, msg_chan chan testerMsg, port int, echConfig *EchConfig) {
	defer wg.Done()
	defer fmt.Println("exiting echClient")

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv6loopback, Port: port})
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Error connecting: %s\n", err), err: err}
		return
	}

	msg_chan <- testerMsg{msg: "[client] passed net.Dial\n"}

	var config = Config{
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS13,
		MaxVersion:         VersionTLS13,
		EchEnabled:         true,
		EchConfigs:         []EchConfig{*echConfig},
		ServerName:         "secret.example",
		// TODO(dmcardle): remove this once we fix server's CH parsing
		// to support nonempty delegated credentials extension.
		Bugs: ProtocolBugs{
			DisableDelegatedCredentials: true,
		},
	}

	tls_conn := Client(conn, &config)
	msg_chan <- testerMsg{msg: "[client] passed Client\n"}
	err = tls_conn.Handshake()
	if err != nil {
		msg_chan <- testerMsg{msg: fmt.Sprintf("[client] Error handshaking: %s\n", err), err: err}
		return
	}
	msg_chan <- testerMsg{msg: "[client] passed tls_conn.Handshake\n"}
	fmt.Fprintf(os.Stderr, "Connected.\n")
	tls_conn.Close()
}
