package runner

import (
	"bytes"
	"net"
	"testing"
)

func runServer(cert Certificate, listener net.Listener, fc chan func(c *Conn)) {
	config := &Config{
		Certificates: []Certificate{cert},
	}
	for {
		f := <-fc
		if f == nil {
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		tlsConn := Server(conn, config)
		go func() {
			defer tlsConn.Close()
			f(tlsConn)
		}()
	}
}

func runClient(cache ClientSessionCache, conn net.Conn, t *testing.T, f func(c *Conn)) {
	config := &Config{
		InsecureSkipVerify: true,
		ClientSessionCache: cache,
	}
	tlsConn := Client(conn, config)
	defer tlsConn.Close()
	f(tlsConn)
}

func TestPSKResumption(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	certPath := "../../../build/server.pem"
	cert, err := LoadX509KeyPair(certPath, certPath)
	if err != nil {
		t.Errorf("Error loading cert: %s\n", err)
		return
	}
	cache := NewLRUClientSessionCache(0)

	serverFunctions := make(chan func(conn *Conn))
	go runServer(cert, listener, serverFunctions)
	// Run first connection
	serverFunctions <- func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		writeFull([]byte("from server"), conn.Write, t)
	}
	clientConn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	runClient(cache, clientConn, t, func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		writeFull([]byte("testing"), conn.Write, t)
		msg := make([]byte, 7)
		readFull(msg, conn.Read, t)
	})

	// Run second connection
	serverFunctions <- func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
	}
	clientConn, err = net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	runClient(cache, clientConn, t, func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		if !conn.ConnectionState().DidResume {
			t.Errorf("Second connection was not resumed")
		}
		writeFull([]byte("testing"), conn.Write, t)
	})
}

func writeFull(msg []byte, writer func([]byte) (int, error), t *testing.T) {
	var n int
	for n < len(msg) {
		m, err := writer(msg[n:])
		if err != nil {
			t.Fatalf("Error writing '%s': %s\n", msg, err)
		}
		n += m
	}
}

var readFull = writeFull

func TestZeroRTT(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	certPath := "../../../build/server.pem"
	cert, err := LoadX509KeyPair(certPath, certPath)
	if err != nil {
		t.Errorf("Error loading cert: %s\n", err)
		return
	}
	cache := NewLRUClientSessionCache(0)

	serverFunctions := make(chan func(conn *Conn))
	go runServer(cert, listener, serverFunctions)
	// Run first connection
	serverFunctions <- func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		writeFull([]byte("from server"), conn.Write, t)
	}
	clientConn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	runClient(cache, clientConn, t, func(conn *Conn) {
		if err := conn.Handshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		writeFull([]byte("testing"), conn.Write, t)
		msg := make([]byte, 11)
		readFull(msg, conn.Read, t)
	})

	// Run second connection
	earlyWrite := []byte("early write")
	halfRTT := []byte("half RTT data")
	appData := []byte("app data")
	serverFunctions <- func(conn *Conn) {
		if err := conn.StartHandshake(); err != nil {
			t.Errorf("Handshake error: %s\n", err)
			return
		}
		s := make([]byte, len(earlyWrite))
		readFull(s, conn.Read, t)
		if !bytes.Equal(s, earlyWrite) {
			t.Errorf("Expected '%s' but got '%s'\n", earlyWrite, s)
		}
		writeFull(halfRTT, conn.Write, t)
		s = make([]byte, len(appData))
		readFull(s, conn.Read, t)
		if !bytes.Equal(s, appData) {
			t.Errorf("Expected '%s' but got '%s'\n", appData, s)
		}
	}
	clientConn, err = net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	runClient(cache, clientConn, t, func(conn *Conn) {
		if err := conn.StartHandshake(); err != nil {
			t.Fatalf("Handshake error: %s\n", err)
			return
		}
		writeFull(earlyWrite, conn.EarlyWrite, t)
		if err := conn.FinishHandshake(); err != nil {
			t.Fatalf("Failed to finish handshake: %s\n", err)
		}
		s := make([]byte, len(halfRTT))
		readFull(s, conn.Read, t)
		if !bytes.Equal(s, halfRTT) {
			t.Errorf("Expected '%s' but got '%s'\n", halfRTT, s)
		}
		writeFull(appData, conn.Write, t)
	})
}
