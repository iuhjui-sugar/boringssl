// Copyright (c) 2019, Google Inc.
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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const tagHandshake = byte('H')
const tagApplication = byte('A')

type mockQuicTransport struct {
	net.Conn
	readSecret, writeSecret []byte
}

func newMockQuicTransport(conn net.Conn) *mockQuicTransport {
	return &mockQuicTransport{conn, []byte{}, []byte{}}
}

func (m *mockQuicTransport) readTag() (byte, error) {
	out := make([]byte, 1)
	if _, err := io.ReadFull(m.Conn, out); err != nil {
		return 0, err
	}
	return out[0], nil
}

func (m *mockQuicTransport) readLength() (int, error) {
	var length uint32
	if err := binary.Read(m.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	return int(length), nil
}

func (m *mockQuicTransport) read() (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(m.Conn, header); err != nil {
		return 0, nil, err
	}
	var length uint32
	binary.Read(bytes.NewBuffer(header[1:]), binary.BigEndian, &length)
	secret := make([]byte, len(m.readSecret))
	if _, err := io.ReadFull(m.Conn, secret); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(secret, m.readSecret) {
		return 0, nil, fmt.Errorf("Secrets don't match")
	}
	out := make([]byte, int(length))
	if _, err := io.ReadFull(m.Conn, out); err != nil {
		return 0, nil, err
	}
	return header[0], out, nil
}

func (m *mockQuicTransport) readRecord(want recordType) (recordType, *block, error) {
	typ, contents, err := m.read()
	if err != nil {
		return 0, nil, err
	}
	var returnType recordType
	if typ == tagHandshake {
		returnType = recordTypeHandshake
	} else if typ == tagApplication {
		returnType = recordTypeApplicationData
	} else {
		return 0, nil, fmt.Errorf("Unknown type %d\n", typ)
	}
	return returnType, &block{contents, 0, nil}, nil
}

func (m *mockQuicTransport) writeRecord(typ recordType, data []byte) (int, error) {
	tag := tagHandshake
	if typ == recordTypeApplicationData {
		tag = tagApplication
	} else if typ != recordTypeHandshake {
		return 0, fmt.Errorf("Unsupported record type %d\n", typ)
	}
	payload := make([]byte, 1+4+len(m.writeSecret)+len(data))
	payload[0] = tag
	binary.BigEndian.PutUint32(payload[1:5], uint32(len(data)))
	copy(payload[5:], m.writeSecret)
	copy(payload[5+len(m.writeSecret):], data)
	if _, err := m.Conn.Write(payload); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (m *mockQuicTransport) Write(b []byte) (int, error) {
	panic("Unexpected call to Write")
}

func (m *mockQuicTransport) Read(b []byte) (int, error) {
	panic("Unexpected call to Read")
}
