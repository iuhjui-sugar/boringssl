// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"time"
)

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
type sessionState struct {
	vers                 uint16
	cipherSuite          uint16
	masterSecret         []byte
	handshakeHash        []byte
	certificates         [][]byte
	extendedMasterSecret bool
	earlyALPN            []byte
	ticketCreationTime   time.Time
	ticketExpiration     time.Time
	ticketFlags          uint32
	ticketAgeAdd         uint32
}

func (s *sessionState) marshal() []byte {
	msg := newByteBuilder()
	msg.addU16(s.vers)
	msg.addU16(s.cipherSuite)
	masterSecret := msg.addU16LengthPrefixed()
	masterSecret.addBytes(s.masterSecret)
	handshakeHash := msg.addU16LengthPrefixed()
	handshakeHash.addBytes(s.handshakeHash)
	msg.addU16(uint16(len(s.certificates)))
	for _, cert := range s.certificates {
		certMsg := msg.addU32LengthPrefixed()
		certMsg.addBytes(cert)
	}

	if s.extendedMasterSecret {
		msg.addU8(1)
	} else {
		msg.addU8(0)
	}

	if s.vers >= VersionTLS13 {
		msg.addU64(uint64(s.ticketCreationTime.UnixNano()))
		msg.addU64(uint64(s.ticketExpiration.UnixNano()))
		msg.addU32(s.ticketFlags)
		msg.addU32(s.ticketAgeAdd)
	}

	earlyALPN := msg.addU16LengthPrefixed()
	earlyALPN.addBytes(s.earlyALPN)

	return msg.finish()
}

func (s *sessionState) unmarshal(data []byte) bool {
	reader := byteReader(data)
	var numCerts uint16
	if !reader.readU16(&s.vers) ||
		!reader.readU16(&s.cipherSuite) ||
		!reader.readU16LengthPrefixedBytes(&s.masterSecret) ||
		!reader.readU16LengthPrefixedBytes(&s.handshakeHash) ||
		!reader.readU16(&numCerts) {
		return false
	}

	s.certificates = make([][]byte, int(numCerts))
	for i := range s.certificates {
		if !reader.readU32LengthPrefixedBytes(&s.certificates[i]) {
			return false
		}
	}

	var extendedMasterSecret uint8
	if !reader.readU8(&extendedMasterSecret) {
		return false
	}
	if extendedMasterSecret == 0 {
		s.extendedMasterSecret = false
	} else if extendedMasterSecret == 1 {
		s.extendedMasterSecret = true
	} else {
		return false
	}

	if s.vers >= VersionTLS13 {
		var ticketCreationTime, ticketExpiration uint64
		if !reader.readU64(&ticketCreationTime) ||
			!reader.readU64(&ticketExpiration) ||
			!reader.readU32(&s.ticketFlags) ||
			!reader.readU32(&s.ticketAgeAdd) {
			return false
		}
		s.ticketCreationTime = time.Unix(0, int64(ticketCreationTime))
		s.ticketExpiration = time.Unix(0, int64(ticketExpiration))
	}

	if !reader.readU16LengthPrefixedBytes(&s.earlyALPN) ||
		len(reader) > 0 {
		return false
	}

	return true
}

func (c *Conn) encryptTicket(state *sessionState) ([]byte, error) {
	serialized := state.marshal()
	encrypted := make([]byte, aes.BlockSize+len(serialized)+sha256.Size)
	iv := encrypted[:aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(c.config.rand(), iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.config.SessionTicketKey[:16])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[aes.BlockSize:], serialized)

	mac := hmac.New(sha256.New, c.config.SessionTicketKey[16:32])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

func (c *Conn) decryptTicket(encrypted []byte) (*sessionState, bool) {
	if len(encrypted) < aes.BlockSize+sha256.Size {
		return nil, false
	}

	iv := encrypted[:aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	mac := hmac.New(sha256.New, c.config.SessionTicketKey[16:32])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return nil, false
	}

	block, err := aes.NewCipher(c.config.SessionTicketKey[:16])
	if err != nil {
		return nil, false
	}
	ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)

	state := new(sessionState)
	ok := state.unmarshal(plaintext)
	return state, ok
}
