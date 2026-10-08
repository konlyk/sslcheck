package sslcheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// This file is a very small TLS 1.2 client, only enough to drive the active probes: it builds a
// ClientHello, reads the server's handshake records, and sends raw records. It decrypts nothing
// and recovers nothing; the probes read a weakness from which records the server sends back, the
// way testssl, sslscan and nmap's ssl scripts do. It is not a TLS implementation and is never
// used for the ordinary assessment, which goes through crypto/tls and zcrypto.

// record types.
const (
	recHandshake       = 22
	recChangeCipher    = 20
	recAlert           = 21
	recApplicationData = 23
)

// handshake message types.
const (
	hsServerHello     = 2
	hsCertificate     = 11
	hsServerKeyExch   = 12
	hsServerHelloDone = 14
)

// rawConn is a minimal TLS record transport over one TCP connection.
type rawConn struct {
	conn    net.Conn
	timeout time.Duration
}

func dialRaw(ctx context.Context, addr string, opts Options) (*rawConn, error) {
	c, err := dial(ctx, addr, opts)
	if err != nil {
		return nil, err
	}
	return &rawConn{conn: c, timeout: opts.timeout()}, nil
}

func (r *rawConn) close() { _ = r.conn.Close() }

// writeRecord sends one TLS record of the given type and version.
func (r *rawConn) writeRecord(typ byte, version uint16, payload []byte) error {
	_ = r.conn.SetWriteDeadline(time.Now().Add(r.timeout))
	head := []byte{typ, byte(version >> 8), byte(version), byte(len(payload) >> 8), byte(len(payload))}
	if _, err := r.conn.Write(append(head, payload...)); err != nil {
		return err
	}
	return nil
}

// readRecord reads one TLS record. It returns the type and payload, or an error (including an
// alert, surfaced as alertError so a probe can read the alert code).
func (r *rawConn) readRecord() (byte, []byte, error) {
	_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	head := make([]byte, 5)
	if _, err := io.ReadFull(r.conn, head); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:5]))
	if _, err := io.ReadFull(r.conn, body); err != nil {
		return 0, nil, err
	}
	if head[0] == recAlert && len(body) >= 2 {
		return recAlert, body, &alertError{level: body[0], code: body[1]}
	}
	return head[0], body, nil
}

// alertError is a TLS alert the server sent.
type alertError struct{ level, code byte }

func (e *alertError) Error() string { return "tls alert " + itoaByte(e.code) }

func asAlert(err error) (*alertError, bool) {
	var a *alertError
	return a, errors.As(err, &a)
}

// clientHello builds a TLS 1.2 ClientHello offering suites, with SNI for serverName and the
// extensions a modern server needs to answer (supported groups, point formats, signature
// algorithms). sessionID and the ticket extension are set by the probes that need them.
func clientHello(serverName string, suites []uint16, sessionID []byte, extra []byte) []byte {
	var b []byte
	put16 := func(v uint16) { b = append(b, byte(v>>8), byte(v)) }

	b = append(b, 0x03, 0x03) // client_version TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	b = append(b, byte(len(sessionID))) // session id
	b = append(b, sessionID...)
	put16(uint16(len(suites) * 2)) // cipher suites
	for _, s := range suites {
		put16(s)
	}
	b = append(b, 0x01, 0x00) // one compression method: null

	ext := sniExtension(serverName)
	ext = append(ext, supportedGroupsExtension()...)
	ext = append(ext, pointFormatsExtension()...)
	ext = append(ext, sigAlgsExtension()...)
	ext = append(ext, extra...)
	put16(uint16(len(ext)))
	b = append(b, ext...)

	return handshakeMessage(1, b) // 1 = client_hello
}

// handshakeMessage wraps a handshake body in its 4-byte type+length header.
func handshakeMessage(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func sniExtension(name string) []byte {
	if name == "" {
		return nil
	}
	host := []byte(name)
	srvNameList := append([]byte{0x00}, uint16b(len(host))...) // name_type host_name + length
	srvNameList = append(srvNameList, host...)
	list := append(uint16b(len(srvNameList)), srvNameList...)
	return extension(0x0000, list)
}

func supportedGroupsExtension() []byte {
	groups := []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18} // x25519, secp256r1, secp384r1
	return extension(0x000a, append(uint16b(len(groups)), groups...))
}

func pointFormatsExtension() []byte {
	return extension(0x000b, []byte{0x01, 0x00}) // one format: uncompressed
}

func sigAlgsExtension() []byte {
	algs := []byte{0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x01} // rsa/ecdsa with sha256/384/512 + sha1
	return extension(0x000d, append(uint16b(len(algs)), algs...))
}

// extension wraps a body as a TLS extension of the given type.
func extension(typ uint16, body []byte) []byte {
	return append(append(uint16b(int(typ)), uint16b(len(body))...), body...)
}

func uint16b(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func itoaByte(b byte) string { return itoa(int(b)) }

// readUntilServerHelloDone reads handshake records until ServerHelloDone, returning the collected
// handshake messages by type. It is how a probe gets the ServerHello and Certificate before it
// sends its crafted continuation.
func (r *rawConn) readUntilServerHelloDone() (map[byte][]byte, error) {
	msgs := map[byte][]byte{}
	var buf []byte
	for {
		typ, body, err := r.readRecord()
		if err != nil {
			return msgs, err
		}
		if typ != recHandshake {
			continue
		}
		buf = append(buf, body...)
		for len(buf) >= 4 {
			n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
			if len(buf) < 4+n {
				break
			}
			mtype := buf[0]
			msgs[mtype] = buf[4 : 4+n]
			buf = buf[4+n:]
			if mtype == hsServerHelloDone {
				return msgs, nil
			}
		}
	}
}
