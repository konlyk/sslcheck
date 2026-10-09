package sslcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// rsaKexHandshake answers a ClientHello with a ServerHello choosing an RSA-key-exchange suite, the
// leaf certificate, and ServerHelloDone, which is the flight the CCS and ROBOT probes read before
// their crafted continuation. It returns false if no ClientHello arrived.
func rsaKexHandshake(c net.Conn, leaf []byte) bool {
	h, err := readClientHello(c)
	if err != nil {
		return false
	}
	suite := pickSuite(h, 0x0035, 0x002f, 0x000a) // RSA_WITH_AES_256_CBC_SHA etc: no ServerKeyExchange
	srvWrite(c, recHandshake, serverHelloMsg(suite, nil, compressionNone, false))
	srvWrite(c, recHandshake, certificateMsg(leaf))
	srvWrite(c, recHandshake, serverHelloDoneMsg())
	return true
}

// drainRecords reads and discards up to n records, stopping early on error.
func drainRecords(c net.Conn, n int) {
	for i := 0; i < n; i++ {
		if _, _, err := srvRead(c); err != nil {
			return
		}
	}
}

// A server that answers the second early ChangeCipherSpec with a bad_record_mac alert is the
// vulnerable OpenSSL signature; one that answers with unexpected_message is patched.
func TestCCSInjection(t *testing.T) {
	cert, _, _ := testCert(t)
	cases := []struct {
		name  string
		alert byte
		want  bool
	}{
		{"vulnerable bad_record_mac", 20, true},
		{"vulnerable decryption_failed", 21, true},
		{"patched unexpected_message", 10, false},
		{"patched handshake_failure", 40, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := scriptedServer(t, func(_ int, c net.Conn) {
				if !rsaKexHandshake(c, cert.Certificate[0]) {
					return
				}
				drainRecords(c, 2) // the two early ChangeCipherSpec records
				srvAlert(c, tc.alert)
			})
			require.Equal(t, tc.want, ccsInjection(context.Background(), addr, testOpts()))
		})
	}
}

// A server whose alert to the well-formed padding differs, reproducibly, from its alert to the
// malformed probes is a padding oracle; one that answers every probe alike is not. The scripted
// oracle decrypts each probe with the test key to tell the well-formed one apart, so it does not
// depend on the order the probes' connections arrive in (they are sent concurrently).
func TestRobot(t *testing.T) {
	cert, _, key := testCert(t)
	robotServer := func(oracle bool) string {
		return scriptedServer(t, func(_ int, c net.Conn) {
			if !rsaKexHandshake(c, cert.Certificate[0]) {
				return
			}
			typ, body, err := srvRead(c) // the ClientKeyExchange (absent on the key-fetch connection)
			if err != nil || typ != recHandshake || len(body) < 4 || body[0] != 16 {
				return
			}
			drainRecords(c, 2) // ChangeCipherSpec, the dummy Finished
			if oracle && wellFormedPremaster(key, body[4:]) {
				srvAlert(c, 20) // the well-formed probe is treated differently
			} else {
				srvAlert(c, 40)
			}
		})
	}
	require.NotEmpty(t, robot(context.Background(), robotServer(true), testOpts()), "an oracle")
	require.Empty(t, robot(context.Background(), robotServer(false), testOpts()), "uniform answers")
}

// wellFormedPremaster raw-decrypts a ClientKeyExchange body (2-byte length + ciphertext) with the
// test key and reports whether it carries correct PKCS#1 v1.5 padding: 00 02, non-zero padding,
// a 00 delimiter 48 bytes from the end.
func wellFormedPremaster(key *rsa.PrivateKey, cke []byte) bool {
	if len(cke) < 2 {
		return false
	}
	n := int(cke[0])<<8 | int(cke[1])
	if len(cke) < 2+n {
		return false
	}
	m := new(big.Int).Exp(new(big.Int).SetBytes(cke[2:2+n]), key.D, key.N)
	b := make([]byte, key.Size())
	m.FillBytes(b)
	size := len(b)
	if b[0] != 0x00 || b[1] != 0x02 || b[size-49] != 0x00 {
		return false
	}
	for _, x := range b[2 : size-49] {
		if x == 0 {
			return false
		}
	}
	return true
}

// A server with no RSA key exchange cannot be a ROBOT oracle.
func TestRobotNoRSAKex(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		srvAlert(c, 40) // handshake_failure: no suite in common
	})
	require.Empty(t, robot(context.Background(), addr, testOpts()))
}

// ticketbleedEcho returns the full session id the server echoes, from which the caller reads any
// padding past the id it sent.
func TestTicketbleedEcho(t *testing.T) {
	sid := []byte{0x00, 0x0b, 0xad, 0xc0, 0xde, 0x00}
	echoed := make([]byte, 32)
	copy(echoed, sid)
	_, _ = rand.Read(echoed[len(sid):]) // the "memory" past our id
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(0x002f, echoed, compressionNone, false))
	})
	got := ticketbleedEcho(context.Background(), addr, testOpts(), probeSuites, sid, extension(0x0023, make([]byte, 16)))
	require.Equal(t, echoed, got)
}

// A sound server (the in-process TLS server, which issues tickets but does not leak) is not
// Ticketbleed-vulnerable.
func TestTicketbleedNotVulnerable(t *testing.T) {
	addr, _ := localServer(t, modernConfig())
	require.False(t, ticketbleed(context.Background(), addr, testOpts()))
}

// The full probe against a server that behaves like a vulnerable F5: it issues a real ticket on
// the first (genuine TLS) connection, then, on each resumption, echoes the short session id padded
// to 32 bytes with different bytes every time. The same server echoing a fixed padding, or exactly
// the id, is not vulnerable.
func TestTicketbleedVulnerable(t *testing.T) {
	cert, _, _ := testCert(t)
	f5 := func(pad func(i int) []byte) string {
		return scriptedServer(t, func(i int, c net.Conn) {
			if i == 1 { // the ticket harvest: a genuine TLS 1.2 handshake that issues a ticket
				srv := cryptotls.Server(c, &cryptotls.Config{Certificates: []cryptotls.Certificate{cert}, MaxVersion: cryptotls.VersionTLS12})
				_ = srv.Handshake()
				return
			}
			h, err := readClientHello(c)
			if err != nil || !h.hasTicket || len(h.sid) == 0 || len(h.sid) >= 32 {
				return
			}
			echoed := append(append([]byte(nil), h.sid...), pad(i)[:32-len(h.sid)]...)
			srvWrite(c, recHandshake, serverHelloMsg(h.suites[0], echoed, compressionNone, false))
		})
	}
	leaking := func(int) []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
	fixed := func(int) []byte { return make([]byte, 32) }
	require.True(t, ticketbleed(context.Background(), f5(leaking), testOpts()), "memory differs on every resumption")
	require.False(t, ticketbleed(context.Background(), f5(fixed), testOpts()), "a stable padding is not a leak")
}
