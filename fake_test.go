package sslcheck

import (
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file holds the scaffolding the probe tests run against: a scripted server that answers
// with exact TLS records, so each probe's decision logic is exercised against a known server
// behaviour without a network or a real TLS stack on the far side.

// testCert makes a root CA and a leaf it signs for "localhost", and returns the leaf as a
// crypto/tls certificate, the pool that trusts the root, and the leaf's RSA key.
func testCert(t *testing.T) (cryptotls.Certificate, *x509.CertPool, *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sslcheck test CA", Organization: []string{"sslcheck test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots, key
}

// scriptedServer listens on 127.0.0.1 and hands each accepted connection, with its 1-based
// index, to handle; the connection is closed when handle returns.
func scriptedServer(t *testing.T, handle func(i int, c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 1; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(i int, c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(i, c)
			}(i, c)
		}
	}()
	return ln.Addr().String()
}

// testOpts are the options the probe tests scan with: a short timeout and the test cert's name.
func testOpts() Options { return Options{Timeout: 2 * time.Second, ServerName: "localhost"} }

// Server-side record helpers.

func srvWrite(c net.Conn, typ byte, body []byte) {
	head := []byte{typ, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	_, _ = c.Write(append(head, body...))
}

func srvRead(c net.Conn) (byte, []byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:5]))
	if _, err := io.ReadFull(c, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func srvAlert(c net.Conn, code byte) { srvWrite(c, recAlert, []byte{2, code}) }

// helloInfo is what the fake servers read out of a ClientHello.
type helloInfo struct {
	sid          []byte
	suites       []uint16
	compressions []byte
	ticket       []byte // the session_ticket extension body
	hasTicket    bool
	secureReneg  bool // the SCSV or the renegotiation_info extension was offered
}

// readClientHello reads one handshake record and parses the ClientHello in it.
func readClientHello(c net.Conn) (helloInfo, error) {
	var h helloInfo
	typ, body, err := srvRead(c)
	if err != nil {
		return h, err
	}
	if typ != recHandshake || len(body) < 4 || body[0] != 1 {
		return h, io.ErrUnexpectedEOF
	}
	b := body[4:]
	at := func(n int) []byte {
		if len(b) < n {
			panic("short ClientHello")
		}
		v := b[:n]
		b = b[n:]
		return v
	}
	at(2 + 32) // version, random
	h.sid = append([]byte(nil), at(int(at(1)[0]))...)
	suites := at(int(binary.BigEndian.Uint16(at(2))))
	for i := 0; i+1 < len(suites); i += 2 {
		s := uint16(suites[i])<<8 | uint16(suites[i+1])
		if s == 0x00ff {
			h.secureReneg = true
		}
		h.suites = append(h.suites, s)
	}
	h.compressions = append([]byte(nil), at(int(at(1)[0]))...)
	if len(b) < 2 {
		return h, nil
	}
	exts := at(int(binary.BigEndian.Uint16(at(2))))
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		n := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+n {
			break
		}
		switch typ {
		case 0x0023:
			h.hasTicket = true
			h.ticket = append([]byte(nil), exts[4:4+n]...)
		case 0xff01:
			h.secureReneg = true
		}
		exts = exts[4+n:]
	}
	return h, nil
}

// serverHelloMsg builds a TLS 1.2 ServerHello choosing suite, echoing sid, with the given
// compression method and, when renegInfo, an empty renegotiation_info extension.
func serverHelloMsg(suite uint16, sid []byte, compression byte, renegInfo bool) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	b = append(b, byte(len(sid)))
	b = append(b, sid...)
	b = append(b, byte(suite>>8), byte(suite), compression)
	if renegInfo {
		ext := extension(0xff01, []byte{0x00})
		b = append(b, uint16b(len(ext))...)
		b = append(b, ext...)
	}
	return handshakeMessage(hsServerHello, b)
}

// certificateMsg builds a Certificate handshake message carrying the DER certificates.
func certificateMsg(ders ...[]byte) []byte {
	var list []byte
	for _, d := range ders {
		list = append(list, byte(len(d)>>16), byte(len(d)>>8), byte(len(d)))
		list = append(list, d...)
	}
	body := append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
	return handshakeMessage(hsCertificate, body)
}

func serverHelloDoneMsg() []byte { return handshakeMessage(hsServerHelloDone, nil) }

// pickSuite returns the first of wanted that the client offered, or 0.
func pickSuite(h helloInfo, wanted ...uint16) uint16 {
	for _, w := range wanted {
		for _, s := range h.suites {
			if s == w {
				return w
			}
		}
	}
	return 0
}
