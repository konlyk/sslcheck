package sslcheck

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ztls "github.com/zmap/zcrypto/tls"
)

var twoLegacy = []Protocol{
	{Name: "TLS1_1", Version: 0x0302, Offered: true},
	{Name: "TLS1_2", Version: 0x0303, Offered: true},
}

// A server that answers the fallback hello with inappropriate_fallback (alert 86) honours SCSV; a
// server that completes the handshake does not.
func TestScanFallbackSCSV(t *testing.T) {
	honour := scriptedServer(t, func(_ int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		srvAlert(c, 86)
	})
	s := scanFallbackSCSV(context.Background(), honour, twoLegacy, testOpts())
	require.NotNil(t, s)
	require.True(t, *s)

	ignore := scriptedServer(t, func(_ int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(0x002f, nil, compressionNone, false))
	})
	s = scanFallbackSCSV(context.Background(), ignore, twoLegacy, testOpts())
	require.NotNil(t, s)
	require.False(t, *s)

	// A host with only one usable version has nothing to fall back from.
	require.Nil(t, scanFallbackSCSV(context.Background(), honour, []Protocol{{Name: "TLS1_2", Version: 0x0303, Offered: true}}, testOpts()))
}

// fetchHTTPHeaders captures the response Content-Encoding, the BREACH precondition.
func TestHTTPCompressionDetected(t *testing.T) {
	cert, _, _ := testCert(t)
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		srv := ztls.Server(c, &ztls.Config{Certificates: []ztls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}})
		if err := srv.Handshake(); err != nil {
			return
		}
		r := bufio.NewReader(srv)
		for {
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		_, _ = srv.Write([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	})
	h, err := fetchHTTPHeaders(context.Background(), "localhost", addr, []uint16{0x009c, 0x002f}, testOpts())
	require.NoError(t, err)
	require.Equal(t, "gzip", h.Compression)
}
