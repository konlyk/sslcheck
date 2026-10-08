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

// A host that accepts only a suite crypto/tls will not negotiate (3DES here) still has its HSTS
// header read, over zcrypto with the suite the scan found it accepts, the way testssl reads it
// through openssl.
func TestHTTPHeadersOverLegacySuites(t *testing.T) {
	cert, _, _ := testCert(t)
	const threeDES = 0x000a // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		srv := ztls.Server(c, &ztls.Config{
			Certificates: []ztls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
			CipherSuites: []uint16{threeDES},
		})
		if err := srv.Handshake(); err != nil {
			return // crypto/tls offered nothing in common: a handshake_failure alert, not a transport failure
		}
		r := bufio.NewReader(srv)
		for { // the request head
			line, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		_, _ = srv.Write([]byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	})
	h, err := fetchHTTPHeaders(context.Background(), "localhost", addr, []uint16{threeDES}, testOpts())
	require.NoError(t, err)
	require.Equal(t, "max-age=31536000", h.HSTS)

	// Without the host's suites to fall back on, the failure is the server's, not the network's.
	_, err = fetchHTTPHeaders(context.Background(), "localhost", addr, nil, testOpts())
	require.Error(t, err)
	require.False(t, isTransportFailure(err))
}
