package sslcheck

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// The raw client reads the served chain out of the Certificate message, needing no cipher.
func TestRawChain(t *testing.T) {
	cert, _, _ := testCert(t)
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(pickSuite(h, 0x002f), nil, compressionNone, false))
		srvWrite(c, recHandshake, certificateMsg(cert.Certificate[0]))
		srvWrite(c, recHandshake, serverHelloDoneMsg())
	})
	chain := rawChain(context.Background(), addr, testOpts())
	require.Len(t, chain, 1)
	require.Equal(t, "localhost", chain[0].Subject.CommonName)
}

// A host that accepts only a NULL suite, which neither crypto/tls nor zcrypto can complete, still
// has its certificate described, through the raw fallback.
func TestScanCertificatesNullOnlyServer(t *testing.T) {
	cert, roots, _ := testCert(t)
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		suite := pickSuite(h, 0x0002) // TLS_RSA_WITH_NULL_SHA, or 0 when not offered
		srvWrite(c, recHandshake, serverHelloMsg(suite, nil, compressionNone, false))
		srvWrite(c, recHandshake, certificateMsg(cert.Certificate[0]))
		srvWrite(c, recHandshake, serverHelloDoneMsg())
	})
	opts := testOpts()
	opts.Roots = roots
	certs := scanCertificates(context.Background(), "localhost", addr, opts)
	require.Len(t, certs, 1)
	require.Equal(t, "localhost", certs[0].CommonName)
	require.True(t, certs[0].Trusted, certs[0].TrustReason)
}
