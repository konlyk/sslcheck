package sslcheck

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

var tls12Only = []Protocol{{Name: "TLS1_2", Version: 0x0303, Offered: true}}

// A server that agrees to DEFLATE and offers secure renegotiation is reported as such, even
// though zcrypto abandons both handshakes right after the ServerHello (it implements no
// compression, and the scripted server sends nothing more).
func TestSessionFeaturesFromServerHello(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		comp := byte(compressionNone)
		if bytes.Contains(h.compressions, []byte{compressionDeflate}) {
			comp = compressionDeflate
		}
		srvWrite(c, recHandshake, serverHelloMsg(pickSuite(h, 0x002f), nil, comp, h.secureReneg))
	})
	compression, reneg := scanSessionFeatures(context.Background(), addr, tls12Only, testOpts())
	require.True(t, compression, "the server chose DEFLATE")
	require.NotNil(t, reneg)
	require.True(t, *reneg, "the server answered the renegotiation_info extension")
}

// A server that neither compresses nor supports secure renegotiation.
func TestSessionFeaturesAbsent(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(pickSuite(h, 0x002f), nil, compressionNone, false))
	})
	compression, reneg := scanSessionFeatures(context.Background(), addr, tls12Only, testOpts())
	require.False(t, compression)
	require.NotNil(t, reneg)
	require.False(t, *reneg)
}
