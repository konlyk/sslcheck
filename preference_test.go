package sslcheck

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// A server that always picks the same suite whatever order the client offers enforces an order; a
// server that picks whichever the client lists first does not.
func TestScanCipherOrder(t *testing.T) {
	protos := []Protocol{{Name: "TLS1_2", Version: 0x0303, Offered: true}}
	ciphers := []Cipher{
		{ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Version: "TLS1_2"},
		{ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS1_2"},
	}

	// Enforcing: always choose 0xc030, whatever the client's order.
	enforce := scriptedServer(t, func(_ int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(0xc030, nil, compressionNone, false))
	})
	order, _, noOrder := scanCipherOrder(context.Background(), enforce, protos, ciphers, testOpts())
	require.NotNil(t, order)
	require.True(t, *order)
	require.Empty(t, noOrder)

	// Client-led: choose the client's first suite each time.
	clientLed := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil || len(h.suites) == 0 {
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(h.suites[0], nil, compressionNone, false))
	})
	order, _, noOrder = scanCipherOrder(context.Background(), clientLed, protos, ciphers, testOpts())
	require.NotNil(t, order)
	require.False(t, *order)
	require.Equal(t, []string{"TLS1_2"}, noOrder)
}

func TestCipherQualityLadder(t *testing.T) {
	require.Equal(t, 7, cipherQuality("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
	require.Equal(t, 6, cipherQuality("TLS_RSA_WITH_AES_128_GCM_SHA256"))
	require.Equal(t, 4, cipherQuality("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"))
	require.Equal(t, 3, cipherQuality("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
	require.Equal(t, 2, cipherQuality("TLS_RSA_WITH_RC4_128_SHA"))
	require.Equal(t, 1, cipherQuality("TLS_RSA_WITH_NULL_SHA"))
}

// A server that keeps its order but lets a client that lists ChaCha20 first have it (BoringSSL's
// equal-preference group) has an order, as testssl counts it; the same server with ChaCha left out
// of the comparison picks consistently.
func TestScanCipherOrderChaChaPreference(t *testing.T) {
	const aes256, aes128, chacha = 0xc030, 0xc02f, 0xcca8
	protos := []Protocol{{Name: "TLS1_2", Version: 0x0303, Offered: true}}
	ciphers := []Cipher{
		{ID: aes256, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Version: "TLS1_2"},
		{ID: aes128, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS1_2"},
		{ID: chacha, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Version: "TLS1_2"},
	}
	boring := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil || len(h.suites) == 0 {
			return
		}
		pick := uint16(aes256) // the server's own first choice …
		if h.suites[0] == chacha {
			pick = chacha // … unless the client asks for ChaCha first
		}
		srvWrite(c, recHandshake, serverHelloMsg(pick, nil, compressionNone, false))
	})
	order, level, noOrder := scanCipherOrder(context.Background(), boring, protos, ciphers, testOpts())
	require.NotNil(t, order)
	require.True(t, *order, "honouring a ChaCha preference is still an order")
	require.Equal(t, 5, level)
	require.Empty(t, noOrder)
}
