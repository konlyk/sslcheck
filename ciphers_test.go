package sslcheck

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// resetConn closes a connection with a TCP reset rather than a FIN, which is what a host shedding
// load does; the client sees ECONNRESET, a transport failure, not an answer.
func resetConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// enumerationServer scripts a cipher enumeration: on connection i it calls behave, which returns
// the suite to accept, 0 to refuse with a handshake_failure alert, or -1 to reset the connection.
func enumerationServer(t *testing.T, behave func(i int) int) string {
	return scriptedServer(t, func(i int, c net.Conn) {
		switch suite := behave(i); {
		case suite < 0:
			resetConn(c)
			return
		case suite == 0:
			if _, err := readClientHello(c); err != nil {
				return
			}
			srvAlert(c, 40)
		default:
			if _, err := readClientHello(c); err != nil {
				return
			}
			srvWrite(c, recHandshake, serverHelloMsg(uint16(suite), nil, compressionNone, false))
		}
	})
}

// A burst of resets in the middle of an enumeration is retried through, and the list is complete:
// the server accepts 0x002f, then drops the next three attempts (zcrypto's own retries), accepts
// 0x0035 on the fourth, then refuses.
func TestCiphersAtRetriesDroppedConnections(t *testing.T) {
	addr := enumerationServer(t, func(i int) int {
		switch {
		case i == 1:
			return 0x002f
		case i <= 4:
			return -1
		case i == 5:
			return 0x0035
		default:
			return 0
		}
	})
	cs, complete := ciphersAt(context.Background(), addr, Protocol{Name: "TLS1_2", Version: 0x0303}, testOpts())
	require.True(t, complete)
	require.Equal(t, []string{"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"}, []string{cs[0].Name, cs[1].Name})
}

// A server that keeps resetting is given up on, and the list is reported incomplete rather than
// passed off as the server's last word.
func TestCiphersAtReportsIncomplete(t *testing.T) {
	addr := enumerationServer(t, func(i int) int {
		if i == 1 {
			return 0x002f
		}
		return -1
	})
	cs, complete := ciphersAt(context.Background(), addr, Protocol{Name: "TLS1_2", Version: 0x0303}, testOpts())
	require.False(t, complete)
	require.Len(t, cs, 1)
}

// A server that refuses by simply closing (no alert) has answered: the list is complete.
func TestCiphersAtPlainCloseIsAnAnswer(t *testing.T) {
	addr := scriptedServer(t, func(i int, c net.Conn) {
		if _, err := readClientHello(c); err != nil {
			return
		}
		if i > 1 {
			return // close without a word (having read the hello, so the close is a FIN, not a reset)
		}
		srvWrite(c, recHandshake, serverHelloMsg(0x002f, nil, compressionNone, false))
	})
	cs, complete := ciphersAt(context.Background(), addr, Protocol{Name: "TLS1_2", Version: 0x0303}, testOpts())
	require.True(t, complete)
	require.Len(t, cs, 1)
}

// A protocol probe that the network keeps dropping reports the failure rather than a plain "not
// offered"; a host that answers nothing at all then lists the version as incomplete.
func TestOffersVersionFailureOnResets(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) { resetConn(c) })
	offered, failure := offersVersion(context.Background(), addr, 0x0303, testOpts())
	require.False(t, offered)
	require.NotNil(t, failure)
	require.False(t, failure.mixed, "reset every time")

	_, incomplete := scanProtocols(context.Background(), addr, testOpts())
	require.Contains(t, incomplete, "protocol TLS1_2")
}

// A listener that refuses a version with a reset, while answering another, has answered: that
// version is not offered and not incomplete.
func TestScanProtocolsResetIsRefusalWhenHostAnswers(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			resetConn(c) // SSLv2's raw hello, or a TLS 1.3 hello crypto/tls will not finish
			return
		}
		if pickSuite(h, 0x002f) == 0 {
			resetConn(c)
			return
		}
		srvWrite(c, recHandshake, serverHelloMsg(0x002f, nil, compressionNone, false))
	})
	ps, incomplete := scanProtocols(context.Background(), addr, testOpts())
	require.True(t, anyOffered(ps), "the TLS 1.0-1.2 hellos were answered")
	require.Empty(t, incomplete)
}
