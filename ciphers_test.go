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

// A protocol probe that the network keeps dropping is reported undecided, not "not offered".
func TestOffersVersionUndecidedOnResets(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) { resetConn(c) })
	offered, undecided := offersVersion(context.Background(), addr, 0x0303, testOpts())
	require.False(t, offered)
	require.True(t, undecided)
}
