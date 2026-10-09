package sslcheck

import (
	"context"
	"net"
	"sync"
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

// prefServer scripts a server with a cipher preference: on each hello it picks the first suite in
// prefs the client offered, or refuses with handshake_failure. misbehave, when set, runs first on
// the parsed hello and returns true if it handled (and ended) the connection itself; it is how a
// test injects resets or closes for particular offers.
func prefServer(t *testing.T, prefs []uint16, misbehave func(h helloInfo, c net.Conn) bool) string {
	return scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		if misbehave != nil && misbehave(h, c) {
			return
		}
		if pick := pickSuite(h, prefs...); pick != 0 {
			srvWrite(c, recHandshake, serverHelloMsg(pick, nil, compressionNone, false))
			return
		}
		srvAlert(c, 40)
	})
}

var tls12 = Protocol{Name: "TLS1_2", Version: 0x0303}

func ids(cs []Cipher) []uint16 {
	var out []uint16
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

// The chunked enumeration finds every accepted suite, with the server's first choice first.
func TestCiphersAtEnumeratesAll(t *testing.T) {
	prefs := []uint16{0xc030, 0xc02f, 0x0035, 0x002f, 0x000a}
	addr := prefServer(t, prefs, nil)
	cs, complete := ciphersAt(context.Background(), addr, tls12, testOpts())
	require.True(t, complete)
	require.ElementsMatch(t, prefs, ids(cs))
	require.Equal(t, uint16(0xc030), cs[0].ID, "the server's first choice comes first")
}

// A burst of resets on offers of a particular suite is retried through, and the list is complete:
// the server resets the first three hellos that offer 0x0035, then behaves.
func TestCiphersAtRetriesDroppedConnections(t *testing.T) {
	prefs := []uint16{0xc030, 0x0035, 0x002f}
	var mu sync.Mutex
	resets := 0
	addr := prefServer(t, prefs, func(h helloInfo, c net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if pickSuite(h, 0x0035) != 0 && resets < 3 {
			resets++
			resetConn(c)
			return true
		}
		return false
	})
	cs, complete := ciphersAt(context.Background(), addr, tls12, testOpts())
	require.True(t, complete)
	require.ElementsMatch(t, prefs, ids(cs))
}

// A server that keeps resetting one chain is given up on, and the list is reported incomplete
// rather than passed off as the server's last word; the other chains still contribute.
func TestCiphersAtReportsIncomplete(t *testing.T) {
	prefs := []uint16{0xc030, 0x0035, 0x002f}
	addr := prefServer(t, prefs, func(h helloInfo, c net.Conn) bool {
		if pickSuite(h, 0x0035) != 0 && pickSuite(h, 0xc030) == 0 { // every offer of 0x0035 past the first pick
			resetConn(c)
			return true
		}
		return false
	})
	cs, complete := ciphersAt(context.Background(), addr, tls12, testOpts())
	require.False(t, complete)
	require.Contains(t, ids(cs), uint16(0xc030))
	require.Contains(t, ids(cs), uint16(0x002f))
	require.NotContains(t, ids(cs), uint16(0x0035))
}

// A server that refuses by simply closing (no alert), having read the hello, has answered: the
// list is complete.
func TestCiphersAtPlainCloseIsAnAnswer(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		h, err := readClientHello(c)
		if err != nil {
			return
		}
		if pickSuite(h, 0x002f) != 0 {
			srvWrite(c, recHandshake, serverHelloMsg(0x002f, nil, compressionNone, false))
			return
		}
		// close without a word (having read the hello, so the close is a FIN, not a reset)
	})
	cs, complete := ciphersAt(context.Background(), addr, tls12, testOpts())
	require.True(t, complete)
	require.Equal(t, []uint16{0x002f}, ids(cs))
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
