package sslcheck

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// scanALPN reports the application protocols the server selects.
func TestScanALPN(t *testing.T) {
	cfg := modernConfig()
	cfg.NextProtos = []string{"h2", "http/1.1"}
	addr, _ := localServer(t, cfg)
	got := scanALPN(context.Background(), addr, Options{Timeout: 3 * time.Second, ServerName: "localhost"})
	require.ElementsMatch(t, []string{"h2", "http/1.1"}, got)

	// A server advertising no ALPN selects nothing.
	addr2, _ := localServer(t, modernConfig())
	require.Empty(t, scanALPN(context.Background(), addr2, Options{Timeout: 3 * time.Second, ServerName: "localhost"}))
}

// The well-known-DH-group table names the primes testssl names, keyed by upper-case hex.
func TestKnownDHGroups(t *testing.T) {
	require.Greater(t, len(knownDHGroups), 20)
	for hexP, name := range knownDHGroups {
		require.Equal(t, hexP, upperHex(hexP), "keys are upper-case hex")
		require.NotEmpty(t, name)
	}
	// RFC 3526 group 14 (2048-bit) is the common modern MODP group; it must be present.
	found := false
	for _, name := range knownDHGroups {
		if name == "RFC 3526 group 14 (2048-bit MODP)" {
			found = true
		}
	}
	require.True(t, found)
}

func upperHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}
