package sslcheck

import (
	"context"
	cryptotls "crypto/tls"
	"strings"

	ztls "github.com/zmap/zcrypto/tls"
)

// ecdheSuites are the ECDHE suites offered to read the server's negotiated curve.
var ecdheSuites = []uint16{0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc013, 0xc014, 0xc009, 0xc00a}

// scanConnection reads properties of the negotiated connection that testssl reports but that do
// not themselves feed the grade: the ECDHE curve the server chose, the ALPN protocols it
// advertises, and whether it issues a session ticket. Each is best-effort; an empty value means
// the server offered none or the probe got no answer.
func scanConnection(ctx context.Context, addr string, protocols []Protocol, opts Options) (curve string, alpn []string, ticket bool) {
	version := bestLegacyVersion(protocols)
	if version != 0 {
		// zcrypto offers the session-ticket extension only when told to (or when it has a session
		// cache); without it no server answers with one and tickets could never be seen.
		log, _ := legacyHandshakeWith(ctx, addr, version, ecdheSuites, opts, func(c *ztls.Config) {
			c.ForceSessionTicketExt = true
		})
		if log != nil {
			if sh := log.ServerHello; sh != nil {
				ticket = sh.TicketSupported
			}
			if ske := log.ServerKeyExchange; ske != nil && ske.ECDHParams != nil {
				curve = strings.TrimSpace(ske.ECDHParams.TLSCurveID.Description())
			}
		}
	}
	alpn = scanALPN(ctx, addr, opts)
	return curve, alpn, ticket
}

// scanALPN asks, over whatever TLS version crypto/tls negotiates, which of the common application
// protocols the server selects; testssl lists these as the host's ALPN/HTTP2 support.
func scanALPN(ctx context.Context, addr string, opts Options) []string {
	var out []string
	for _, proto := range []string{"h2", "http/1.1"} {
		if ctx.Err() != nil {
			break
		}
		conn, err := tlsClient(ctx, addr, &cryptotls.Config{
			ServerName: opts.ServerName, InsecureSkipVerify: true, //nolint:gosec // reading ALPN, not trusting
			MinVersion: cryptotls.VersionTLS10, NextProtos: []string{proto},
		}, opts)
		if err != nil {
			continue
		}
		if p := conn.ConnectionState().NegotiatedProtocol; p != "" && !contains(out, p) {
			out = append(out, p)
		}
		_ = conn.Close()
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// dhParams is the DH group the host uses at version: its size in bits, and a name when the prime
// is a well-known one (an RFC group or a software default), which is what makes it precomputable.
func dhParams(ctx context.Context, addr string, version uint16, opts Options) (bits int, group string) {
	var dheSuites []uint16
	for _, c := range knownCiphers {
		if has(strings.ToUpper(c.name), "DHE_") && !has(strings.ToUpper(c.name), "ECDHE") {
			dheSuites = append(dheSuites, c.id)
		}
	}
	if version == 0 {
		return 0, ""
	}
	for len(dheSuites) > 0 {
		if ctx.Err() != nil {
			return 0, ""
		}
		log, _ := legacyHandshake(ctx, addr, version, dheSuites, opts)
		if log == nil || log.ServerHello == nil {
			return 0, ""
		}
		if ske := log.ServerKeyExchange; ske != nil && ske.DHParams != nil && ske.DHParams.Prime != nil {
			prime := ske.DHParams.Prime
			return prime.BitLen(), knownDHGroups[strings.ToUpper(prime.Text(16))]
		}
		before := len(dheSuites)
		dheSuites = remove(dheSuites, uint16(log.ServerHello.CipherSuite))
		if len(dheSuites) == before {
			return 0, ""
		}
	}
	return 0, ""
}
