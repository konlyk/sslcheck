package sslcheck

import (
	"context"
	"time"
)

// scsvValue is TLS_FALLBACK_SCSV, the signalling cipher a client includes when it has already
// fallen back to a lower version, so a server that supports higher versions can refuse the
// downgrade (RFC 7507).
const scsvValue = 0x5600

// scanFallbackSCSV reports whether the server honours TLS_FALLBACK_SCSV: offered a handshake at a
// version below the best it speaks, with the SCSV present, a server that honours it answers with
// an inappropriate_fallback alert (86), which is what blocks a protocol-downgrade attack. The
// result is nil when there is no lower version to fall back from (one protocol, or TLS 1.3 only),
// where the signal does not apply.
func scanFallbackSCSV(ctx context.Context, addr string, protocols []Protocol, opts Options) (supported *bool) {
	best, fallback := bestAndFallback(protocols)
	if best == 0 || fallback == 0 {
		return nil // nothing to fall back from
	}
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return nil
	}
	defer r.close()
	_ = r.conn.SetDeadline(time.Now().Add(opts.timeout()))
	// A hello at the fallback version, offering the host's suites plus the SCSV.
	suites := append(cipherIDs(), scsvValue)
	if err := r.writeRecord(recHandshake, 0x0301, fallbackHello(opts.ServerName, fallback, suites)); err != nil {
		return nil
	}
	typ, body, err := r.readRecord()
	yes, no := true, false
	if a, ok := asAlert(err); ok {
		if a.code == 86 { // inappropriate_fallback: the server refused the downgrade
			return &yes
		}
		return nil // refused for some other reason: says nothing about the SCSV
	}
	if err != nil {
		return nil // a dropped connection is not an answer
	}
	if typ == recHandshake && len(body) >= 4 && body[0] == hsServerHello {
		return &no // the server went ahead at the lower version: the protection is absent
	}
	return nil
}

// bestAndFallback are the best protocol version the host offers that zcrypto can send, and the
// next one below it to fall back from; either is 0 when there is none (TLS 1.3 only, or a single
// version).
func bestAndFallback(protocols []Protocol) (best, fallback uint16) {
	var versions []uint16
	for _, p := range protocols {
		if p.Offered && p.Version != versionSSL20 && p.Version != versionTLS13 {
			versions = append(versions, p.Version)
		}
	}
	for _, v := range versions {
		if v > best {
			best = v
		}
	}
	for _, v := range versions {
		if v < best && v > fallback {
			fallback = v
		}
	}
	return best, fallback
}

// fallbackHello is a ClientHello at the given legacy version offering suites, built like the
// probe ClientHello but with a chosen client_version so the SCSV has a version to fall back from.
func fallbackHello(serverName string, version uint16, suites []uint16) []byte {
	hello := clientHello(serverName, suites, nil, nil)
	// clientHello writes client_version at the first two bytes of the handshake body (after the
	// 4-byte handshake header); set it to the fallback version.
	if len(hello) >= 6 {
		hello[4] = byte(version >> 8)
		hello[5] = byte(version)
	}
	return hello
}
