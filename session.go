package sslcheck

import (
	"context"

	ztls "github.com/zmap/zcrypto/tls"
)

// scanSessionFeatures checks two properties of the TLS 1.2-and-older handshake: whether the
// server agrees to TLS compression (CRIME), and whether it supports RFC 5746 secure
// renegotiation. Both are tested at the best protocol below TLS 1.3 the host offers; a host that
// speaks only TLS 1.3 has neither, and renegotiation is reported as not applicable (nil).
func scanSessionFeatures(ctx context.Context, addr string, protocols []Protocol, opts Options) (compression bool, secureReneg *bool) {
	version := bestLegacyVersion(protocols)
	if version == 0 {
		return false, nil
	}
	// The ServerHello carries both answers, so it counts whether or not zcrypto finishes the
	// handshake after it (it will not when the server picks a suite it cannot complete, and it
	// never does when the server picks DEFLATE, which it does not implement).
	if log, _ := legacyHandshake(ctx, addr, version, cipherIDs(), opts); log != nil && log.ServerHello != nil {
		v := log.ServerHello.SecureRenegotiation
		secureReneg = &v
	}
	// Offer DEFLATE first: a server that compresses picks it.
	log, _ := legacyHandshakeWith(ctx, addr, version, cipherIDs(), opts, func(c *ztls.Config) {
		c.CompressionMethods = []uint8{compressionDeflate, compressionNone}
	})
	if log != nil && log.ServerHello != nil {
		compression = uint8(log.ServerHello.CompressionMethod) == compressionDeflate
	}
	return compression, secureReneg
}

const (
	compressionNone    = 0
	compressionDeflate = 1
)

// bestLegacyVersion is the best protocol offered that zcrypto speaks (SSLv3 to TLS 1.2), or 0 when
// there is none.
func bestLegacyVersion(protocols []Protocol) uint16 {
	var version uint16
	for _, p := range protocols {
		if p.Offered && p.Version != versionTLS13 && p.Version != versionSSL20 && p.Version > version {
			version = p.Version
		}
	}
	return version
}
