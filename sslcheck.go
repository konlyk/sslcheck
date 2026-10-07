// Package sslcheck assesses a host's TLS the way testssl.sh does, but natively in Go: it opens
// ordinary and crafted TLS connections to the host and reports the protocols and ciphers it
// offers, its certificate chain, the known weaknesses it has, and an SSL Labs grade derived from
// all of it. Nothing is shelled out; every check is a connection this package makes and reads.
//
// Only what Ceeyu uses is ported. testssl's text/CSV/HTML reporters, mass-testing, STARTTLS for
// mail, client simulation and server banners are left out; the scanning checks are kept.
package sslcheck

import (
	"context"
	"crypto/x509"
	"net"
	"time"
)

// Assessment is everything the scan learned about one host's TLS.
type Assessment struct {
	Protocols     []Protocol    // every version, offered or not
	Ciphers       []Cipher      // the accepted ciphers, best protocol first
	Certificates  []Certificate // the chains the host serves, leaf first
	ForwardSecret bool          // every accepted key exchange is ephemeral
	Vulns         []Vuln        // the weaknesses found
	Grade         string        // SSL Labs: A+ … F, or M (name mismatch) / T (not trusted)
	Score         int           // SSL Labs score 0–100, capped by the grade
	Reasons       []string      // why the grade is capped
}

// Protocol is one SSL/TLS version and whether the host offers it.
type Protocol struct {
	Version    uint16
	Name       string // "TLS1_3", "SSLv3" …
	Offered    bool
	Deprecated bool // SSLv2, SSLv3, TLS 1.0, TLS 1.1
}

// Cipher is a cipher suite the host accepts, at a protocol version.
type Cipher struct {
	ID       uint16
	Name     string // the IANA name, "TLS_AES_128_GCM_SHA256"
	Version  string // the protocol it was accepted at
	Strength Strength
	Bits     int  // symmetric key size
	Forward  bool // ephemeral (ECDHE/DHE) key exchange
}

// Certificate is one certificate the host serves.
type Certificate struct {
	Leaf              *x509.Certificate
	CommonName        string
	AltNames          []string
	Issuer            string
	Trusted           bool
	NameMismatch      bool // the certificate is otherwise fine but not for this hostname
	TrustReason       string
	ChainComplete     bool // the host sent the intermediates to a trusted root
	FingerprintSHA256 string
	KeyType           string // "RSA 2048", "EC P-256"
	SignatureAlg      string
	Expires           time.Time
}

// Expired reports whether the certificate's validity has passed.
func (c Certificate) Expired() bool { return !c.Expires.IsZero() && c.Expires.Before(time.Now()) }

// Options tune a scan; the zero value is the normal scan.
type Options struct {
	Timeout    time.Duration  // per connection; 0 = 10s
	ServerName string         // SNI; defaults to the host
	Roots      *x509.CertPool // trust anchors; nil = the system's
}

func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return 10 * time.Second
}

// Scan assesses the TLS of host at addr ("ip:port"). host is the name for SNI and certificate
// matching; addr carries the chosen IP so the caller controls which address is probed.
func Scan(ctx context.Context, host, addr string, opts Options) (*Assessment, error) {
	if opts.ServerName == "" {
		opts.ServerName = host
	}
	a := &Assessment{}
	a.Protocols = scanProtocols(ctx, addr, opts)
	if !anyOffered(a.Protocols) {
		return a, nil // nothing speaks TLS here; the caller treats an empty assessment as "no TLS"
	}
	a.Ciphers = scanCiphers(ctx, addr, a.Protocols, opts)
	a.ForwardSecret = forwardSecret(a.Ciphers)
	a.Certificates = scanCertificates(ctx, host, addr, opts)
	a.Vulns = scanVulns(ctx, host, addr, a, opts)
	a.Score, a.Grade, a.Reasons = grade(a)
	return a, nil
}

func anyOffered(ps []Protocol) bool {
	for _, p := range ps {
		if p.Offered {
			return true
		}
	}
	return false
}

// dial opens a TCP connection to addr under ctx and the per-connection timeout.
func dial(ctx context.Context, addr string, opts Options) (net.Conn, error) {
	d := &net.Dialer{Timeout: opts.timeout()}
	return d.DialContext(ctx, "tcp", addr)
}
