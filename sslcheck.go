// Package sslcheck assesses a host's TLS the way testssl.sh does, but natively in Go: it opens
// ordinary and crafted TLS connections to the host and reports the protocols and ciphers it
// offers, its certificate chain, the known weaknesses it has, and an SSL Labs grade derived from
// all of it. Nothing is shelled out; every check is a connection this package makes and reads.
//
// It ports testssl's scanning checks only; its text/CSV/HTML reporters, mass-testing, STARTTLS for
// mail, client simulation and server banners are left out.
package sslcheck

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"time"
)

// Assessment is everything the scan learned about one host's TLS.
type Assessment struct {
	Protocols     []Protocol    // every version, offered or not
	Ciphers       []Cipher      // the accepted ciphers, best protocol first
	Certificates  []Certificate // one per certificate type served (RSA, ECDSA …), leaf described
	ForwardSecret bool          // every accepted key exchange is ephemeral
	Vulns         []Vuln        // the weaknesses found

	// Compression is whether the server agreed to TLS-level compression (CRIME).
	Compression bool
	// SecureRenegotiation is whether the server supports RFC 5746 secure renegotiation; nil when
	// it offers no protocol below TLS 1.3, where renegotiation does not exist.
	SecureRenegotiation *bool
	// HTTP is what the server's HTTP answer says about TLS (HSTS, HPKP); nil when not fetched.
	HTTP *HTTPHeaders

	// The rating, as testssl computes it from SSL Labs's SSL Server Rating Guide.
	Grade               string   // A+ … F, M (name mismatch) or T (not trusted)
	Score               int      // 0–100; 0 when the grade is F, T or M
	ProtocolScore       int      // category 1, protocol support
	KeyExchangeScore    int      // category 2, key exchange
	CipherStrengthScore int      // category 3, cipher strength
	Reasons             []string // the caps applied, worst first
	Warnings            []string // what keeps an A from an A+ (it is then an A-)
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
	Leaf              *x509.Certificate   `json:"-"` // the parsed leaf, for callers; too large to serialise
	Chain             []*x509.Certificate `json:"-"` // as served, leaf first; for callers, not serialised
	CommonName        string
	AltNames          []string
	Issuer            string
	Trusted           bool
	NameMismatch      bool // the certificate is otherwise fine but not for this hostname
	TrustReason       string
	ChainComplete     bool   // the host sent the intermediates to a trusted root
	ChainIncomplete   bool   // an issuer is neither served nor a trusted root (OpenSSL codes 20/21)
	ChainError        string // why the chain fails, as testssl words OpenSSL's verify result
	SelfSigned        bool
	FingerprintSHA256 string
	KeyType           string // "RSA 2048", "EC P-256"
	KeyAlg            string // "RSA", "EC", "DSA", "EdDSA"
	KeyBits           int    // RSA/DSA modulus or EC curve size; Ed25519 253
	RSAExponent       int    // RSA public exponent; 0 for other keys
	SignatureAlg      string
	SignatureHash     string // "SHA1", "SHA256", "MD5", "MD2" …
	Expires           time.Time
	OCSPStapled       bool
	Revoked           bool   // stapled OCSP, or (Options.CheckRevocation) the responder, says revoked
	RevocationSource  string // "stapled OCSP" or the responder's URL
}

// Expired reports whether the certificate's validity has passed.
func (c Certificate) Expired() bool { return !c.Expires.IsZero() && c.Expires.Before(time.Now()) }

// Options tune a scan; the zero value is the normal scan.
type Options struct {
	Timeout    time.Duration // per connection; 0 = 10s
	ServerName string        // SNI; defaults to the host
	// Roots is the set of trust anchors for the certificate verdict; nil uses the system's. With
	// nil, Go's verifier may also fetch a missing intermediate from the certificate's AIA URL on
	// macOS and Windows but not on Linux, so an incomplete chain can grade differently by platform.
	// Pass an explicit pool for a deterministic verdict.
	Roots *x509.CertPool
	// CheckRevocation also asks the certificate's OCSP responder, as testssl's --phone-out does.
	// A stapled OCSP response is always read.
	CheckRevocation bool
	// SkipHTTP leaves out the HTTP request that reads HSTS and HPKP, for non-HTTP services.
	SkipHTTP bool
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
	// The remaining checks read only the protocols and ciphers just found, each opens its own
	// connections, and each writes its own field, so they run concurrently.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); a.Certificates = scanCertificates(ctx, host, addr, opts) }()
	go func() {
		defer wg.Done()
		a.Compression, a.SecureRenegotiation = scanSessionFeatures(ctx, addr, a.Protocols, opts)
	}()
	go func() { defer wg.Done(); a.Vulns = scanVulns(ctx, addr, a, opts) }()
	if !opts.SkipHTTP {
		wg.Add(1)
		go func() { defer wg.Done(); a.HTTP = fetchHTTPHeaders(ctx, host, addr, opts) }()
	}
	wg.Wait()
	rate(a)
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
