package sslcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// scanCertificates opens one verified connection and describes the certificate the host serves:
// its names, issuer, key, expiry and SHA-256 fingerprint, and whether it is trusted, complete to
// a root, and valid for the hostname. The verdict uses crypto/x509 against the system roots, so
// it tracks what browsers currently trust.
func scanCertificates(ctx context.Context, host, addr string, opts Options) []Certificate {
	// Try modern first, then the legacy floor, so a host that only speaks old TLS still yields its
	// certificate. If stdlib refuses the host's ciphers altogether (an RC4- or 3DES-only host,
	// which crypto/tls will not negotiate), fall back to zcrypto, which still speaks them.
	for _, floor := range []uint16{cryptotls.VersionTLS12, cryptotls.VersionTLS10} {
		if chain, ok := certHandshake(ctx, addr, floor, opts); ok && len(chain) > 0 {
			return []Certificate{describe(host, chain, opts)}
		}
	}
	if chain := certFromLegacy(ctx, addr, opts); len(chain) > 0 {
		return []Certificate{describe(host, chain, opts)}
	}
	return nil
}

func certHandshake(ctx context.Context, addr string, minVersion uint16, opts Options) ([]*x509.Certificate, bool) {
	d := &cryptotls.Dialer{Config: &cryptotls.Config{
		MinVersion: minVersion, ServerName: opts.ServerName, InsecureSkipVerify: true, // we verify by hand, below
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	return conn.(*cryptotls.Conn).ConnectionState().PeerCertificates, true
}

// certFromLegacy gets the served chain through zcrypto, which negotiates the weak ciphers (RC4,
// 3DES) that crypto/tls refuses. The certificates are re-parsed with crypto/x509 so the trust
// verdict is the current one.
func certFromLegacy(ctx context.Context, addr string, opts Options) []*x509.Certificate {
	for _, version := range []uint16{ztls.VersionTLS12, ztls.VersionTLS10} {
		log, err := legacyHandshake(ctx, addr, version, cipherIDs(), opts)
		if err != nil || log == nil || log.ServerCertificates == nil {
			continue
		}
		var chain []*x509.Certificate
		raws := append([][]byte{log.ServerCertificates.Certificate.Raw}, chainRaws(log.ServerCertificates.Chain)...)
		for _, raw := range raws {
			if c, err := x509.ParseCertificate(raw); err == nil {
				chain = append(chain, c)
			}
		}
		if len(chain) > 0 {
			return chain
		}
	}
	return nil
}

func chainRaws(chain []ztls.SimpleCertificate) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, c := range chain {
		out = append(out, c.Raw)
	}
	return out
}

// describe turns the served chain (leaf first) into a Certificate, verifying it against the roots.
func describe(host string, chain []*x509.Certificate, opts Options) Certificate {
	leaf := chain[0]
	c := Certificate{
		Leaf: leaf, CommonName: leaf.Subject.CommonName, AltNames: leaf.DNSNames,
		Issuer: leaf.Issuer.CommonName, FingerprintSHA256: fingerprint(leaf),
		KeyType: keyType(leaf), SignatureAlg: leaf.SignatureAlgorithm.String(), Expires: leaf.NotAfter,
	}
	intermediates := x509.NewCertPool()
	for _, ic := range chain[1:] {
		intermediates.AddCert(ic)
	}
	// Trust and completeness: a full chain to a trusted root, without relying on the name.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: opts.Roots, Intermediates: intermediates, CurrentTime: time.Now()}); err == nil {
		c.ChainComplete = true
	}
	// The name match is a separate verdict: a trusted certificate can still be for another host.
	if err := leaf.VerifyHostname(host); err != nil {
		c.Trusted, c.NameMismatch, c.TrustReason = false, true, err.Error()
		return c
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: opts.Roots, Intermediates: intermediates, CurrentTime: time.Now()}); err != nil {
		c.Trusted = false
		c.TrustReason = err.Error()
		return c
	}
	c.Trusted, c.TrustReason = true, "verified to a trusted root and valid for the hostname"
	return c
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	var b strings.Builder
	for _, x := range sum {
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String()
}

func keyType(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("EC %s", pub.Curve.Params().Name)
	default:
		return c.PublicKeyAlgorithm.String()
	}
}
