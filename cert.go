package sslcheck

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // reading old DSA certificates, not making keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/crypto/ocsp"
)

// scanCertificates collects every certificate the host serves, one per key type, as testssl
// does: a host can hold an ECDSA and an RSA certificate and pick by the client's ciphers. Each is
// described and verified on its own; all of them count for the grade.
func scanCertificates(ctx context.Context, host, addr string, opts Options) []Certificate {
	var out []Certificate
	seen := map[string]bool{}
	add := func(chain []*x509.Certificate, staple []byte) {
		if len(chain) == 0 {
			return
		}
		fp := fingerprint(chain[0])
		if seen[fp] {
			return
		}
		seen[fp] = true
		out = append(out, describe(ctx, host, chain, staple, opts))
	}
	// The host's default, then each key type forced through TLS 1.2 cipher suites. The forced
	// handshakes go through zcrypto: some servers (Google's) refuse crypto/tls's RSA-only TLS 1.2
	// ClientHello but answer OpenSSL's, which zcrypto's resembles.
	add(certHandshake(ctx, addr, opts, nil))
	add(legacyChain(ctx, addr, ecdsaSuites, opts), nil)
	add(legacyChain(ctx, addr, rsaSuites, opts), nil)
	if len(out) == 0 {
		// crypto/tls refuses the host's ciphers altogether (an RC4- or 3DES-only host): zcrypto
		// still speaks them.
		add(certFromLegacy(ctx, addr, opts), nil)
	}
	return out
}

// The TLS 1.2 suites that make the server present its ECDSA, or its RSA, certificate.
var (
	ecdsaSuites = []uint16{
		cryptotls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, cryptotls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		cryptotls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, cryptotls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		cryptotls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}
	rsaSuites = []uint16{
		cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, cryptotls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		cryptotls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, cryptotls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		cryptotls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, cryptotls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		cryptotls.TLS_RSA_WITH_AES_256_GCM_SHA384, cryptotls.TLS_RSA_WITH_AES_128_CBC_SHA,
		cryptotls.TLS_RSA_WITH_AES_256_CBC_SHA, cryptotls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
)

// certHandshake completes one handshake and returns the served chain and any stapled OCSP
// response. With suites set, the handshake is TLS 1.2 limited to them.
func certHandshake(ctx context.Context, addr string, opts Options, suites []uint16) ([]*x509.Certificate, []byte) {
	cfg := &cryptotls.Config{ServerName: opts.ServerName, InsecureSkipVerify: true, MinVersion: cryptotls.VersionTLS10} //nolint:gosec // verified by hand
	if suites != nil {
		cfg.MaxVersion, cfg.CipherSuites = cryptotls.VersionTLS12, suites
	}
	d := &cryptotls.Dialer{NetDialer: nil, Config: cfg}
	cctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	st := conn.(*cryptotls.Conn).ConnectionState()
	return st.PeerCertificates, st.OCSPResponse
}

// certFromLegacy gets the served chain through zcrypto, which negotiates the weak ciphers (RC4,
// 3DES) that crypto/tls refuses. The certificates are re-parsed with crypto/x509 so the trust
// verdict is the current one.
func certFromLegacy(ctx context.Context, addr string, opts Options) []*x509.Certificate {
	for _, version := range []uint16{ztls.VersionTLS12, ztls.VersionTLS10, ztls.VersionSSL30} {
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

// legacyChain is the chain the server presents to a TLS 1.2 zcrypto handshake offering only
// suites.
func legacyChain(ctx context.Context, addr string, suites []uint16, opts Options) []*x509.Certificate {
	log, _ := legacyHandshake(ctx, addr, ztls.VersionTLS12, suites, opts)
	if log == nil || log.ServerCertificates == nil {
		return nil
	}
	var chain []*x509.Certificate
	raws := append([][]byte{log.ServerCertificates.Certificate.Raw}, chainRaws(log.ServerCertificates.Chain)...)
	for _, raw := range raws {
		if c, err := x509.ParseCertificate(raw); err == nil {
			chain = append(chain, c)
		}
	}
	return chain
}

func chainRaws(chain []ztls.SimpleCertificate) [][]byte {
	out := make([][]byte, 0, len(chain))
	for _, c := range chain {
		out = append(out, c.Raw)
	}
	return out
}

// describe turns a served chain (leaf first) into a Certificate: what it is, whether it is trusted
// for host, and whether it is revoked.
func describe(ctx context.Context, host string, chain []*x509.Certificate, staple []byte, opts Options) Certificate {
	leaf := chain[0]
	c := Certificate{
		Leaf: leaf, Chain: chain, CommonName: leaf.Subject.CommonName, AltNames: leaf.DNSNames,
		Issuer: leaf.Issuer.CommonName, FingerprintSHA256: fingerprint(leaf),
		SignatureAlg: leaf.SignatureAlgorithm.String(), SignatureHash: signatureHash(leaf.SignatureAlgorithm),
		Expires: leaf.NotAfter, OCSPStapled: len(staple) > 0,
	}
	c.KeyAlg, c.KeyBits, c.RSAExponent = keyInfo(leaf)
	c.KeyType = keyType(leaf)
	// testssl: no issuer organisation, or the issuer's CN is the subject's.
	c.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject) ||
		(leaf.Issuer.CommonName != "" && leaf.Issuer.CommonName == leaf.Subject.CommonName)

	intermediates := x509.NewCertPool()
	for _, ic := range chain[1:] {
		intermediates.AddCert(ic)
	}
	// Trust and completeness, as testssl reads OpenSSL's verify result: a full chain to a trusted
	// root, without relying on the name.
	_, chainErr := leaf.Verify(x509.VerifyOptions{Roots: opts.Roots, Intermediates: intermediates, CurrentTime: time.Now()})
	if chainErr == nil {
		c.ChainComplete = true
	} else {
		c.ChainError, c.ChainIncomplete = opensslVerifyError(chain, chainErr, c.SelfSigned)
	}
	c.Revoked, c.RevocationSource = revoked(ctx, leaf, chain, staple, opts)

	// The name match is a separate verdict: a trusted certificate can still be for another host.
	if err := leaf.VerifyHostname(host); err != nil {
		c.Trusted, c.NameMismatch, c.TrustReason = false, true, err.Error()
		return c
	}
	switch {
	case chainErr != nil:
		c.Trusted, c.TrustReason = false, c.ChainError+": "+chainErr.Error()
	default:
		c.Trusted, c.TrustReason = true, "verified to a trusted root and valid for the hostname"
	}
	return c
}

// opensslVerifyError names a failed chain the way testssl prints OpenSSL's verify result, and says
// whether it is the "chain incomplete" kind (codes 20 and 21: an issuer is neither served nor a
// trusted root), which testssl caps to B instead of T.
func opensslVerifyError(chain []*x509.Certificate, err error, leafSelfSigned bool) (reason string, incomplete bool) {
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) && inv.Reason == x509.Expired {
		if time.Now().Before(chain[0].NotBefore) {
			return "not yet valid", false
		}
		return "expired", false
	}
	if leafSelfSigned && len(chain) == 1 {
		return "self signed", false
	}
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ua) {
		return "not trusted", false
	}
	// Follow the served chain from the leaf by issuer; where it ends decides the code.
	top := chain[0]
	used := map[int]bool{0: true}
	for {
		next := -1
		for i, cand := range chain {
			if !used[i] && bytes.Equal(top.RawIssuer, cand.RawSubject) {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		used[next] = true
		top = chain[next]
	}
	switch {
	case bytes.Equal(top.RawIssuer, top.RawSubject) && top != chain[0]:
		return "self signed CA in chain", false
	case bytes.Equal(top.RawIssuer, top.RawSubject):
		return "self signed", false
	default:
		// OpenSSL reports "unable to get local issuer certificate" (code 20) whether the server
		// sent some intermediates or only the leaf, so both word the same as testssl's.
		return "chain incomplete", true
	}
}

// revoked reads a stapled OCSP response and, when asked to, the leaf's OCSP responder.
func revoked(ctx context.Context, leaf *x509.Certificate, chain []*x509.Certificate, staple []byte, opts Options) (bool, string) { //nolint:gocyclo
	if len(chain) < 2 {
		return false, ""
	}
	issuer := chain[1]
	if len(staple) > 0 {
		if r, err := ocsp.ParseResponseForCert(staple, leaf, issuer); err == nil && r.Status == ocsp.Revoked {
			return true, "stapled OCSP"
		}
	}
	if !opts.CheckRevocation || len(leaf.OCSPServer) == 0 {
		return false, ""
	}
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, ""
	}
	cctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	hr, err := http.NewRequestWithContext(cctx, http.MethodPost, leaf.OCSPServer[0], bytes.NewReader(req))
	if err != nil {
		return false, ""
	}
	hr.Header.Set("Content-Type", "application/ocsp-request")
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, ""
	}
	if r, err := ocsp.ParseResponseForCert(body, leaf, issuer); err == nil && r.Status == ocsp.Revoked {
		return true, leaf.OCSPServer[0]
	}
	return false, ""
}

func httpGet(ctx context.Context, url string, opts Options) []byte {
	cctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return body
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

// keyInfo is the key's algorithm as testssl names it for the key-exchange score, its size in
// bits, and the RSA exponent.
func keyInfo(c *x509.Certificate) (alg string, bits, exponent int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen(), pub.E
	case *ecdsa.PublicKey:
		return "EC", pub.Curve.Params().BitSize, 0
	case *dsa.PublicKey:
		return "DSA", pub.P.BitLen(), 0
	case ed25519.PublicKey:
		return "EdDSA", 253, 0
	default:
		return c.PublicKeyAlgorithm.String(), 0, 0
	}
}

// signatureHash is the hash of the certificate's signature, as the grade looks at it.
func signatureHash(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA1"
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return "SHA256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return "SHA384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return "SHA512"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return a.String()
	}
}
