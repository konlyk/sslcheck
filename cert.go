package sslcheck

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // reading old DSA certificates, not making keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // fingerprint only
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/asn1"
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
	if len(out) == 0 {
		// Not even zcrypto can complete a handshake (a NULL- or anonymous-only host): the raw
		// client still reads the Certificate message out of the server's first flight.
		add(rawChain(ctx, addr, opts), nil)
	}
	return out
}

// rawChain is the chain in the Certificate message a raw TLS 1.2 handshake offering every known
// suite gets back. It needs no cipher implementation, so it works whatever the host accepts.
func rawChain(ctx context.Context, addr string, opts Options) []*x509.Certificate {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return nil
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, cipherIDs(), nil, nil)); err != nil {
		return nil
	}
	msgs, _ := r.readUntilServerHelloDone() // whatever arrived before any failure still counts
	return certificatesFromMessage(msgs[hsCertificate])
}

// certificatesFromMessage parses the certificates in a TLS Certificate handshake message, leaf
// first, skipping any that do not parse.
func certificatesFromMessage(msg []byte) []*x509.Certificate {
	if len(msg) < 3 {
		return nil
	}
	list := msg[3:] // after the 3-byte list length
	var out []*x509.Certificate
	for len(list) >= 3 {
		n := int(list[0])<<16 | int(list[1])<<8 | int(list[2])
		if len(list) < 3+n {
			break
		}
		if c, err := x509.ParseCertificate(list[3 : 3+n]); err == nil {
			out = append(out, c)
		}
		list = list[3+n:]
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
	conn, err := tlsClient(ctx, addr, cfg, opts)
	if err != nil {
		return nil, nil
	}
	defer conn.Close()
	st := conn.ConnectionState()
	return st.PeerCertificates, st.OCSPResponse
}

// certFromLegacy gets the served chain through zcrypto, which negotiates the weak ciphers (RC4,
// 3DES) that crypto/tls refuses. The certificates are re-parsed with crypto/x509 so the trust
// verdict is the current one.
func certFromLegacy(ctx context.Context, addr string, opts Options) []*x509.Certificate {
	for _, version := range []uint16{ztls.VersionTLS12, ztls.VersionTLS10, ztls.VersionSSL30} {
		// The chain is logged as soon as the Certificate message is read, whatever happens later.
		log, _ := legacyHandshake(ctx, addr, version, cipherIDs(), opts)
		if log == nil || log.ServerCertificates == nil {
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
	c.NotBefore = leaf.NotBefore
	c.Serial = strings.ToUpper(leaf.SerialNumber.Text(16))
	c.FingerprintSHA1 = sha1Fingerprint(leaf)
	c.ValidityDays = int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
	c.MustStaple = hasMustStaple(leaf)
	c.Transparency = hasSCT(leaf) || ocspHasSCT(staple)
	c.ChainOrderProblem = chainOutOfOrder(chain)
	c.WeakChainSig, c.IntermediateExpiry = chainSignatureAndExpiry(chain)
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

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	var b strings.Builder
	for _, x := range sum {
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String()
}

// certFindings are the weaknesses that follow from a described certificate, as testssl reports
// them (findings, not grade caps): an over-long validity, an intermediate about to expire, a
// SHA1/MD5/MD2-signed intermediate, and a mis-ordered chain.
func certFindings(c Certificate) []Vuln {
	var out []Vuln
	switch {
	case c.ValidityDays >= 3650:
		out = append(out, Vuln{"CERT_VALIDITY", "HIGH", "", "CWE-295", "the certificate is valid for " + itoa(c.ValidityDays) + " days, over ten years"})
	case c.ValidityDays >= 1825:
		out = append(out, Vuln{"CERT_VALIDITY", "MEDIUM", "", "CWE-295", "the certificate is valid for " + itoa(c.ValidityDays) + " days, over five years"})
	case c.ValidityDays > 398 && c.NotBefore.Year() >= 2020 && !c.NotBefore.Before(sept2020):
		out = append(out, Vuln{"CERT_VALIDITY", "MEDIUM", "", "CWE-295", "the certificate is valid for " + itoa(c.ValidityDays) + " days, over the 398-day maximum for certificates issued since September 2020"})
	}
	if !c.IntermediateExpiry.IsZero() {
		switch days := int(time.Until(c.IntermediateExpiry).Hours() / 24); {
		case days <= 20:
			out = append(out, Vuln{"INTERMEDIATE_EXPIRY", "CRITICAL", "", "CWE-324", "an intermediate certificate expires in " + itoa(days) + " days"})
		case days <= 40:
			out = append(out, Vuln{"INTERMEDIATE_EXPIRY", "HIGH", "", "CWE-324", "an intermediate certificate expires in " + itoa(days) + " days"})
		}
	}
	if c.WeakChainSig != "" {
		out = append(out, Vuln{"WEAK_CHAIN_SIGNATURE", "MEDIUM", "", "CWE-327", "an intermediate certificate is signed with " + c.WeakChainSig})
	}
	if c.ChainOrderProblem {
		out = append(out, Vuln{"CHAIN_ORDER", "LOW", "", "CWE-295", "the server sends the certificate chain out of order"})
	}
	return out
}

// sept2020 is the date after which the CA/Browser Forum caps leaf validity at 398 days.
var sept2020 = time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)

func sha1Fingerprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw) //nolint:gosec // a fingerprint, not a signature
	var b strings.Builder
	for _, x := range sum {
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String()
}

// OIDs for the certificate features testssl reports.
var (
	oidMustStaple     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}       // TLS feature
	oidSCTList        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2} // CT precert SCTs
	oidSCTOCSP        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5} // CT SCTs in OCSP
	oidFeatureID  int = 5                                                       // status_request, for must-staple
)

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

// hasMustStaple reports whether the leaf carries the TLS-feature extension listing status_request,
// which commits the server to stapling an OCSP response.
func hasMustStaple(c *x509.Certificate) bool {
	v := hasExtension(c, oidMustStaple)
	if v == nil {
		return false
	}
	var features []int
	if _, err := asn1.Unmarshal(v, &features); err != nil {
		return false
	}
	for _, f := range features {
		if f == oidFeatureID {
			return true
		}
	}
	return false
}

func hasSCT(c *x509.Certificate) bool { return hasExtension(c, oidSCTList) != nil }

// ocspHasSCT reports whether a stapled OCSP response carries a CT SCT extension, found by its OID
// encoded in the DER (the x509 OCSP parser does not expose it).
func ocspHasSCT(staple []byte) bool {
	if len(staple) == 0 {
		return false
	}
	der, err := asn1.Marshal(oidSCTOCSP)
	if err != nil {
		return false
	}
	return bytes.Contains(staple, der)
}

// chainOutOfOrder reports whether the served chain is not in leaf-to-root order: each certificate
// after the first should be the issuer of the one before it.
func chainOutOfOrder(chain []*x509.Certificate) bool {
	for i := 1; i < len(chain); i++ {
		if !bytes.Equal(chain[i].RawSubject, chain[i-1].RawIssuer) {
			return true
		}
	}
	return false
}

// chainSignatureAndExpiry reports the weakest signature hash among the non-leaf certificates (when
// SHA1/MD5/MD2, else "") and the soonest intermediate expiry; a self-signed root in the chain is
// not counted, as its own signature does not matter.
func chainSignatureAndExpiry(chain []*x509.Certificate) (weak string, soonest time.Time) {
	for _, c := range chain[1:] {
		selfSigned := bytes.Equal(c.RawIssuer, c.RawSubject)
		if h := signatureHash(c.SignatureAlgorithm); !selfSigned && (h == "SHA1" || h == "MD5" || h == "MD2") {
			weak = h
		}
		if !selfSigned && (soonest.IsZero() || c.NotAfter.Before(soonest)) {
			soonest = c.NotAfter
		}
	}
	return weak, soonest
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
