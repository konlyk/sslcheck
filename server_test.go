package sslcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// localServer starts an in-process TLS server on 127.0.0.1 with the given config and a self-signed
// RSA 2048 certificate for "localhost", and returns its address and the pool that trusts it. It
// serves until the test ends. It lets the scan run against a real handshake rather than the
// network, so protocol detection, cipher enumeration, certificate description and the grade are
// all exercised end to end.
func localServer(t *testing.T, cfg *cryptotls.Config) (addr string, roots *x509.CertPool) {
	t.Helper()
	// A self-signed root CA, and a leaf it signs for "localhost"; the server presents the leaf and
	// the test trusts the root, so the leaf is a normal, trusted, non-self-signed certificate.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sslcheck test CA", Organization: []string{"sslcheck test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots = x509.NewCertPool()
	roots.AddCert(ca)

	cfg = cfg.Clone()
	cfg.Certificates = []cryptotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}
	ln, err := cryptotls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				tc := conn.(*cryptotls.Conn)
				if tc.Handshake() == nil {
					_ = tc.CloseWrite()
				}
			}()
		}
	}()
	return ln.Addr().String(), roots
}

// A modern server (TLS 1.2 + 1.3, a trusted certificate) is detected, enumerated, described and
// graded end to end.
func TestScanModernServer(t *testing.T) {
	addr, roots := localServer(t, &cryptotls.Config{
		MinVersion: cryptotls.VersionTLS12, MaxVersion: cryptotls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := Scan(ctx, "localhost", addr, Options{Roots: roots, Timeout: 3 * time.Second, SkipHTTP: true})
	require.NoError(t, err)

	require.True(t, offered(a, "TLS1_2"))
	require.True(t, offered(a, "TLS1_3"))
	require.False(t, offered(a, "TLS1"), "server floor is TLS 1.2")
	require.False(t, offered(a, "SSLv3"))
	require.False(t, offered(a, "SSLv2"))

	require.NotEmpty(t, a.Ciphers)
	require.Equal(t, "TLS1_3", a.Ciphers[0].Version, "ciphers are ordered best protocol first")
	require.True(t, anyAt(a, "TLS1_2"), "TLS 1.2 suites are enumerated too")

	require.Len(t, a.Certificates, 1)
	c := a.Certificates[0]
	require.True(t, c.Trusted, c.TrustReason)
	require.False(t, c.NameMismatch)
	require.Equal(t, "RSA 2048", c.KeyType)

	require.Contains(t, []string{"A", "A-", "A+"}, a.Grade, a.Reasons)
}

// A legacy server (TLS 1.0–1.2, a CBC suite zcrypto negotiates) is detected and capped at B for
// the old protocols, and the weakness findings that follow from the ciphers are raised.
func TestScanLegacyServer(t *testing.T) {
	addr, roots := localServer(t, &cryptotls.Config{
		MinVersion: cryptotls.VersionTLS10, MaxVersion: cryptotls.VersionTLS12,
		CipherSuites: []uint16{
			cryptotls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			cryptotls.TLS_RSA_WITH_AES_128_CBC_SHA,
			cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := Scan(ctx, "localhost", addr, Options{Roots: roots, Timeout: 3 * time.Second, SkipHTTP: true})
	require.NoError(t, err)

	require.True(t, offered(a, "TLS1"))
	require.True(t, offered(a, "TLS1_1"))
	require.True(t, offered(a, "TLS1_2"))
	require.False(t, offered(a, "TLS1_3"))

	require.True(t, hasCipher(a, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"))
	require.Equal(t, "B", a.Grade, a.Reasons)
	require.Contains(t, a.Reasons, "Grade capped to B. TLS 1.0 offered")
	require.True(t, hasVuln(a, "BEAST"), "CBC on TLS 1.0")
	require.True(t, hasVuln(a, "LUCKY13"), "a CBC suite is accepted")
}

func offered(a *Assessment, name string) bool {
	for _, p := range a.Protocols {
		if p.Name == name {
			return p.Offered
		}
	}
	return false
}

func anyAt(a *Assessment, version string) bool {
	for _, c := range a.Ciphers {
		if c.Version == version {
			return true
		}
	}
	return false
}

func hasCipher(a *Assessment, name string) bool {
	for _, c := range a.Ciphers {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasVuln(a *Assessment, name string) bool {
	for _, v := range a.Vulns {
		if v.Name == name {
			return true
		}
	}
	return false
}
