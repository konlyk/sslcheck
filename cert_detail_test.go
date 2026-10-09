package sslcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCertFindings(t *testing.T) {
	now := time.Now()
	require.Equal(t, "HIGH", sev(certFindings(Certificate{ValidityDays: 4000})))
	require.Equal(t, "MEDIUM", sev(certFindings(Certificate{ValidityDays: 2000})))
	require.Equal(t, "MEDIUM", sev(certFindings(Certificate{ValidityDays: 400, NotBefore: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)})))
	require.Empty(t, certFindings(Certificate{ValidityDays: 90, NotBefore: now}))

	crit := certFindings(Certificate{IntermediateExpiry: now.Add(10 * 24 * time.Hour)})
	require.Equal(t, "INTERMEDIATE_EXPIRY", crit[0].Name)
	require.Equal(t, "CRITICAL", crit[0].Severity)

	require.Equal(t, "WEAK_CHAIN_SIGNATURE", certFindings(Certificate{WeakChainSig: "SHA1"})[0].Name)
	require.Equal(t, "CHAIN_ORDER", certFindings(Certificate{ChainOrderProblem: true})[0].Name)
}

func sev(vs []Vuln) string {
	for _, v := range vs {
		if v.Name == "CERT_VALIDITY" {
			return v.Severity
		}
	}
	return ""
}

func signCert(t *testing.T, tmpl, parent *x509.Certificate, pub interface{}, signerKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

// describe fills the detail fields from a real root -> intermediate -> leaf chain: the leaf's
// validity and serial, a must-staple extension, a SHA1-signed intermediate and its expiry, and
// (on a reversed chain) the ordering problem.
func TestDescribeCertificateDetails(t *testing.T) {
	now := time.Now()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root CA", Organization: []string{"Test"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(3650 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	ca := signCert(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	interKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	inter := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate", Organization: []string{"Test"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(25 * 24 * time.Hour), // expires soon
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		SignatureAlgorithm: x509.SHA1WithRSA, // weak intermediate signature
	}, ca, &interKey.PublicKey, caKey)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mustStaple, _ := asn1.Marshal([]int{5})
	leaf := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(0x1234), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(400 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidMustStaple, Value: mustStaple}},
	}, inter, &leafKey.PublicKey, interKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	c := describe(context.Background(), "localhost", []*x509.Certificate{leaf, inter}, nil, Options{Roots: roots, Timeout: time.Second})
	require.Equal(t, 400, c.ValidityDays)
	require.Equal(t, "1234", c.Serial)
	require.Len(t, c.FingerprintSHA1, 40)
	require.True(t, c.MustStaple)
	require.Equal(t, "SHA1", c.WeakChainSig)
	require.False(t, c.IntermediateExpiry.IsZero())
	require.False(t, c.ChainOrderProblem)
	require.True(t, chainOutOfOrder([]*x509.Certificate{inter, leaf}), "reversed chain")
}
