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
	span := func(days int, from time.Time) Certificate {
		return Certificate{NotBefore: from, Expires: from.Add(time.Duration(days) * 24 * time.Hour), ValidityDays: days}
	}
	require.Equal(t, "HIGH", sev(certFindings(span(4000, now))))
	require.Equal(t, "MEDIUM", sev(certFindings(span(2000, now))))
	require.Equal(t, "MEDIUM", sev(certFindings(span(400, time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)))))
	require.Equal(t, "", sev(certFindings(span(400, time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)))), "issued before September 2020")
	require.Empty(t, certFindings(span(90, now)))

	soon := certFindings(Certificate{IntermediateExpiry: now.Add(10 * 24 * time.Hour)})
	require.Equal(t, "INTERMEDIATE_EXPIRY", soon[0].Name)
	require.Equal(t, "HIGH", soon[0].Severity)

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

// The intermediate-expiry ladder follows testssl: expired CRITICAL, within 20 days HIGH, within
// 40 MEDIUM; the validity span is compared by duration, so 398 days and a few hours counts.
func TestCertFindingLadders(t *testing.T) {
	now := time.Now()
	sev := func(c Certificate, name string) string {
		for _, v := range certFindings(c) {
			if v.Name == name {
				return v.Severity
			}
		}
		return ""
	}
	require.Equal(t, "CRITICAL", sev(Certificate{IntermediateExpiry: now.Add(-24 * time.Hour)}, "INTERMEDIATE_EXPIRY"))
	require.Equal(t, "HIGH", sev(Certificate{IntermediateExpiry: now.Add(10 * 24 * time.Hour)}, "INTERMEDIATE_EXPIRY"))
	require.Equal(t, "MEDIUM", sev(Certificate{IntermediateExpiry: now.Add(30 * 24 * time.Hour)}, "INTERMEDIATE_EXPIRY"))
	require.Equal(t, "", sev(Certificate{IntermediateExpiry: now.Add(60 * 24 * time.Hour)}, "INTERMEDIATE_EXPIRY"))

	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	justOver := Certificate{NotBefore: start, Expires: start.Add(398*24*time.Hour + 3*time.Hour), ValidityDays: 398}
	require.Equal(t, "MEDIUM", sev(justOver, "CERT_VALIDITY"), "398 days and 3 hours is over 398 days")
	exact := Certificate{NotBefore: start, Expires: start.Add(398 * 24 * time.Hour), ValidityDays: 398}
	require.Equal(t, "", sev(exact, "CERT_VALIDITY"))
}

// Findings are raised for every certificate the host serves, once each.
func TestAllCertFindings(t *testing.T) {
	long := Certificate{NotBefore: time.Now(), Expires: time.Now().Add(11 * 365 * 24 * time.Hour), ValidityDays: 4015}
	vs := allCertFindings([]Certificate{{ValidityDays: 90, NotBefore: time.Now(), Expires: time.Now().Add(90 * 24 * time.Hour)}, long, long})
	require.Len(t, vs, 1)
	require.Equal(t, "CERT_VALIDITY", vs[0].Name)
	require.Equal(t, "HIGH", vs[0].Severity)
}
