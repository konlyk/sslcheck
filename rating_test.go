package sslcheck

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// host builds an assessment of a good modern host (TLS 1.2 + 1.3, ECDHE AEAD and AES-256, RSA
// 2048, trusted chain), which each case below then breaks in one way.
func host() *Assessment {
	yes := true
	return &Assessment{
		Protocols: []Protocol{
			{Name: "SSLv2", Version: versionSSL20}, {Name: "SSLv3", Version: 0x0300},
			{Name: "TLS1", Version: 0x0301}, {Name: "TLS1_1", Version: 0x0302},
			{Name: "TLS1_2", Version: 0x0303, Offered: true}, {Name: "TLS1_3", Version: versionTLS13, Offered: true},
		},
		Ciphers: []Cipher{
			{Name: "TLS_AES_256_GCM_SHA384", Version: "TLS1_3", Bits: 256, Forward: true},
			{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS1_2", Bits: 128, Forward: true},
		},
		Certificates:        []Certificate{{KeyAlg: "RSA", KeyBits: 2048, RSAExponent: 65537, SignatureHash: "SHA256", ChainComplete: true, Trusted: true, Expires: time.Now().Add(time.Hour)}},
		SecureRenegotiation: &yes,
	}
}

func offer(a *Assessment, names ...string) {
	for i := range a.Protocols {
		for _, n := range names {
			if a.Protocols[i].Name == n {
				a.Protocols[i].Offered = true
			}
		}
	}
}

func drop(a *Assessment, names ...string) {
	for i := range a.Protocols {
		for _, n := range names {
			if a.Protocols[i].Name == n {
				a.Protocols[i].Offered = false
			}
		}
	}
}

// The reference host: testssl's arithmetic, and an A+ for no warnings.
func TestRatingScoreArithmetic(t *testing.T) {
	a := host()
	rate(a)
	// protocols (100+100)/2; RSA 2048 → 90; ciphers best 256 (100), worst 128 (80) → 90.
	require.Equal(t, []int{100, 90, 90}, []int{a.ProtocolScore, a.KeyExchangeScore, a.CipherStrengthScore})
	require.Equal(t, 100*30/100+90*30/100+90*40/100, a.Score) // 93, as testssl computes webberly.vip
	require.Equal(t, "A+", a.Grade)
	require.Empty(t, a.Reasons)

	// An EC P-256 key scores 100.
	a = host()
	a.Certificates[0].KeyAlg, a.Certificates[0].KeyBits = "EC", 256
	rate(a)
	require.Equal(t, 100, a.KeyExchangeScore)
}

func TestRatingWarningsMakeAMinus(t *testing.T) {
	no := false
	cases := map[string]func(*Assessment){
		"TLS 1.3 is not supported":              func(a *Assessment) { drop(a, "TLS1_3"); a.Ciphers = a.Ciphers[1:] },
		"Secure renegotiation is not supported": func(a *Assessment) { a.SecureRenegotiation = &no },
		"HSTS max-age is too short":             func(a *Assessment) { a.HTTP = &HTTPHeaders{HSTS: "max-age=3600"} },
		"HSTS is disabled":                      func(a *Assessment) { a.HTTP = &HTTPHeaders{HSTS: "max-age=0"} },
		"HSTS max-age is misconfigured":         func(a *Assessment) { a.HTTP = &HTTPHeaders{HSTS: "max-age=soon"} },
	}
	for warning, breakIt := range cases {
		a := host()
		breakIt(a)
		rate(a)
		require.Equal(t, "A-", a.Grade, warning)
		require.Contains(t, a.Warnings, warning)
	}
	// A long enough HSTS, or none, is no warning.
	for _, v := range []string{"", "max-age=31536000; includeSubDomains", `max-age="15552000"`} {
		a := host()
		a.HTTP = &HTTPHeaders{HSTS: v}
		rate(a)
		require.Equal(t, "A+", a.Grade, v)
	}
}

func TestRatingCaps(t *testing.T) {
	cases := []struct {
		name    string
		grade   string
		reason  string
		breakIt func(*Assessment)
	}{
		{"SSLv2", "F", "SSLv2 is offered", func(a *Assessment) { offer(a, "SSLv2") }},
		{"SSLv3", "B", "SSLv3 is offered", func(a *Assessment) { offer(a, "SSLv3") }},
		{"SSLv3 only", "F", "SSLv3 is the best protocol offered", func(a *Assessment) {
			drop(a, "TLS1_2", "TLS1_3")
			offer(a, "SSLv3")
			a.Ciphers = []Cipher{{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Version: "SSLv3", Bits: 128, Forward: true}}
		}},
		{"TLS 1.0", "B", "TLS 1.0 offered", func(a *Assessment) { offer(a, "TLS1") }},
		{"TLS 1.1", "B", "TLS 1.1 offered", func(a *Assessment) { offer(a, "TLS1_1") }},
		{"no TLS 1.2 but downgrade", "C", "TLS 1.2 is not offered", func(a *Assessment) {
			drop(a, "TLS1_2")
			offer(a, "TLS1")
		}},
		{"export", "F", "Export suite offered", func(a *Assessment) {
			a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Version: "TLS1_2", Bits: 40})
		}},
		{"under 112 bits", "F", "Using cipher suites weaker than 112 bits", func(a *Assessment) {
			a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_RSA_WITH_DES_CBC_SHA", Version: "TLS1_2", Bits: 56})
		}},
		{"SHA1 signature", "T", "Uses SHA1 algorithm", func(a *Assessment) { a.Certificates[0].SignatureHash = "SHA1" }},
		{"MD5 signature", "F", "Supports a insecure signature (MD5)", func(a *Assessment) { a.Certificates[0].SignatureHash = "MD5" }},
		{"RSA exponent 1", "F", "RSA certificate uses exponent of 1", func(a *Assessment) { a.Certificates[0].RSAExponent = 1 }},
		{"name mismatch", "M", "Domain name mismatch", func(a *Assessment) { a.Certificates[0].NameMismatch = true }},
		{"incomplete chain", "B", "Issues with chain of trust (chain incomplete)", func(a *Assessment) {
			a.Certificates[0].ChainComplete, a.Certificates[0].ChainIncomplete = false, true
		}},
		{"untrusted chain", "T", "Issues with chain of trust (not trusted)", func(a *Assessment) { a.Certificates[0].ChainComplete = false }},
		{"expired", "T", "Certificate expired", func(a *Assessment) { a.Certificates[0].Expires = time.Now().Add(-time.Hour) }},
		{"revoked", "T", "Certificate revoked", func(a *Assessment) { a.Certificates[0].Revoked = true }},
		{"issuer without organisation", "T", "Self-signed certificate", func(a *Assessment) {
			a.Certificates[0].Leaf = &x509.Certificate{}
		}},
		{"self-signed chain", "T", "Issues with chain of trust (self signed)", func(a *Assessment) {
			a.Certificates[0].SelfSigned, a.Certificates[0].ChainComplete = true, false
		}},
		{"no forward secrecy", "B", "Forward Secrecy (FS) is not supported", func(a *Assessment) {
			drop(a, "TLS1_3")
			a.Ciphers = []Cipher{{Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", Version: "TLS1_2", Bits: 256}}
		}},
		{"RSA 1024", "B", "Using a weak public key and/or ephemeral key", func(a *Assessment) { a.Certificates[0].KeyBits = 1024 }},
		{"RSA 512", "F", "Using an insecure public key and/or ephemeral key", func(a *Assessment) { a.Certificates[0].KeyBits = 512 }},
		{"heartbleed", "F", "Vulnerable to Heartbleed", func(a *Assessment) { a.Vulns = []Vuln{{Name: "HEARTBLEED"}} }},
		{"CCS", "F", "Vulnerable to CCS injection", func(a *Assessment) { a.Vulns = []Vuln{{Name: "CCS_INJECTION"}} }},
		{"ticketbleed", "F", "Vulnerable to Ticketbleed", func(a *Assessment) { a.Vulns = []Vuln{{Name: "TICKETBLEED"}} }},
		{"ROBOT", "F", "Vulnerable to ROBOT", func(a *Assessment) { a.Vulns = []Vuln{{Name: "ROBOT"}} }},
		{"CRIME", "C", "Vulnerable to CRIME", func(a *Assessment) { a.Compression = true }},
		{"POODLE", "C", "Vulnerable to POODLE", func(a *Assessment) {
			offer(a, "SSLv3")
			a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", Version: "SSLv3", Bits: 128})
		}},
		{"RC4", "B", "RC4 ciphers offered", func(a *Assessment) {
			a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Version: "TLS1_2", Bits: 128, Forward: true})
		}},
		{"RC4 on TLS 1.1 only", "C", "RC4 ciphers offered on TLS 1.1", func(a *Assessment) {
			offer(a, "TLS1_1")
			a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_RSA_WITH_RC4_128_SHA", Version: "TLS1_1", Bits: 128})
		}},
		{"SWEET32 only at TLS 1.1", "C", "Uses 64 bit block ciphers with TLS 1.1 (vulnerable to SWEET32)", func(a *Assessment) {
			drop(a, "TLS1_3")
			offer(a, "TLS1_1")
			a.Ciphers = []Cipher{
				{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Version: "TLS1_2", Bits: 128, Forward: true},
				{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Version: "TLS1_1", Bits: 168},
			}
		}},
		{"HPKP with one pin", "A", "Problems with HTTP Public Key Pinning (HPKP)", func(a *Assessment) {
			a.HTTP = &HTTPHeaders{HPKP: []string{`pin-sha256="abc="; max-age=5184000`}}
		}},
	}
	for _, tc := range cases {
		a := host()
		tc.breakIt(a)
		rate(a)
		require.Equal(t, tc.grade, a.Grade, tc.name)
		require.Contains(t, a.Reasons, "Grade capped to "+tc.grade+". "+tc.reason, tc.name)
		// testssl prints a score of 0 once a fail is known before scoring; the caps it sets while
		// scoring (SSLv3 as the best protocol, an insecure key) leave the score as computed.
		scoringCap := tc.name == "SSLv3 only" || tc.name == "RSA 512"
		if (tc.grade == "F" || tc.grade == "T" || tc.grade == "M") && !scoringCap {
			require.Zero(t, a.Score, tc.name)
		}
	}
}

// What testssl does differently from the guide's prose is kept: SWEET32 does not cap when the
// 64-bit cipher is reachable at the preferred protocol, and a host with TLS 1.3 but no TLS 1.2 is
// not capped.
func TestRatingFollowsTestssl(t *testing.T) {
	a := host()
	a.Ciphers = append(a.Ciphers, Cipher{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Version: "TLS1_2", Bits: 168})
	rate(a)
	require.NotContains(t, a.Grade, "C")
	require.Equal(t, 90, a.CipherStrengthScore, "3DES counts as 168 bits")

	a = host()
	drop(a, "TLS1_2")
	a.Ciphers = a.Ciphers[:1]
	rate(a)
	require.Equal(t, "A+", a.Grade, "TLS 1.3 alone is not capped")
}

// T and M override other caps, and of several the last one set stands, as in testssl: a
// mismatched, expired certificate is T (expiry is checked after the name).
func TestRatingHardCapsOverride(t *testing.T) {
	a := host()
	offer(a, "SSLv2")
	a.Certificates[0].NameMismatch = true
	rate(a)
	require.Equal(t, "M", a.Grade)

	a = host()
	a.Certificates[0].NameMismatch = true
	a.Certificates[0].Expires = time.Now().Add(-time.Hour)
	rate(a)
	require.Equal(t, "T", a.Grade)
}

// A matching pin plus a backup pin with a long max-age is fine; no pin for the served chain is a
// problem.
func TestHPKP(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("leaf key")}
	certs := []Certificate{{Chain: []*x509.Certificate{leaf}}}
	good := &HTTPHeaders{HPKP: []string{`pin-sha256="` + spkiPin(leaf) + `"; pin-sha256="backup="; max-age=5184000`}}
	require.False(t, hpkpProblem(good, certs))
	noMatch := &HTTPHeaders{HPKP: []string{`pin-sha256="x="; pin-sha256="y="; max-age=5184000`}}
	require.True(t, hpkpProblem(noMatch, certs))
	noBackup := &HTTPHeaders{HPKP: []string{`pin-sha256="` + spkiPin(leaf) + `"; pin-sha256="` + spkiPin(leaf) + `"; max-age=5184000`}}
	require.True(t, hpkpProblem(noBackup, certs))
	short := &HTTPHeaders{HPKP: []string{`pin-sha256="` + spkiPin(leaf) + `"; pin-sha256="backup="; max-age=10`}}
	require.True(t, hpkpProblem(short, certs))
}

// BEAST caps to B when CBC is offered on TLS 1.0 and nothing newer is, which such a host's missing
// TLS 1.2 already caps further, to C.
func TestRatingBEAST(t *testing.T) {
	a := host()
	drop(a, "TLS1_2", "TLS1_3")
	offer(a, "TLS1")
	a.Ciphers = []Cipher{{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Version: "TLS1", Bits: 128, Forward: true}}
	rate(a)
	require.Equal(t, "C", a.Grade)
	require.Contains(t, a.Reasons, "Grade capped to B. Vulnerable to BEAST")
	require.Contains(t, a.Reasons, "Grade capped to C. TLS 1.2 is not offered")
}

// RC4 accepted at the preferred protocol as well as at TLS 1.1 is only a B, as testssl finds it in
// its first pass; ECDHE with only RC4 or 3DES is no forward secrecy.
func TestRatingRC4AndRobustForwardSecrecy(t *testing.T) {
	a := host()
	drop(a, "TLS1_3")
	offer(a, "TLS1_1")
	a.Ciphers = []Cipher{
		{Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Version: "TLS1_2", Bits: 128, Forward: true},
		{Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Version: "TLS1_1", Bits: 128, Forward: true},
	}
	rate(a)
	require.NotContains(t, a.Reasons, "Grade capped to C. RC4 ciphers offered on TLS 1.1")
	require.Contains(t, a.Reasons, "Grade capped to B. RC4 ciphers offered")
	require.Contains(t, a.Reasons, "Grade capped to B. Forward Secrecy (FS) is not supported", "ECDHE-RC4 is not robust FS")
}
