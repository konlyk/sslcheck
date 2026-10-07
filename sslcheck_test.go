package sslcheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	cases := map[string]Strength{
		"TLS_AES_128_GCM_SHA256":                      StrengthStrong,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       StrengthStrong,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": StrengthStrong,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          StrengthWeak,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":               StrengthWeak,
		"TLS_RSA_WITH_RC4_128_SHA":                    StrengthInsecure,
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5":              StrengthInsecure,
		"TLS_DH_anon_WITH_AES_128_CBC_SHA":            StrengthInsecure,
		"TLS_RSA_WITH_NULL_SHA":                       StrengthInsecure,
	}
	for name, want := range cases {
		require.Equal(t, want, classify(name), name)
	}
}

func TestKeyBitsAndForward(t *testing.T) {
	require.Equal(t, 112, keyBits("TLS_RSA_WITH_3DES_EDE_CBC_SHA"), "3DES is the 64-bit-block case SWEET32 flags")
	require.Equal(t, 256, keyBits("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
	require.Equal(t, 40, keyBits("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"))
	require.True(t, isForward("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
	require.True(t, isForward("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"))
	require.True(t, isForward("TLS_AES_128_GCM_SHA256"), "every TLS 1.3 suite is ephemeral")
	require.False(t, isForward("TLS_RSA_WITH_AES_128_GCM_SHA256"))
}

func TestKnownCiphersExcludeSCSV(t *testing.T) {
	for _, c := range knownCiphers {
		require.NotContains(t, c.name, "SCSV", "SCSV values must not be offered as ciphers")
	}
	require.Greater(t, len(knownCiphers), 100, "the suite table should be well populated")
}

// A host offering a mismatched or untrusted certificate fails outright, whatever else it does.
func TestGradeCertificateFailsOutright(t *testing.T) {
	strong := []Protocol{{Name: "TLS1_2", Offered: true}, {Name: "TLS1_3", Offered: true}}
	a := &Assessment{Protocols: strong, ForwardSecret: true, Certificates: []Certificate{{NameMismatch: true, TrustReason: "not for host"}}}
	_, letter, _ := grade(a)
	require.Equal(t, "M", letter)

	a.Certificates = []Certificate{{Trusted: false, TrustReason: "self-signed"}}
	_, letter, _ = grade(a)
	require.Equal(t, "T", letter)
}

// Offering a deprecated protocol caps the grade at B however good the rest is.
func TestGradeCapsOnOldProtocols(t *testing.T) {
	a := &Assessment{
		Protocols:     []Protocol{{Name: "TLS1", Offered: true, Deprecated: true}, {Name: "TLS1_2", Offered: true}},
		Ciphers:       []Cipher{{Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Strength: StrengthStrong, Forward: true}},
		ForwardSecret: true,
		Certificates:  []Certificate{{Trusted: true, KeyType: "RSA 2048"}},
	}
	_, letter, reasons := grade(a)
	require.Equal(t, "B", letter)
	require.Contains(t, reasons, "TLS 1.0 offered")
}

// An insecure cipher is a fail; a modern, forward-secret host with a trusted cert is an A.
func TestGradeFloorAndCeiling(t *testing.T) {
	// RC4 caps to C (SSL Labs' rule); a truly broken cipher (export) caps to F.
	rc4 := &Assessment{
		Protocols:    []Protocol{{Name: "TLS1_2", Offered: true}},
		Ciphers:      []Cipher{{Name: "TLS_RSA_WITH_RC4_128_SHA", Strength: StrengthInsecure}},
		Certificates: []Certificate{{Trusted: true, KeyType: "RSA 2048"}},
	}
	_, letter, _ := grade(rc4)
	require.Equal(t, "C", letter)

	export := &Assessment{
		Protocols:    []Protocol{{Name: "TLS1_2", Offered: true}},
		Ciphers:      []Cipher{{Name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", Strength: StrengthInsecure}},
		Certificates: []Certificate{{Trusted: true, KeyType: "RSA 2048"}},
	}
	_, letter, _ = grade(export)
	require.Equal(t, "F", letter)

	clean := &Assessment{
		Protocols:     []Protocol{{Name: "TLS1_2", Offered: true}, {Name: "TLS1_3", Offered: true}},
		Ciphers:       []Cipher{{Name: "TLS_AES_128_GCM_SHA256", Strength: StrengthStrong, Forward: true}},
		ForwardSecret: true,
		Certificates:  []Certificate{{Trusted: true, KeyType: "EC P-256"}},
	}
	score, letter, _ := grade(clean)
	require.Equal(t, "A", letter)
	require.GreaterOrEqual(t, score, 80)
}
