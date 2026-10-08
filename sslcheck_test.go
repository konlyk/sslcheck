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
	require.Equal(t, 168, keyBits("TLS_RSA_WITH_3DES_EDE_CBC_SHA"), "3DES as OpenSSL reports it")
	require.Equal(t, 40, keyBits("TLS_RSA_EXPORT_WITH_RC4_40_MD5"), "export before RC4")
	require.Equal(t, 0, keyBits("TLS_RSA_WITH_NULL_SHA"))
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
