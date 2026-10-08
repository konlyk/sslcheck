package sslcheck

import (
	"context"
	"sort"
	"strings"
	"sync"

	ztls "github.com/zmap/zcrypto/tls"
)

// Strength classifies a cipher suite, as testssl and SSL Labs do.
type Strength string

const (
	StrengthInsecure Strength = "INSECURE" // no real protection: NULL, anonymous, export, DES, RC4, RC2
	StrengthWeak     Strength = "WEAK"     // outdated but not broken: 3DES, CBC, SHA-1 MAC
	StrengthStrong   Strength = "STRONG"   // AEAD: GCM, CHACHA20, CCM
)

// knownCiphers are the cipher suites zcrypto has a name for, with that name. The scan offers all
// of them and sees which the host accepts; the list is built once from zcrypto's own table so it
// stays in step with the library instead of a copy that drifts.
var knownCiphers = func() []cipherInfo {
	var out []cipherInfo
	for id := 0; id <= 0xffff; id++ {
		name := ztls.CipherSuite(id).String()
		if name == "unknown" || name == "" || strings.Contains(name, "SCSV") {
			continue // SCSV values signal fallback/renegotiation, not a cipher; offering them trips alert 86
		}
		out = append(out, cipherInfo{id: uint16(id), name: name, strength: classify(name), bits: keyBits(name), forward: isForward(name)})
	}
	return out
}()

type cipherInfo struct {
	id       uint16
	name     string
	strength Strength
	bits     int
	forward  bool
}

// cipherIDs is every known suite id, offered together to find what a host accepts.
func cipherIDs() []uint16 {
	ids := make([]uint16, len(knownCiphers))
	for i, c := range knownCiphers {
		ids[i] = c.id
	}
	return ids
}

func cipherByID(id uint16) (cipherInfo, bool) {
	for _, c := range knownCiphers {
		if c.id == id {
			return c, true
		}
	}
	return cipherInfo{}, false
}

// classify buckets a cipher by its IANA name, by the same rules testssl uses: anything with no
// real encryption or a broken primitive is insecure, CBC and 3DES are weak, AEAD is strong.
func classify(name string) Strength {
	n := strings.ToUpper(name)
	switch {
	case has(n, "NULL"), has(n, "_ANON_"), has(n, "EXPORT"), has(n, "_RC4_"), has(n, "_RC2_"),
		has(n, "_DES_"), has(n, "DES40"), has(n, "DES_40"), has(n, "_MD5"):
		return StrengthInsecure
	case has(n, "3DES"), has(n, "DES_EDE"), has(n, "_CBC_"), has(n, "IDEA"), has(n, "SEED"), has(n, "_RC4"):
		return StrengthWeak
	case has(n, "_GCM_"), has(n, "CHACHA20"), has(n, "_CCM"):
		return StrengthStrong
	default:
		return StrengthWeak
	}
}

// keyBits is the symmetric key size a cipher's name implies, as OpenSSL reports it (Enc=…(bits)),
// which is what the rating's cipher-strength category uses.
func keyBits(name string) int {
	n := strings.ToUpper(name)
	switch {
	case has(n, "AES_256"), has(n, "AES256"), has(n, "CAMELLIA_256"), has(n, "CHACHA20"):
		return 256
	case has(n, "ARIA_256"), has(n, "GOST"):
		return 256
	case has(n, "AES_128"), has(n, "AES128"), has(n, "CAMELLIA_128"), has(n, "ARIA_128"), has(n, "SEED"), has(n, "IDEA"):
		return 128
	case has(n, "EXPORT1024") && has(n, "RC4_56"), has(n, "EXPORT1024") && has(n, "DES_CBC"):
		return 56
	case has(n, "EXPORT"), has(n, "DES40"), has(n, "DES_40"):
		return 40
	case has(n, "3DES"), has(n, "DES_EDE"):
		return 168 // as OpenSSL reports 3DES, which is what the rating's cipher strength uses
	case has(n, "_RC4_"), has(n, "_RC4"):
		return 128
	case has(n, "_RC2_"):
		return 128
	case has(n, "_DES_"):
		return 56
	case has(n, "NULL"):
		return 0
	default:
		return 128 // an unlisted modern suite; only NULL has no encryption
	}
}

// isForward reports whether a cipher's key exchange is ephemeral, which gives forward secrecy.
func isForward(name string) bool {
	n := strings.ToUpper(name)
	return has(n, "ECDHE") || has(n, "DHE_") || has(n, "_DHE") || tls13Suite(name)
}

// tls13Suite reports whether name is one of the three TLS 1.3 suites, whose key exchange is
// always ephemeral.
func tls13Suite(name string) bool {
	switch name {
	case "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256":
		return true
	}
	return false
}

func has(s, sub string) bool { return strings.Contains(s, sub) }

// scanCiphers finds the ciphers the host accepts at each offered protocol, best protocol first.
// The protocols are enumerated concurrently, since each is an independent sequence of handshakes.
func scanCiphers(ctx context.Context, addr string, protocols []Protocol, opts Options) []Cipher {
	var offered []Protocol
	for _, p := range protocols {
		if p.Offered {
			offered = append(offered, p)
		}
	}
	// Best protocol first, as the Ciphers field is documented.
	sort.Slice(offered, func(i, j int) bool { return offered[i].Version > offered[j].Version })
	perProto := make([][]Cipher, len(offered))
	var wg sync.WaitGroup
	for i, p := range offered {
		wg.Add(1)
		go func(i int, p Protocol) {
			defer wg.Done()
			perProto[i] = ciphersAt(ctx, addr, p, opts)
		}(i, p)
	}
	wg.Wait()
	var out []Cipher
	for _, cs := range perProto {
		out = append(out, cs...)
	}
	return out
}

// ciphersAt enumerates the ciphers one protocol accepts, the way testssl does: offer every suite,
// note the one the server picks, drop it, and offer the rest, until the server accepts none.
func ciphersAt(ctx context.Context, addr string, p Protocol, opts Options) []Cipher {
	if p.Version == versionTLS13 { // TLS 1.3: its suites are fixed and all strong
		return tls13Ciphers(ctx, addr, opts)
	}
	var out []Cipher
	seen := map[uint16]bool{}
	remaining := cipherIDs()
	for len(remaining) > 0 {
		if ctx.Err() != nil {
			return out
		}
		log, _ := legacyHandshake(ctx, addr, p.Version, remaining, opts)
		// The ServerHello is the answer: a handshake that fails after it (a suite zcrypto cannot
		// finish, a certificate it cannot parse) still names a suite the server accepts.
		if log == nil || log.ServerHello == nil || uint16(log.ServerHello.Version) != p.Version {
			break
		}
		chosen := uint16(log.ServerHello.CipherSuite)
		info, ok := cipherByID(chosen)
		if !ok || seen[chosen] { // an unknown or already-seen pick means the server stopped cooperating
			break
		}
		seen[chosen] = true
		out = append(out, Cipher{ID: chosen, Name: info.name, Version: p.Name, Strength: info.strength, Bits: info.bits, Forward: info.forward})
		remaining = remove(remaining, chosen)
	}
	return out
}

func remove(ids []uint16, id uint16) []uint16 {
	out := ids[:0]
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

func forwardSecret(ciphers []Cipher) bool {
	if len(ciphers) == 0 {
		return false
	}
	for _, c := range ciphers {
		if !c.Forward {
			return false
		}
	}
	return true
}
