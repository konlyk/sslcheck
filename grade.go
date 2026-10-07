package sslcheck

import (
	"sort"
	"strconv"
	"strings"
)

// grade scores the host the way SSL Labs's "SSL Server Rating Guide" does, which is what testssl
// implements in run_rating: a protocol score, a key-exchange score and a cipher-strength score,
// combined 30/30/40, then turned into a letter and capped for the weaknesses found. The caps are
// what actually decides most grades, so they matter more than the arithmetic.
func grade(a *Assessment) (score int, letter string, reasons []string) {
	// A certificate that is not trusted or not for this host is an immediate fail, as SSL Labs
	// grades M (mismatch) and T (not trusted); these outrank any number.
	if len(a.Certificates) > 0 {
		c := a.Certificates[0]
		if c.NameMismatch {
			return 0, "M", []string{"certificate is not valid for the hostname: " + c.TrustReason}
		}
		if !c.Trusted {
			return 0, "T", []string{"certificate is not trusted: " + c.TrustReason}
		}
	}

	proto := protocolScore(a.Protocols)
	kex := kexScore(a)
	cipher := cipherScore(a.Ciphers)
	score = proto*30/100 + kex*30/100 + cipher*40/100
	letter = letterFor(score)
	letter, reasons = applyCaps(letter, a)
	// The score is capped to the band of the final letter, as testssl caps it.
	if m, ok := scoreCap[letter]; ok && score > m {
		score = m
	}
	return score, letter, reasons
}

// protocolScore is SSL Labs's: the best and worst supported protocol averaged, on its 0–100
// scale (SSLv2 0, SSLv3 80, TLS1.0 90, TLS1.1 95, TLS1.2 100, TLS1.3 100).
func protocolScore(ps []Protocol) int {
	points := map[string]int{"SSLv2": 0, "SSLv3": 80, "TLS1": 90, "TLS1_1": 95, "TLS1_2": 100, "TLS1_3": 100}
	best, worst := -1, 101
	for _, p := range ps {
		if !p.Offered {
			continue
		}
		v := points[p.Name]
		best = max(best, v)
		worst = min(worst, v)
	}
	if best < 0 {
		return 0
	}
	return (best + worst) / 2
}

// kexScore scores the key exchange: forward secrecy and key sizes. It is a coarse form of SSL
// Labs's table, enough for the caps that follow to do the real work.
func kexScore(a *Assessment) int {
	if len(a.Certificates) == 0 {
		return 0
	}
	kt := a.Certificates[0].KeyType
	if strings.HasPrefix(kt, "EC") {
		return 100 // an EC key on a served curve is strong enough here
	}
	bits := 0
	if strings.HasPrefix(kt, "RSA ") {
		bits, _ = strconv.Atoi(strings.TrimPrefix(kt, "RSA "))
	}
	switch {
	case bits >= 2048:
		return 90
	case bits >= 1024:
		return 40
	default:
		return 20
	}
}

// cipherScore averages the strength of the accepted ciphers on SSL Labs's scale (strong 100,
// weak 80, insecure 20).
func cipherScore(cs []Cipher) int {
	if len(cs) == 0 {
		return 0
	}
	points := map[Strength]int{StrengthStrong: 100, StrengthWeak: 80, StrengthInsecure: 20}
	best, worst := 0, 101
	for _, c := range cs {
		v := points[c.Strength]
		best = max(best, v)
		worst = min(worst, v)
	}
	return (best + worst) / 2
}

func letterFor(score int) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 65:
		return "B"
	case score >= 50:
		return "C"
	case score >= 35:
		return "D"
	case score >= 20:
		return "E"
	default:
		return "F"
	}
}

// scoreCap is the most a score may be once capped to a letter band, as testssl caps it.
var scoreCap = map[string]int{"B": 79, "C": 64, "D": 49, "E": 34, "F": 19, "M": 0, "T": 0}

// applyCaps lowers the letter for the weaknesses SSL Labs caps on, and lists the reasons. The
// lowest cap wins.
func applyCaps(letter string, a *Assessment) (string, []string) {
	var reasons []string
	capTo := func(max, reason string) {
		if rank(max) < rank(letter) {
			letter = max
		}
		reasons = append(reasons, reason)
	}
	offered := map[string]bool{}
	for _, p := range a.Protocols {
		offered[p.Name] = p.Offered
	}
	if offered["SSLv2"] {
		capTo("F", "SSLv2 offered")
	}
	if offered["SSLv3"] {
		capTo("F", "SSLv3 offered")
	}
	if offered["TLS1"] {
		capTo("B", "TLS 1.0 offered")
	}
	if offered["TLS1_1"] {
		capTo("B", "TLS 1.1 offered")
	}
	if !a.ForwardSecret && len(a.Ciphers) > 0 {
		capTo("B", "not all key exchanges are forward-secret")
	}
	for _, c := range a.Ciphers {
		if c.Strength != StrengthInsecure {
			continue
		}
		// SSL Labs caps RC4 to C and the rest of the broken ciphers (export, NULL, anonymous,
		// single DES) to F.
		if has(strings.ToUpper(c.Name), "RC4") {
			capTo("C", "RC4 is accepted")
		} else {
			capTo("F", "an insecure cipher is accepted")
		}
	}
	// A 64-bit-block cipher (3DES, the SWEET32 case) caps to B, as SSL Labs does; truly broken
	// ciphers are StrengthInsecure and already capped to F above. Ordinary AES-CBC is not weak
	// for the grade, only noted as a LUCKY13/BEAST finding.
	for _, c := range a.Ciphers {
		if c.Bits > 0 && c.Bits < 128 {
			capTo("B", "a 64-bit-block cipher (SWEET32) is accepted")
			break
		}
	}
	for _, v := range a.Vulns {
		switch v.Severity {
		case "CRITICAL":
			capTo("F", v.Name+" ("+v.Severity+")")
		case "HIGH":
			capTo("F", v.Name+" ("+v.Severity+")")
		}
	}
	// Expiry is a fail too.
	if len(a.Certificates) > 0 && a.Certificates[0].Expired() {
		capTo("T", "certificate has expired")
	}
	sort.Strings(reasons)
	return letter, reasons
}

// rank orders grades so a lower rank is a worse grade; the caps keep the lowest.
func rank(letter string) int {
	order := map[string]int{"A+": 9, "A": 8, "A-": 7, "B": 6, "C": 5, "D": 4, "E": 3, "F": 2, "T": 1, "M": 0}
	if r, ok := order[letter]; ok {
		return r
	}
	return 8
}
