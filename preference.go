package sslcheck

import (
	"context"
	"strings"
)

// scanCipherOrder reports whether the server imposes its own cipher order, the way testssl's
// run_server_preference does: at each offered protocol the accepted suites are offered in their
// order and then reversed; a server with an order picks the same suite both times, a server
// without picks whichever the client listed first. order is nil when no protocol had two suites
// to compare. level is testssl's rating of the worst such protocol, 5 (no concern) down to 1
// (critical), from how much weaker the client's choice can be than the server's; noOrder names
// the protocols that enforce no order.
func scanCipherOrder(ctx context.Context, addr string, protocols []Protocol, ciphers []Cipher, opts Options) (order *bool, level int, noOrder []string) {
	level = 5
	for _, p := range protocols {
		if !p.Offered || p.Version == versionSSL20 {
			continue
		}
		var ids []uint16
		var qualities []int
		for _, c := range ciphers {
			if c.Version == p.Name {
				ids = append(ids, c.ID)
				qualities = append(qualities, cipherQuality(c.Name))
			}
		}
		if len(ids) < 2 {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		first, ok1 := pickAt(ctx, addr, p, ids, opts)
		second, ok2 := pickAt(ctx, addr, p, reversed(ids), opts)
		if !ok1 || !ok2 {
			continue // no answer: nothing to conclude for this protocol
		}
		if order == nil {
			yes := true
			order = &yes
		}
		if first != second && isChaCha(second) && orderedWithoutChaCha(ctx, addr, p, ids, opts) {
			// The server keeps its order but lets a client that prefers ChaCha20 have it (an
			// equal-preference group, as BoringSSL servers do); testssl counts that as an order.
			continue
		}
		if first != second {
			*order = false
			noOrder = append(noOrder, p.Name)
			if r := differenceRating(qualities); r < level {
				level = r
			}
		}
	}
	return order, level, noOrder
}

// orderedWithoutChaCha repeats the two-order comparison with the ChaCha20 suites left out, which
// tells a server that merely honours a client's ChaCha preference from one with no order at all.
func orderedWithoutChaCha(ctx context.Context, addr string, p Protocol, ids []uint16, opts Options) bool {
	var rest []uint16
	for _, id := range ids {
		if !isChaCha(id) {
			rest = append(rest, id)
		}
	}
	if len(rest) < 2 {
		return true // ChaCha and one other suite: nothing else to be out of order
	}
	first, ok1 := pickAt(ctx, addr, p, rest, opts)
	second, ok2 := pickAt(ctx, addr, p, reversed(rest), opts)
	return ok1 && ok2 && first == second
}

// isChaCha reports whether a suite id is a ChaCha20-Poly1305 suite (TLS 1.3's included).
func isChaCha(id uint16) bool {
	if id == 0x1303 {
		return true
	}
	info, ok := cipherByID(id)
	return ok && has(strings.ToUpper(info.name), "CHACHA20")
}

// pickAt is the suite the server picks when offered ids, in that order, at protocol p.
func pickAt(ctx context.Context, addr string, p Protocol, ids []uint16, opts Options) (uint16, bool) {
	if p.Version == versionTLS13 {
		return tls13Pick(ctx, addr, ids, opts)
	}
	log, _ := legacyHandshake(ctx, addr, p.Version, ids, opts)
	if log == nil || log.ServerHello == nil {
		return 0, false
	}
	return uint16(log.ServerHello.CipherSuite), true
}

func reversed(ids []uint16) []uint16 {
	out := make([]uint16, len(ids))
	for i, id := range ids {
		out[len(ids)-1-i] = id
	}
	return out
}

// cipherQuality is testssl's get_cipher_quality ladder for a suite's IANA name: 1 is no real
// protection (NULL, export, anonymous), 2 a broken cipher (RC4, RC2, single DES, MD5), 3 a 64-bit
// block (3DES, IDEA), 4 CBC, 5 unknown, 6 AEAD with a static key exchange, 7 AEAD with an
// ephemeral one.
func cipherQuality(name string) int {
	n := strings.ToUpper(name)
	switch {
	case has(n, "NULL"), has(n, "EXPORT"), has(n, "_DES40_"), has(n, "DES40"), has(n, "_ANON_"), strings.HasPrefix(n, "TLS_SHA"):
		return 1
	case has(n, "RC4"), has(n, "_RC2_"), has(n, "_MD5"):
		return 2
	case has(n, "3DES"), has(n, "DES_EDE"), has(n, "IDEA"):
		return 3
	case has(n, "_DES_"):
		return 2
	case has(n, "_GCM_"), has(n, "_CCM"), has(n, "CHACHA20"):
		if isForward(name) {
			return 7
		}
		return 6
	case has(n, "_CBC_"), has(n, "GOST"):
		return 4
	default:
		return 5
	}
}

// differenceRating is testssl's rating of a protocol whose cipher order the client decides: how
// bad the weakest pick can be, weighed against the best the server has. 5 means no concern.
func differenceRating(qualities []int) int {
	best, worst := 0, 8
	for _, q := range qualities {
		if q > best {
			best = q
		}
		if q < worst {
			worst = q
		}
	}
	if best == worst {
		return 5
	}
	switch best {
	case 3, 5, 6, 7:
		if worst > 5 {
			return 5
		}
		return worst
	case 4:
		switch worst {
		case 3:
			return 4
		case 2:
			return 2
		case 1:
			return 1
		}
	case 2:
		return 2
	}
	return 5
}

// cipherOrderSeverity maps testssl's level to a finding severity; 5 is no finding.
func cipherOrderSeverity(level int) string {
	switch level {
	case 4:
		return "LOW"
	case 3:
		return "MEDIUM"
	case 2:
		return "HIGH"
	case 1:
		return "CRITICAL"
	}
	return ""
}
