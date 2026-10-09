package sslcheck

import (
	"context"
	"strings"
	"sync"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// Vuln is a weakness the host has, named as testssl names it.
type Vuln struct {
	Name     string
	Severity string // CRITICAL, HIGH, MEDIUM, LOW
	CVE      string
	CWE      string
	Remark   string
}

// scanVulns collects the host's weaknesses: those that follow from the protocols and ciphers it
// offers, and those found by an active probe.
func scanVulns(ctx context.Context, addr string, a *Assessment, opts Options) []Vuln {
	var out []Vuln
	add := func(v Vuln) { out = append(out, v) }

	offered := map[string]bool{}
	for _, p := range a.Protocols {
		offered[p.Name] = p.Offered
	}

	// Derived from the protocols and ciphers on offer.
	if offered["SSLv2"] {
		add(Vuln{"DROWN", "HIGH", "CVE-2016-0800", "CWE-310", "SSLv2 is offered; the key may be attacked through it"})
	}
	for _, c := range a.Ciphers {
		if c.Version == "SSLv3" && has(strings.ToUpper(c.Name), "_CBC_") {
			add(Vuln{"POODLE_SSL", "MEDIUM", "CVE-2014-3566", "CWE-310", "SSLv3 is offered with CBC ciphers; their padding can be attacked"})
			break
		}
	}
	var hasRC4, hasExportRSA, hasExportDH, has3DES, hasCBC, hasNULL, hasAnon bool
	beastCBC := false // CBC at SSLv3 or TLS 1.0, the protocols BEAST applies to
	for _, c := range a.Ciphers {
		n := strings.ToUpper(c.Name)
		hasRC4 = hasRC4 || has(n, "RC4")
		has3DES = has3DES || block64(n)
		hasCBC = hasCBC || has(n, "_CBC_")
		hasNULL = hasNULL || has(n, "NULL")
		hasAnon = hasAnon || has(n, "_ANON_")
		if has(n, "EXPORT") {
			if has(n, "DH") {
				hasExportDH = true
			} else {
				hasExportRSA = true
			}
		}
		if (c.Version == "TLS1" || c.Version == "SSLv3") && has(n, "_CBC_") {
			beastCBC = true
		}
	}
	if hasExportRSA {
		add(Vuln{"FREAK", "HIGH", "CVE-2015-0204", "CWE-310", "an export-grade RSA cipher is accepted"})
	}
	if hasExportDH {
		add(Vuln{"LOGJAM", "MEDIUM", "CVE-2015-4000", "CWE-310", "an export-grade DH cipher is accepted"})
	} else if bits, group := dhParams(ctx, addr, bestLegacyVersion(a.Protocols), opts); bits > 0 {
		a.DHBits, a.DHGroup = bits, group
		// testssl grades a well-known prime (one an attacker may have precomputed for) harsher
		// than an unknown one of the same size, and an unknown one only at 1024 bits or less.
		if group != "" {
			if sev := knownPrimeSeverity(bits); sev != "" {
				add(Vuln{"LOGJAM", sev, "CVE-2015-4000", "CWE-310", "the server uses a well-known " + itoa(bits) + "-bit DH group (" + group + "), which an attacker may have precomputed for"})
			}
		} else if bits <= 1024 {
			add(Vuln{"LOGJAM", dhSeverity(bits), "CVE-2015-4000", "CWE-310", "the DH group is only " + itoa(bits) + " bits"})
		}
	}
	if has3DES {
		add(Vuln{"SWEET32", "LOW", "CVE-2016-2183 CVE-2016-6329", "CWE-327", "a 64-bit-block cipher (3DES, IDEA, DES, RC2) is accepted"})
	}
	if hasRC4 {
		add(Vuln{"RC4", "MEDIUM", "CVE-2013-2566 CVE-2015-2808", "CWE-310", "the RC4 cipher is accepted"})
	}
	if beastCBC {
		add(Vuln{"BEAST", "LOW", "CVE-2011-3389", "CWE-20", "CBC ciphers are offered on SSLv3 or TLS 1.0"})
	}
	if hasCBC {
		add(Vuln{"LUCKY13", "LOW", "CVE-2013-0169", "CWE-310", "a CBC cipher is accepted"})
	}
	if hasNULL {
		add(Vuln{"NULL_CIPHER", "HIGH", "", "CWE-327", "a cipher without encryption is accepted"})
	}
	if hasAnon {
		add(Vuln{"ANON_CIPHER", "HIGH", "", "CWE-327", "an anonymous (unauthenticated) cipher is accepted"})
	}

	// Active probes. Each opens its own connections and is independent of the others, so they run
	// concurrently; the findings are still added in a fixed order.
	if ctx.Err() == nil {
		var hb, ccs, tb bool
		var rb string
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); hb = heartbleed(ctx, addr, legacyCipherIDs(a.Ciphers), opts) }()
		go func() { defer wg.Done(); ccs = ccsInjection(ctx, addr, opts) }()
		go func() { defer wg.Done(); tb = ticketbleed(ctx, addr, opts) }()
		go func() { defer wg.Done(); rb = robot(ctx, addr, opts) }()
		wg.Wait()
		if hb {
			add(Vuln{"HEARTBLEED", "CRITICAL", "CVE-2014-0160", "CWE-119", "the server returns memory to a malformed heartbeat"})
		}
		if ccs {
			add(Vuln{"CCS_INJECTION", "HIGH", "CVE-2014-0224", "CWE-310", "the server accepts an early ChangeCipherSpec"})
		}
		if tb {
			add(Vuln{"TICKETBLEED", "HIGH", "CVE-2016-9244", "CWE-200", "the server returns memory in a session-ticket echo"})
		}
		if rb != "" {
			add(Vuln{"ROBOT", "HIGH", "CVE-2017-17382 CVE-2017-17427 CVE-2017-13099", "CWE-203", rb})
		}
	}
	return out
}

// heartbleed reports whether the host bleeds memory in answer to a malformed heartbeat. zcrypto
// has the check built in; the module only has to turn the heartbeat extension on and ask. It
// offers the suites the host was seen to accept (forced, so zcrypto presents them even when they
// are not its own defaults), so a server that shares none of zcrypto's default suites — an RC4- or
// 3DES-only host, which is just the sort of old OpenSSL that bleeds — still completes the
// handshake the heartbeat rides on.
func heartbleed(ctx context.Context, addr string, suites []uint16, opts Options) bool {
	if len(suites) > 0 {
		if vulnerable, decided := heartbleedWith(ctx, addr, suites, opts); decided {
			return vulnerable
		}
		// The server picked an accepted suite zcrypto cannot finish: try zcrypto's own defaults.
	}
	vulnerable, _ := heartbleedWith(ctx, addr, nil, opts)
	return vulnerable
}

// heartbleedWith runs zcrypto's check offering suites (its defaults when nil). decided is false
// when the handshake did not complete, so the check could not say either way.
func heartbleedWith(ctx context.Context, addr string, suites []uint16, opts Options) (vulnerable, decided bool) {
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.timeout()))
	cfg := &ztls.Config{MaxVersion: ztls.VersionTLS12, HeartbeatEnabled: true, InsecureSkipVerify: true, ServerName: opts.ServerName}
	if len(suites) > 0 {
		cfg.CipherSuites, cfg.ForceSuites = suites, true
	}
	c := ztls.Client(conn, cfg)
	_, err = c.CheckHeartbleed(make([]byte, 256))
	switch {
	case err == nil: // the handshake completed and the server offers no heartbeat extension
		return false, true
	case err == ztls.HeartbleedError: // the heartbeat went out; the log says what came back
		return c.GetHeartbleedLog() != nil && c.GetHeartbleedLog().Vulnerable, true
	default: // the handshake itself failed
		return false, false
	}
}

// legacyCipherIDs are the ids of the accepted ciphers below TLS 1.3, which is as high as the
// heartbeat (and zcrypto) goes.
func legacyCipherIDs(cs []Cipher) []uint16 {
	var out []uint16
	for _, c := range cs {
		if c.Version != "TLS1_3" {
			out = append(out, c.ID)
		}
	}
	return out
}

// knownPrimeSeverity grades a well-known DH prime as testssl's out_common_prime does: a published
// group is worth precomputing for, so it is held to a stricter ladder than an unknown one, and is
// no concern at all above 1536 bits (RFC 7919's groups are recommended practice).
func knownPrimeSeverity(bits int) string {
	switch {
	case bits <= 800:
		return "CRITICAL"
	case bits <= 1024:
		return "HIGH"
	case bits <= 1536:
		return "LOW"
	default:
		return ""
	}
}

// dhSeverity grades a DH group of 1024 bits or less as testssl's pr_dh_quality does.
func dhSeverity(bits int) string {
	switch {
	case bits <= 600:
		return "CRITICAL"
	case bits <= 800:
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
