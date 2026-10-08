package sslcheck

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"
)

// rate grades the host as testssl 3.2 does (run_rating, implementing SSL Labs's SSL Server Rating
// Guide 2009r): three category scores weighted 30/30/40, a letter from the score, the grade caps
// testssl sets while it scans, and the warnings that turn an uncapped A into A+ or A-.
//
// The rules follow testssl's code rather than the guide's prose where the two differ, so that a
// grade can be checked against testssl: the guide's "no AEAD" cap is not applied (testssl's
// pattern for it never matches), ephemeral DH group sizes do not lower the key-exchange score
// (testssl passes them as type DHE, which its scorer ignores), and SWEET32 caps only when 64-bit
// ciphers are reachable at TLS 1.1 but not at the server's preferred protocol.
func rate(a *Assessment) {
	r := &rater{}
	r.protocols(a)
	r.ciphers(a)
	for _, c := range a.Certificates {
		r.certificate(c)
	}
	if len(a.Ciphers) > 0 && !robustForward(a.Ciphers) {
		r.capTo("B", "Forward Secrecy (FS) is not supported")
	}
	r.http(a)
	r.vulnerabilities(a)

	a.ProtocolScore, a.KeyExchangeScore, a.CipherStrengthScore = 0, 0, 0
	if r.cap == "F" || r.cap == "T" || r.cap == "M" {
		// testssl does not compute a score once the grade is a fail.
		a.Score, a.Grade = 0, r.cap
		a.Reasons, a.Warnings = r.sortedReasons(), dedupe(r.warnings)
		return
	}

	// Category 1, protocol support: the best and the worst protocol offered, averaged.
	best, worst, sslv3Best := protocolPoints(a.Protocols)
	if sslv3Best {
		r.capTo("F", "SSLv3 is the best protocol offered")
	}
	c1 := (best + worst) / 2

	// Category 2, key exchange: the weakest certificate key.
	c2 := keyExchangeScore(a.Certificates)
	if c2 <= 40 {
		r.capTo("F", "Using an insecure public key and/or ephemeral key")
	} else if c2 <= 80 {
		r.capTo("B", "Using a weak public key and/or ephemeral key")
	}

	// Category 3, cipher strength: the strongest and the weakest cipher's key size.
	c3 := cipherStrengthScore(a.Ciphers)

	score := c1*30/100 + c2*30/100 + c3*40/100
	if c1 == 0 || c2 == 0 || c3 == 0 {
		score = 0
	}
	a.ProtocolScore, a.KeyExchangeScore, a.CipherStrengthScore, a.Score = c1, c2, c3, score

	pre := letterFor(score)
	switch {
	case r.cap != "" && !(pre > r.cap):
		a.Grade = r.cap
	case r.cap == "" && pre == "A":
		if len(r.warnings) == 0 {
			a.Grade = "A+"
		} else {
			a.Grade = "A-"
		}
	default:
		a.Grade = pre
	}
	a.Reasons, a.Warnings = r.sortedReasons(), dedupe(r.warnings)
}

// rater collects caps and warnings the way testssl's set_grade_cap and set_grade_warning do.
type rater struct {
	cap      string // "" none; otherwise the worst cap so far, or the last T/M
	reasons  []string
	warnings []string
}

// capTo records a cap. T and M always replace the current cap (a mismatch or an untrusted chain is
// a hard fail whatever else was found); any other cap is kept only when it is worse, letters
// comparing as testssl compares them (A < B < … < F).
func (r *rater) capTo(letter, reason string) {
	r.reasons = append(r.reasons, "Grade capped to "+letter+". "+reason)
	if letter == "T" || letter == "M" {
		r.cap = letter
		return
	}
	if !(r.cap > letter) {
		r.cap = letter
	}
}

func (r *rater) warn(w string) { r.warnings = append(r.warnings, w) }

// sortedReasons are the caps, worst first, without repeats, as testssl lists them (sort -ru).
func (r *rater) sortedReasons() []string {
	out := dedupe(r.reasons)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] > out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (r *rater) protocols(a *Assessment) {
	offered := offeredSet(a.Protocols)
	if offered["SSLv2"] {
		r.capTo("F", "SSLv2 is offered")
	}
	if offered["SSLv3"] {
		r.capTo("B", "SSLv3 is offered")
	}
	if offered["TLS1"] {
		r.capTo("B", "TLS 1.0 offered")
	}
	if offered["TLS1_1"] {
		r.capTo("B", "TLS 1.1 offered")
	}
	if !offered["TLS1_2"] {
		switch {
		case offered["SSLv3"] || offered["TLS1"] || offered["TLS1_1"]:
			r.capTo("C", "TLS 1.2 is not offered") // the server downgrades instead
		case !offered["TLS1_3"]:
			r.capTo("C", "TLS 1.2 or TLS 1.3 are not offered")
		}
	}
	if !offered["TLS1_3"] {
		r.warn("TLS 1.3 is not supported")
	}
}

func (r *rater) ciphers(a *Assessment) {
	for _, c := range a.Ciphers {
		if has(strings.ToUpper(c.Name), "EXPORT") {
			r.capTo("F", "Export suite offered")
			break
		}
	}
	for _, c := range a.Ciphers {
		if c.Bits < 112 {
			r.capTo("F", "Using cipher suites weaker than 112 bits")
			break
		}
	}
}

// certificate applies the certificate caps in the order testssl's certificate_info sets them, so
// that of several T/M verdicts the last one stands, as in testssl.
func (r *rater) certificate(c Certificate) {
	switch c.SignatureHash {
	case "SHA1":
		r.capTo("T", "Uses SHA1 algorithm")
	case "MD2":
		r.capTo("F", "Supports a insecure signature (MD2)")
	case "MD5":
		r.capTo("F", "Supports a insecure signature (MD5)")
	}
	if c.KeyAlg == "RSA" && c.RSAExponent == 1 {
		r.capTo("F", "RSA certificate uses exponent of 1")
	}
	if c.NameMismatch {
		r.capTo("M", "Domain name mismatch")
	}
	switch {
	case c.ChainIncomplete:
		r.capTo("B", "Issues with chain of trust ("+chainReason(c)+")")
	case !c.ChainComplete:
		r.capTo("T", "Issues with chain of trust ("+chainReason(c)+")")
	}
	if c.Expired() {
		r.capTo("T", "Certificate expired")
	}
	if c.Revoked {
		r.capTo("T", "Certificate revoked")
	}
	// testssl's own self-signed test: the issuer has no organisation. (Its other branch compares
	// the issuer's CN with the certificate served without SNI, which rarely applies.)
	if c.Leaf != nil && len(c.Leaf.Issuer.Organization) == 0 {
		r.capTo("T", "Self-signed certificate")
	}
}

func chainReason(c Certificate) string {
	if c.ChainError != "" {
		return c.ChainError
	}
	switch {
	case c.SelfSigned:
		return "self signed"
	case c.Expired():
		return "expired"
	case c.ChainIncomplete:
		return "chain incomplete"
	default:
		return "not trusted"
	}
}

// http applies the HSTS warnings and the HPKP cap.
func (r *rater) http(a *Assessment) {
	if a.HTTP == nil {
		return
	}
	if w := hstsWarning(a.HTTP.HSTS); w != "" {
		r.warn(w)
	}
	if hpkpProblem(a.HTTP, a.Certificates) {
		r.capTo("A", "Problems with HTTP Public Key Pinning (HPKP)")
	}
}

// hpkpProblem is testssl's set of HPKP faults: more than one Public-Key-Pins header, a single pin,
// a max-age under testssl's minimum, no pin matching the served chain, or no backup pin (one
// matching nothing served).
func hpkpProblem(h *HTTPHeaders, certs []Certificate) bool {
	if len(h.HPKP) == 0 && len(h.HPKPReportOnly) == 0 {
		return false
	}
	if len(h.HPKP) > 1 {
		return true
	}
	header := ""
	if len(h.HPKP) == 1 {
		header = h.HPKP[0]
	} else {
		header = h.HPKPReportOnly[0]
	}
	var pins []string
	maxAge := int64(-1)
	for _, part := range strings.Split(header, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "pin-sha256":
			pins = append(pins, v)
		case "max-age":
			n, _ := strconv.ParseInt(strings.Map(digitsOnly, v), 10, 64)
			maxAge = n
		}
	}
	if len(pins) == 1 {
		return true
	}
	// testssl compares the age in seconds with HPKP_MIN, which it sets in days (30): 30 seconds.
	if maxAge < 30 {
		return true
	}
	served := map[string]bool{}
	for _, c := range certs {
		for _, x := range c.Chain {
			served[spkiPin(x)] = true
		}
	}
	match, backup := false, false
	for _, p := range pins {
		if served[p] || served[strings.TrimRight(p, "=")+"="] {
			match = true
		} else {
			backup = true
		}
	}
	return !match || !backup
}

func digitsOnly(r rune) rune {
	if r >= '0' && r <= '9' {
		return r
	}
	return -1
}

// spkiPin is a certificate's HPKP pin: base64 of the SHA-256 of its SubjectPublicKeyInfo.
func spkiPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// vulnerabilities applies the caps of the vulnerability checks and the renegotiation warning.
func (r *rater) vulnerabilities(a *Assessment) {
	for _, v := range a.Vulns {
		switch v.Name {
		case "HEARTBLEED":
			r.capTo("F", "Vulnerable to Heartbleed")
		case "CCS_INJECTION":
			r.capTo("F", "Vulnerable to CCS injection")
		case "TICKETBLEED":
			r.capTo("F", "Vulnerable to Ticketbleed")
		case "ROBOT":
			r.capTo("F", "Vulnerable to ROBOT")
		}
	}
	if a.SecureRenegotiation != nil && !*a.SecureRenegotiation {
		r.warn("Secure renegotiation is not supported")
	}
	if a.Compression {
		r.capTo("C", "Vulnerable to CRIME")
	}
	offered := offeredSet(a.Protocols)
	cbcAt := map[string]bool{}
	rc4At := map[string]bool{}
	block64At := map[string]bool{}
	for _, c := range a.Ciphers {
		n := strings.ToUpper(c.Name)
		if has(n, "_CBC_") {
			cbcAt[c.Version] = true
		}
		if has(n, "RC4") {
			rc4At[c.Version] = true
		}
		if block64(n) {
			block64At[c.Version] = true
		}
	}
	if offered["SSLv3"] && cbcAt["SSLv3"] {
		r.capTo("C", "Vulnerable to POODLE")
	}
	if !offered["TLS1_3"] && block64At["TLS1_1"] && !block64At[bestBelowTLS13(a.Protocols)] {
		r.capTo("C", "Uses 64 bit block ciphers with TLS 1.1 (vulnerable to SWEET32)")
	}
	if offered["SSLv2"] {
		r.capTo("F", "Vulnerable to DROWN")
	}
	if (cbcAt["SSLv3"] || cbcAt["TLS1"]) && !(offered["TLS1_1"] || offered["TLS1_2"] || offered["TLS1_3"]) {
		r.capTo("B", "Vulnerable to BEAST")
	}
	if len(rc4At) > 0 {
		if rc4OnlyAtTLS11(a) {
			r.capTo("C", "RC4 ciphers offered on TLS 1.1")
		}
		r.capTo("B", "RC4 ciphers offered")
	}
}

// block64 reports whether a cipher uses a 64-bit block (SWEET32): 3DES, DES, IDEA, RC2.
func block64(upperName string) bool {
	return has(upperName, "3DES") || has(upperName, "DES_EDE") || has(upperName, "_DES_") ||
		has(upperName, "IDEA") || has(upperName, "_RC2_")
}

// bestBelowTLS13 is the name of the best protocol offered below TLS 1.3, the one an ordinary
// client ends up at when TLS 1.3 is not offered.
func bestBelowTLS13(ps []Protocol) string {
	best := ""
	var bestV uint16
	for _, p := range ps {
		if p.Offered && p.Version != versionTLS13 && p.Version > bestV {
			best, bestV = p.Name, p.Version
		}
	}
	return best
}

// protocolPoints is category 1's best and worst protocol, on SSL Labs's scale.
func protocolPoints(ps []Protocol) (best, worst int, sslv3Best bool) {
	offered := offeredSet(ps)
	switch {
	case offered["TLS1_3"] || offered["TLS1_2"]:
		best = 100
	case offered["TLS1_1"]:
		best = 95
	case offered["TLS1"]:
		best = 90
	case offered["SSLv3"]:
		best, sslv3Best = 80, true
	}
	switch {
	case offered["SSLv2"]:
		worst = 0
	case offered["SSLv3"]:
		worst = 80
	case offered["TLS1"]:
		worst = 90
	case offered["TLS1_1"]:
		worst = 95
	default:
		worst = 100
	}
	return best, worst, sslv3Best
}

// keyExchangeScore is testssl's KEY_EXCH_SCORE: 100, lowered by each certificate key.
func keyExchangeScore(certs []Certificate) int {
	score := 100
	lower := func(to int) {
		if score >= to {
			score = to
		}
	}
	for _, c := range certs {
		size := c.KeyBits
		switch c.KeyAlg {
		case "EC", "EdDSA":
			switch {
			case size < 110:
				lower(20)
			case size < 123:
				lower(40)
			case size < 163:
				lower(80)
			case size < 225:
				lower(90)
			}
		case "RSA", "DSA", "DH":
			switch {
			case size < 512:
				lower(20)
			case size < 1024:
				lower(40)
			case size < 2048:
				lower(80)
			case size < 4096:
				lower(90)
			}
		}
	}
	return score
}

// cipherStrengthScore is category 3: the best and the worst cipher key size, each on SSL Labs's
// scale, averaged.
func cipherStrengthScore(cs []Cipher) int {
	bestBits, worstBits := 0, 100000
	for _, c := range cs {
		bestBits = max(bestBits, c.Bits)
		worstBits = min(worstBits, c.Bits)
	}
	var best, worst int
	switch {
	case bestBits >= 256:
		best = 100
	case bestBits >= 128:
		best = 80
	default:
		best = 20
	}
	switch {
	case worstBits > 0 && worstBits < 128:
		worst = 20
	case worstBits >= 128 && worstBits < 256:
		worst = 80
	case worstBits >= 256:
		worst = 100
	default:
		worst = 0
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

func offeredSet(ps []Protocol) map[string]bool {
	out := map[string]bool{}
	for _, p := range ps {
		out[p.Name] = p.Offered
	}
	return out
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// robustForward reports whether a forward-secret suite worth the name is accepted: testssl's FS
// test leaves out NULL, anonymous, DES/3DES and RC4 suites, so a host whose only ECDHE suites are
// those has no forward secrecy for the rating.
func robustForward(cs []Cipher) bool {
	for _, c := range cs {
		n := strings.ToUpper(c.Name)
		if c.Forward && !has(n, "NULL") && !has(n, "_ANON_") && !has(n, "DES") && !has(n, "RC4") {
			return true
		}
	}
	return false
}

// rc4OnlyAtTLS11 is when testssl caps RC4 to C: it first collects the RC4 suites the server
// accepts at its preferred protocol (none when TLS 1.3 is offered, which that probe then
// negotiates), then caps for any further RC4 suite it finds at TLS 1.1.
func rc4OnlyAtTLS11(a *Assessment) bool {
	preferred := ""
	if !offeredSet(a.Protocols)["TLS1_3"] {
		preferred = bestBelowTLS13(a.Protocols)
	}
	atPreferred := map[string]bool{}
	for _, c := range a.Ciphers {
		if c.Version == preferred && has(strings.ToUpper(c.Name), "RC4") {
			atPreferred[c.Name] = true
		}
	}
	for _, c := range a.Ciphers {
		if c.Version == "TLS1_1" && has(strings.ToUpper(c.Name), "RC4") && !atPreferred[c.Name] {
			return true
		}
	}
	return false
}
