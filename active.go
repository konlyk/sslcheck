package sslcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"crypto/x509"
	"math/big"
)

// The active probes send crafted handshake records and read a flaw from how the server answers,
// not from what it offers. Heartbleed is in vulns.go (zcrypto's built-in check). The three below
// are hand-rolled on raw.go. Each is conservative: an error, a timeout or an answer it does not
// recognise is reported as not vulnerable, so a probe never raises a false alarm on a scan.

// a few RSA key-exchange ciphers, for the ROBOT probe, and some CBC ciphers for CCS/Ticketbleed.
var (
	rsaKexSuites = []uint16{
		0x003c, 0x002f, 0x0035, 0x003d, // TLS_RSA_WITH_AES_128/256_CBC_SHA(256)
		0x009c, 0x009d, // TLS_RSA_WITH_AES_128/256_GCM_SHA256/384
		0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	}
	probeSuites = append([]uint16{
		0xc02f, 0xc030, 0xc02b, 0xc02c, // ECDHE suites first, so any server answers
	}, rsaKexSuites...)
)

// ccsInjection reports whether the server accepts a ChangeCipherSpec before the key exchange
// (CVE-2014-0224). A patched server rejects the early CCS with an unexpected-message or
// handshake-failure alert, or drops the connection; the vulnerable OpenSSL instead derives keys
// from an empty secret and answers a following record with a bad-record-mac/decryption alert.
func ccsInjection(ctx context.Context, addr string, opts Options) bool {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return false
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, probeSuites, nil, nil)); err != nil {
		return false
	}
	msgs, err := r.readUntilServerHelloDone()
	if err != nil {
		return false
	}
	// Use the version the server chose for the ChangeCipherSpec records.
	version := uint16(0x0303)
	if sh := msgs[hsServerHello]; len(sh) >= 2 {
		version = uint16(sh[0])<<8 | uint16(sh[1])
	}
	// Inject a ChangeCipherSpec before the key exchange. A patched server rejects the first with
	// an unexpected-message or handshake-failure alert (or drops the connection); the vulnerable
	// OpenSSL accepts it, derives keys from an empty master secret, and errors only on a following
	// record. testssl sends the CCS twice and reads the answer to the second, so the probe does too.
	ccs := []byte{0x01}
	if err := r.writeRecord(recChangeCipher, version, ccs); err != nil {
		return false
	}
	_ = r.writeRecord(recChangeCipher, version, ccs)
	_, _, err = r.readRecord()
	a, ok := asAlert(err)
	if !ok {
		return false // empty reply or plain handshake data, not the vulnerable signature: patched
	}
	switch a.code {
	case 20, 21, 22: // bad_record_mac, decryption_failed, record_overflow: the vulnerable path
		return true
	default: // 10 unexpected_message, 40 handshake_failure, …: patched
		return false
	}
}

// ticketbleed reports whether an F5 BIG-IP returns uninitialised memory in the session id it
// echoes for a crafted session ticket (CVE-2016-9244). The probe sends a one-byte marker as the
// session id with an (invalid) session-ticket extension; a vulnerable server echoes a 32-byte
// session id that starts with the marker and is padded with memory, while a sound server echoes
// nothing or exactly the marker.
func ticketbleed(ctx context.Context, addr string, opts Options) bool {
	// The flaw only shows on a resumption, so harvest a valid TLS 1.2 ticket from a normal
	// handshake first.
	ticket := harvestSessionTicket(ctx, addr, opts)
	if len(ticket) == 0 {
		return false // the server issues no session ticket: nothing to resume, not vulnerable
	}
	ticketExt := extension(0x0023, ticket)
	sid := []byte{0x00, 0x0b, 0xad, 0xc0, 0xde, 0x00} // a short, fixed session id, as testssl sends
	var memories [][]byte
	for i := 0; i < 3; i++ {
		if ctx.Err() != nil {
			return false
		}
		echoed := ticketbleedEcho(ctx, addr, opts, sid, ticketExt)
		if len(echoed) != 32 || !bytes.Equal(echoed[:len(sid)], sid) {
			return false // not the full-length echo of our short id that the flaw produces
		}
		memories = append(memories, append([]byte(nil), echoed[len(sid):]...))
	}
	// Vulnerable when the bytes past our short id differ between resumptions: they are leaked
	// memory, not a stable value the server chose. Three matching echoes with differing tails is
	// testssl's signature, so a server that returns a fixed 32-byte id is not mistaken for a leak.
	return !bytes.Equal(memories[0], memories[1]) && !bytes.Equal(memories[1], memories[2])
}

// harvestSessionTicket completes one TLS 1.2 handshake and returns the session ticket the server
// issued, or nil when it issues none. The ticket is captured through a client session cache; in
// TLS 1.2 it arrives during the handshake, so it is set by the time Dial returns.
func harvestSessionTicket(ctx context.Context, addr string, opts Options) []byte {
	g := &ticketGrabber{}
	d := &cryptotls.Dialer{Config: &cryptotls.Config{
		ServerName: opts.ServerName, InsecureSkipVerify: true, //nolint:gosec // reading a ticket, not trusting
		MinVersion: cryptotls.VersionTLS10, MaxVersion: cryptotls.VersionTLS12,
		ClientSessionCache: g,
	}}
	cctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return nil
	}
	_ = conn.Close()
	return g.ticket
}

// ticketGrabber is a crypto/tls ClientSessionCache that keeps the first session ticket the server
// sends.
type ticketGrabber struct{ ticket []byte }

func (g *ticketGrabber) Get(string) (*cryptotls.ClientSessionState, bool) { return nil, false }

func (g *ticketGrabber) Put(_ string, cs *cryptotls.ClientSessionState) {
	if cs == nil || g.ticket != nil {
		return
	}
	if t, _, err := cs.ResumptionState(); err == nil {
		g.ticket = t
	}
}

// ticketbleedEcho sends a TLS 1.2 ClientHello that resumes ticket with the short session id and
// returns the session id the server echoes in its ServerHello. It reads only up to the
// ServerHello: a resumption follows it with a ChangeCipherSpec and an encrypted Finished, neither
// of which the probe needs or can read.
func ticketbleedEcho(ctx context.Context, addr string, opts Options, sid, ticketExt []byte) []byte {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return nil
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, probeSuites, sid, ticketExt)); err != nil {
		return nil
	}
	var buf []byte
	for {
		typ, body, err := r.readRecord()
		if err != nil {
			return nil
		}
		if typ != recHandshake {
			continue
		}
		buf = append(buf, body...)
		for len(buf) >= 4 {
			n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
			if len(buf) < 4+n {
				break
			}
			if buf[0] == hsServerHello {
				return serverHelloSessionID(buf[4 : 4+n])
			}
			buf = buf[4+n:]
		}
	}
}

// serverHelloSessionID pulls the session id out of a ServerHello body.
func serverHelloSessionID(sh []byte) []byte {
	if len(sh) < 2+32+1 { // version + random + id length
		return nil
	}
	idLen := int(sh[34])
	if len(sh) < 35+idLen {
		return nil
	}
	return sh[35 : 35+idLen]
}

// robot reports a Bleichenbacher RSA padding oracle (ROBOT) when the server's answers to a small
// fixed set of (mis)formed RSA key-exchange messages let an attacker tell a well-padded premaster
// from a badly-padded one. It only ever sends that fixed set — it does not run the attack — and
// returns "" when the server offers no RSA key exchange or does not behave as an oracle.
func robot(ctx context.Context, addr string, opts Options) string {
	pub := rsaKexPubKey(ctx, addr, opts)
	if pub == nil {
		return "" // no RSA key exchange to probe
	}
	size := pub.Size()
	if size < 59 { // too small to hold PKCS#1 v1.5 framing, padding and a 48-byte premaster
		return ""
	}
	// The premaster carries the offered ClientHello version; a server that checks it treats a
	// premaster with the wrong version as invalid, so the valid probe must match it or the oracle
	// is masked.
	const version = uint16(0x0303)
	// Run the five-probe battery twice. Report vulnerable only when it distinguishes the probes
	// and distinguishes them the same way both times, so a transient answer (a dropped connection,
	// a one-off timeout) is never mistaken for a padding oracle.
	first, ok := robotBattery(ctx, addr, opts, pub, size, version)
	if !ok || allEqual(first) {
		return ""
	}
	second, ok := robotBattery(ctx, addr, opts, pub, size, version)
	if !ok || !sameDiffPattern(first, second) {
		return ""
	}
	return "the server's answers to malformed RSA key exchanges differ by padding validity"
}

// robotBattery sends the five probes once and returns how the server answered each. ok is false
// when a probe could not be delivered (a dial or write failure), which makes the whole run
// inconclusive rather than a signal.
func robotBattery(ctx context.Context, addr string, opts Options, pub *rsa.PublicKey, size int, version uint16) ([]string, bool) {
	probes := robotProbes(size, version)
	resp := make([]string, 0, len(probes))
	for _, p := range probes {
		if ctx.Err() != nil {
			return nil, false
		}
		r, ok := robotResponse(ctx, addr, opts, pub, p, version)
		if !ok {
			return nil, false
		}
		resp = append(resp, r)
	}
	return resp, true
}

// rsaKexPubKey offers only RSA key-exchange suites and returns the RSA public key from the
// certificate the server sends in that same handshake. Reading the key from the probe's own
// Certificate message (rather than a second, unrestricted connection) uses exactly the key an RSA
// key exchange encrypts to, so a host that also serves an ECDSA certificate is probed correctly.
func rsaKexPubKey(ctx context.Context, addr string, opts Options) *rsa.PublicKey {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return nil
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, rsaKexSuites, nil, nil)); err != nil {
		return nil
	}
	msgs, err := r.readUntilServerHelloDone()
	if err != nil {
		return nil
	}
	return leafRSAKey(msgs[hsCertificate])
}

// leafRSAKey parses the leaf out of a TLS Certificate handshake message and returns its RSA public
// key, or nil when the leaf is absent or not an RSA key.
func leafRSAKey(cert []byte) *rsa.PublicKey {
	if len(cert) < 6 { // 3-byte list length + 3-byte first-certificate length
		return nil
	}
	list := cert[3:]
	n := int(list[0])<<16 | int(list[1])<<8 | int(list[2])
	if len(list) < 3+n {
		return nil
	}
	c, err := x509.ParseCertificate(list[3 : 3+n])
	if err != nil {
		return nil
	}
	pub, _ := c.PublicKey.(*rsa.PublicKey)
	return pub
}

// robotProbes is one correctly padded PKCS#1 v1.5 block carrying the offered version, followed by
// four malformed variants, each exactly the key's byte length. They are fixed decoys; nothing
// real is encrypted. A server that is not an oracle answers all five alike.
func robotProbes(size int, version uint16) [][]byte {
	pms := make([]byte, 48)
	_, _ = rand.Read(pms)
	pms[0], pms[1] = byte(version>>8), byte(version) // the client version a checking server expects
	block := func() []byte {
		b := make([]byte, size)
		for i := 2; i < size-49; i++ {
			b[i] = 0x01 // non-zero PKCS#1 padding
		}
		b[0], b[1] = 0x00, 0x02 // correct PKCS#1 v1.5 framing
		b[size-49] = 0x00       // the 0x00 delimiter before the premaster
		copy(b[size-48:], pms)
		return b
	}
	valid := block()
	wrongFirst := block()
	wrongFirst[0] = 0x01 // first byte not 0x00
	wrongSecond := block()
	wrongSecond[1] = 0x01 // second byte not 0x02
	noDelimiter := block()
	noDelimiter[size-49] = 0x01 // no 0x00 before the premaster
	earlyZero := block()
	earlyZero[2] = 0x00 // a 0x00 inside the padding
	return [][]byte{valid, wrongFirst, wrongSecond, noDelimiter, earlyZero}
}

// robotResponse sends one crafted RSA ClientKeyExchange and reports how the server answered,
// classified coarsely (an alert code, "data" for a plaintext record, or "closed"). ok is false
// only when the probe could not be delivered at all, which the caller treats as inconclusive.
func robotResponse(ctx context.Context, addr string, opts Options, pub *rsa.PublicKey, block []byte, version uint16) (string, bool) {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return "", false
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, rsaKexSuites, nil, nil)); err != nil {
		return "", false
	}
	if _, err := r.readUntilServerHelloDone(); err != nil {
		return "", false
	}
	enc := rsaEncryptBlock(pub, block)
	cke := handshakeMessage(16, append(uint16b(len(enc)), enc...)) // 16 = client_key_exchange
	if err := r.writeRecord(recHandshake, version, cke); err != nil {
		return "", false
	}
	_ = r.writeRecord(recChangeCipher, version, []byte{0x01})
	_ = r.writeRecord(recHandshake, version, bytes.Repeat([]byte{0x00}, 40)) // a dummy encrypted Finished
	_, _, err = r.readRecord()
	if a, ok := asAlert(err); ok {
		return "alert-" + itoaByte(a.code), true
	}
	if err != nil {
		return "closed", true
	}
	return "data", true
}

// allEqual reports whether every element equals the first.
func allEqual(xs []string) bool {
	for _, x := range xs[1:] {
		if x != xs[0] {
			return false
		}
	}
	return true
}

// sameDiffPattern reports whether a and b set the same probes apart from the first one, so that a
// difference counts as an oracle only when it reproduces.
func sameDiffPattern(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i] == a[0]) != (b[i] == b[0]) {
			return false
		}
	}
	return true
}

// rsaEncryptBlock raw-RSA-encrypts an already-padded block (m^e mod n), without adding padding of
// its own: the probes above are the padding under test.
func rsaEncryptBlock(pub *rsa.PublicKey, block []byte) []byte {
	m := new(big.Int).SetBytes(block)
	e := big.NewInt(int64(pub.E))
	c := new(big.Int).Exp(m, e, pub.N)
	out := make([]byte, pub.Size())
	c.FillBytes(out)
	return out
}
