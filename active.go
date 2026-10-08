package sslcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
	"math/big"

	ztls "github.com/zmap/zcrypto/tls"
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
// fixed set of malformed RSA key-exchange messages let an attacker tell a well-padded premaster
// from a badly-padded one. It only ever sends that fixed set — it does not run the attack — and
// returns "" when the server offers no RSA key exchange or does not behave as an oracle.
func robot(ctx context.Context, host, addr string, opts Options) string {
	pub, ok := rsaKeyIfRSAKex(ctx, addr, opts)
	if !ok {
		return "" // no RSA key exchange to probe
	}
	// Each probe is a differently (mis)formed PKCS#1 v1.5 block of the server key's size. A server
	// that is not an oracle answers them all alike; one that distinguishes "valid" from "invalid"
	// padding is vulnerable.
	size := pub.Size()
	probes := robotProbes(size)
	var responses []string
	for _, pms := range probes {
		if ctx.Err() != nil {
			return ""
		}
		responses = append(responses, robotResponse(ctx, addr, opts, pub, pms))
	}
	// The first probe is the well-formed one; if any malformed probe answers differently from it
	// in a consistent way, the padding is observable.
	oracle := false
	for _, resp := range responses[1:] {
		if resp != responses[0] {
			oracle = true
		}
	}
	if !oracle {
		return ""
	}
	return "the server's answers to malformed RSA key exchanges differ by padding validity"
}

// rsaKeyIfRSAKex returns the server's RSA public key when it negotiates an RSA key-exchange
// cipher, which is what a ROBOT oracle needs; otherwise ok is false.
func rsaKeyIfRSAKex(ctx context.Context, addr string, opts Options) (*rsa.PublicKey, bool) {
	// zcrypto handshake offering only RSA-kx suites; if it succeeds, the cert key is the oracle key.
	log, err := legacyHandshake(ctx, addr, ztls.VersionTLS12, rsaKexSuites, opts)
	if err != nil || log == nil || log.ServerHello == nil {
		return nil, false
	}
	// Re-fetch the leaf through crypto/tls for a clean *rsa.PublicKey.
	d := &cryptotls.Dialer{Config: &cryptotls.Config{InsecureSkipVerify: true, ServerName: opts.ServerName, MaxVersion: cryptotls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	certs := conn.(*cryptotls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, false
	}
	pub, ok := certs[0].PublicKey.(*rsa.PublicKey)
	return pub, ok
}

// robotProbes are a well-formed PKCS#1 v1.5 block followed by malformed variants, each the key's
// byte length. They are fixed decoys; nothing real is encrypted.
func robotProbes(size int) [][]byte {
	pms := make([]byte, 48)
	_, _ = rand.Read(pms)
	valid := make([]byte, size)
	valid[0], valid[1] = 0x00, 0x02 // correct PKCS#1 v1.5 framing
	for i := 2; i < size-49; i++ {
		valid[i] = 0x01 // non-zero padding
	}
	valid[size-49] = 0x00
	copy(valid[size-48:], pms)

	wrongFirst := append([]byte(nil), valid...)
	wrongFirst[0] = 0x01 // not 0x00
	wrongSecond := append([]byte(nil), valid...)
	wrongSecond[1] = 0x01 // not 0x02
	noZero := append([]byte(nil), valid...)
	noZero[size-49] = 0x01 // no 0x00 delimiter before the premaster
	return [][]byte{valid, wrongFirst, wrongSecond, noZero}
}

// robotResponse sends one crafted RSA ClientKeyExchange and reports how the server answered,
// classified coarsely (an alert code, "none", or "closed").
func robotResponse(ctx context.Context, addr string, opts Options, pub *rsa.PublicKey, block []byte) string {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return "dial-error"
	}
	defer r.close()
	if err := r.writeRecord(recHandshake, 0x0301, clientHello(opts.ServerName, rsaKexSuites, nil, nil)); err != nil {
		return "write-error"
	}
	if _, err := r.readUntilServerHelloDone(); err != nil {
		return "no-serverhellodone"
	}
	enc := rsaEncryptBlock(pub, block)
	cke := handshakeMessage(16, append(uint16b(len(enc)), enc...)) // 16 = client_key_exchange
	if err := r.writeRecord(recHandshake, 0x0303, cke); err != nil {
		return "cke-write-error"
	}
	_ = r.writeRecord(recChangeCipher, 0x0303, []byte{0x01})
	_ = r.writeRecord(recHandshake, 0x0303, bytes.Repeat([]byte{0x00}, 40)) // a dummy encrypted Finished
	_, _, err = r.readRecord()
	if a, ok := asAlert(err); ok {
		return "alert-" + itoaByte(a.code)
	}
	if err != nil {
		return "closed"
	}
	return "none"
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
