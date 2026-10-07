package sslcheck

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/binary"
	"io"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// versionTLS13 is TLS 1.3's number; zcrypto stops at 1.2, so 1.3 goes through crypto/tls.
const versionTLS13 = 0x0304

// versionSSL20 is SSLv2's number; it has its own handshake, probed raw below.
const versionSSL20 = 0x0200

// allVersions is every version the scan tests, oldest first.
var allVersions = []struct {
	version    uint16
	name       string
	deprecated bool
}{
	{versionSSL20, "SSLv2", true},
	{ztls.VersionSSL30, "SSLv3", true},
	{ztls.VersionTLS10, "TLS1", true},
	{ztls.VersionTLS11, "TLS1_1", true},
	{ztls.VersionTLS12, "TLS1_2", false},
	{versionTLS13, "TLS1_3", false},
}

// scanProtocols tests each version and reports which the host offers.
func scanProtocols(ctx context.Context, addr string, opts Options) []Protocol {
	out := make([]Protocol, 0, len(allVersions))
	for _, v := range allVersions {
		if ctx.Err() != nil {
			break
		}
		out = append(out, Protocol{Version: v.version, Name: v.name, Deprecated: v.deprecated, Offered: offersVersion(ctx, addr, v.version, opts)})
	}
	return out
}

// offersVersion reports whether the host completes a handshake at exactly this version.
func offersVersion(ctx context.Context, addr string, version uint16, opts Options) bool {
	switch version {
	case versionSSL20:
		return offersSSL2(ctx, addr, opts)
	case versionTLS13:
		conn, err := tls13Dial(ctx, addr, opts)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	default:
		log, err := legacyHandshake(ctx, addr, version, cipherIDs(), opts)
		return err == nil && log != nil && log.ServerHello != nil && uint16(log.ServerHello.Version) == version
	}
}

// legacyHandshake opens one connection and offers suites at exactly version, returning what the
// server answered. A failure (alert, reset, timeout) means the server accepted none of it.
func legacyHandshake(ctx context.Context, addr string, version uint16, suites []uint16, opts Options) (*ztls.ServerHandshake, error) {
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.timeout()))
	cfg := &ztls.Config{
		MinVersion: version, MaxVersion: version,
		CipherSuites: suites, ForceSuites: true,
		ServerName: opts.ServerName, InsecureSkipVerify: true,
	}
	c := ztls.Client(conn, cfg)
	err = c.Handshake()
	return c.GetHandshakeLog(), err
}

// tls13Dial completes a TLS 1.3 handshake through crypto/tls, which zcrypto cannot speak.
func tls13Dial(ctx context.Context, addr string, opts Options) (*cryptotls.Conn, error) {
	d := &cryptotls.Dialer{Config: &cryptotls.Config{
		MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13,
		ServerName: opts.ServerName, InsecureSkipVerify: true,
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*cryptotls.Conn), nil
}

// tls13Ciphers reports the TLS 1.3 suites the host negotiates. crypto/tls will not let a client
// restrict them, so the scan reads the one it negotiates and trusts that all three are strong:
// every TLS 1.3 suite is AEAD with an ephemeral key exchange.
func tls13Ciphers(ctx context.Context, addr string, opts Options) []Cipher {
	conn, err := tls13Dial(ctx, addr, opts)
	if err != nil {
		return nil
	}
	defer conn.Close()
	name := cryptotls.CipherSuiteName(conn.ConnectionState().CipherSuite)
	return []Cipher{{Name: name, Version: "TLS1_3", Strength: StrengthStrong, Bits: keyBits(name), Forward: true}}
}

// offersSSL2 reports whether the host answers an SSLv2 CLIENT-HELLO with an SSLv2 SERVER-HELLO.
// SSLv2 has its own wire format that no TLS library speaks, so the hello is sent by hand; its
// only use is detecting SSLv2 at all, which is what DROWN turns on.
func offersSSL2(ctx context.Context, addr string, opts Options) bool {
	conn, err := dial(ctx, addr, opts)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.timeout()))
	if _, err := conn.Write(ssl2ClientHello()); err != nil {
		return false
	}
	// An SSLv2 record: a 2-byte length with the high bit set, then a body whose first byte is the
	// message type. SERVER-HELLO is type 4.
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return false
	}
	if head[0]&0x80 == 0 {
		return false // not the short SSLv2 record framing
	}
	length := int(binary.BigEndian.Uint16(head) & 0x7fff)
	if length < 1 {
		return false
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		return false
	}
	return first[0] == 0x04 // SERVER-HELLO
}

// ssl2ClientHello is a minimal SSLv2 CLIENT-HELLO offering a few SSLv2 ciphers. It is only ever
// used to see whether the host replies in SSLv2; nothing in the reply is decrypted or used.
func ssl2ClientHello() []byte {
	ciphers := []byte{
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
	}
	challenge := make([]byte, 16)
	body := []byte{
		0x01,       // MSG-CLIENT-HELLO
		0x00, 0x02, // version SSLv2
		0x00, byte(len(ciphers)), // cipher-spec length
		0x00, 0x00, // session-id length
		0x00, byte(len(challenge)), // challenge length
	}
	body = append(body, ciphers...)
	body = append(body, challenge...)
	rec := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(rec, uint16(len(body))|0x8000) // short record, high bit set
	copy(rec[2:], body)
	return rec
}
