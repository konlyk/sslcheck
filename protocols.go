package sslcheck

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
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

// scanProtocols tests each version and reports which the host offers. The versions are
// independent handshakes, so they run concurrently; the result keeps them oldest-first. The
// second value names the versions whose probe ended on a network failure rather than the
// server's answer, so "not offered" there is not certain.
func scanProtocols(ctx context.Context, addr string, opts Options) ([]Protocol, []string) {
	out := make([]Protocol, len(allVersions))
	undecided := make([]bool, len(allVersions))
	var wg sync.WaitGroup
	for i, v := range allVersions {
		out[i] = Protocol{Version: v.version, Name: v.name, Deprecated: v.deprecated}
		if ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		go func(i int, version uint16) {
			defer wg.Done()
			out[i].Offered, undecided[i] = offersVersion(ctx, addr, version, opts)
		}(i, v.version)
	}
	wg.Wait()
	var incomplete []string
	for i, u := range undecided {
		if u {
			incomplete = append(incomplete, "protocol "+out[i].Name)
		}
	}
	return out, incomplete
}

// offersVersion reports whether the host completes a handshake at exactly this version. undecided
// is true when the probe ended on a network failure (a timeout, a reset) rather than an answer.
func offersVersion(ctx context.Context, addr string, version uint16, opts Options) (offered, undecided bool) {
	switch version {
	case versionSSL20:
		return offersSSL2(ctx, addr, opts), false
	case versionTLS13:
		conn, err := tls13Dial(ctx, addr, opts)
		if err != nil {
			return false, isTransportFailure(err)
		}
		_ = conn.Close()
		return true, false
	default:
		// Offered when the server answers with a ServerHello at that version, whether or not the
		// rest of the handshake completes. A missed protocol changes the grade, so this probe is
		// given the full three attempts even when the failures are timeouts.
		log, err := handshakeAttempts(ctx, addr, version, cipherIDs(), opts, nil, 3)
		if log != nil && log.ServerHello != nil && uint16(log.ServerHello.Version) == version {
			return true, false
		}
		return false, err != nil && isTransportFailure(err)
	}
}

// legacyHandshake opens one connection and offers suites at exactly version, returning what the
// server answered. A failure (alert, reset, timeout) means the server accepted none of it.
func legacyHandshake(ctx context.Context, addr string, version uint16, suites []uint16, opts Options) (*ztls.ServerHandshake, error) {
	return legacyHandshakeWith(ctx, addr, version, suites, opts, nil)
}

// legacyHandshakeWith is legacyHandshake with the client config adjusted by tweak. A handshake
// that gets no ServerHello and no TLS alert is retried, as a dropped connection is not the
// server's answer; an alert is. A reset or a close is tried up to three times; a timeout only
// twice, since a server that twice says nothing for the whole timeout has answered, and a third
// wait would only make a silently dropping host cost three timeouts per probe.
func legacyHandshakeWith(ctx context.Context, addr string, version uint16, suites []uint16, opts Options, tweak func(*ztls.Config)) (*ztls.ServerHandshake, error) {
	return handshakeAttempts(ctx, addr, version, suites, opts, tweak, 2)
}

// handshakeAttempts makes up to three handshake attempts, stopping at the first that yields a
// ServerHello or a TLS alert, and after maxTimeouts of them have timed out. A retry waits a
// little first: a dropped connection usually means the host is shedding a burst, and an immediate
// retry lands in the same burst.
func handshakeAttempts(ctx context.Context, addr string, version uint16, suites []uint16, opts Options, tweak func(*ztls.Config), maxTimeouts int) (*ztls.ServerHandshake, error) {
	var log *ztls.ServerHandshake
	var err error
	timeouts := 0
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 && !sleepCtx(ctx, time.Duration(attempt)*retryBackoff) {
			break
		}
		log, err = legacyHandshakeOnce(ctx, addr, version, suites, opts, tweak)
		if (log != nil && log.ServerHello != nil) || err == nil || isTLSAlert(err) || ctx.Err() != nil {
			break
		}
		if isTimeout(err) {
			timeouts++
			if timeouts >= maxTimeouts {
				break
			}
		}
	}
	return log, err
}

// retryBackoff is the wait before the first retry of a dropped connection; later retries wait
// multiples of it.
const retryBackoff = 250 * time.Millisecond

// sleepCtx waits d, or until ctx is done, and reports whether the wait ran its course.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// isTLSAlert reports whether the server ended the handshake with a TLS alert: a refusal, unlike a
// network failure.
func isTLSAlert(err error) bool {
	msg := err.Error()
	// zcrypto's alert type is unexported; a server alert surfaces as "remote error: tls: …".
	return strings.Contains(msg, "remote error") || strings.Contains(msg, "alert")
}

// isTimeout reports whether err is a network timeout (the connection deadline passed).
func isTimeout(err error) bool {
	var ne net.Error
	return (errors.As(err, &ne) && ne.Timeout()) || strings.Contains(err.Error(), "i/o timeout")
}

// isTransportFailure reports whether err is the network failing under the probe (a timeout, a
// reset, a broken pipe) rather than the server answering, which it does with an alert or, on some
// servers, a plain close.
func isTransportFailure(err error) bool {
	if err == nil || isTLSAlert(err) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	if isTimeout(err) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection refused")
}

func legacyHandshakeOnce(ctx context.Context, addr string, version uint16, suites []uint16, opts Options, tweak func(*ztls.Config)) (*ztls.ServerHandshake, error) {
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
	if tweak != nil {
		tweak(cfg)
	}
	c := ztls.Client(conn, cfg)
	err = c.Handshake()
	return c.GetHandshakeLog(), err
}

// tls13Dial completes a TLS 1.3 handshake through crypto/tls, which zcrypto cannot speak.
func tls13Dial(ctx context.Context, addr string, opts Options) (*cryptotls.Conn, error) {
	return tlsClient(ctx, addr, &cryptotls.Config{
		MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS13,
		ServerName: opts.ServerName, InsecureSkipVerify: true, //nolint:gosec // detection only
	}, opts)
}

// tls13Ciphers reports the TLS 1.3 suites the host negotiates. crypto/tls will not let a client
// restrict them, so the scan reads the one it negotiates and trusts that all three are strong:
// every TLS 1.3 suite is AEAD with an ephemeral key exchange.
func tls13Ciphers(ctx context.Context, addr string, opts Options) []Cipher {
	var out []Cipher
	for _, s := range tls13Suites {
		if ctx.Err() != nil {
			break
		}
		if tls13Accepts(ctx, addr, s.id, opts) {
			out = append(out, Cipher{ID: s.id, Name: s.name, Version: "TLS1_3", Strength: StrengthStrong, Bits: keyBits(s.name), Forward: true})
		}
	}
	if len(out) > 0 {
		return out
	}
	// The raw probe found nothing (an unusual server): fall back to the suite crypto/tls gets.
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
