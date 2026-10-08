package sslcheck

import (
	"context"
	"crypto/rand"
	"time"
)

// The TLS 1.3 cipher suites, by id; testssl tests all five.
var tls13Suites = []struct {
	id   uint16
	name string
}{
	{0x1301, "TLS_AES_128_GCM_SHA256"},
	{0x1302, "TLS_AES_256_GCM_SHA384"},
	{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
	{0x1304, "TLS_AES_128_CCM_SHA256"},
	{0x1305, "TLS_AES_128_CCM_8_SHA256"},
}

// tls13Accepts reports whether the server accepts the TLS 1.3 suite id: it offers only that suite
// in a TLS 1.3 ClientHello and reads the server's first answer. A ServerHello (or a
// HelloRetryRequest, which is one) naming the suite means it is accepted; an alert means not. The
// handshake is not completed: crypto/tls cannot offer a chosen TLS 1.3 suite.
func tls13Accepts(ctx context.Context, addr string, id uint16, opts Options) bool {
	r, err := dialRaw(ctx, addr, opts)
	if err != nil {
		return false
	}
	defer r.close()
	_ = r.conn.SetDeadline(time.Now().Add(opts.timeout()))
	if err := r.writeRecord(recHandshake, 0x0301, tls13ClientHello(opts.ServerName, id)); err != nil {
		return false
	}
	typ, body, err := r.readRecord()
	if err != nil || typ != recHandshake || len(body) < 4 || body[0] != hsServerHello {
		return false
	}
	sh := body[4:]
	// legacy_version(2) random(32) session_id(1+n) cipher_suite(2)
	if len(sh) < 35 {
		return false
	}
	n := int(sh[34])
	if len(sh) < 35+n+2 {
		return false
	}
	return uint16(sh[35+n])<<8|uint16(sh[36+n]) == id
}

// tls13ClientHello is a TLS 1.3 ClientHello offering one suite, with what servers require to
// answer: supported_versions 1.3, an x25519 key share, groups and signature algorithms
// (including RSA-PSS, which TLS 1.3 signs RSA certificates with).
func tls13ClientHello(serverName string, suite uint16) []byte {
	var b []byte
	b = append(b, 0x03, 0x03) // legacy_version TLS 1.2
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	sid := make([]byte, 32) // a legacy session id, as browsers send in middlebox compatibility mode
	_, _ = rand.Read(sid)
	b = append(b, byte(len(sid)))
	b = append(b, sid...)
	b = append(b, uint16b(2)...)
	b = append(b, uint16b(int(suite))...)
	b = append(b, 0x01, 0x00) // compression: null

	share := make([]byte, 32)
	_, _ = rand.Read(share)
	keyShare := append(uint16b(0x001d), uint16b(len(share))...) // x25519
	keyShare = append(keyShare, share...)
	sigAlgs := []byte{
		0x08, 0x04, 0x08, 0x05, 0x08, 0x06, // rsa_pss_rsae_sha256/384/512
		0x04, 0x03, 0x05, 0x03, 0x06, 0x03, // ecdsa_secp256r1_sha256 …
		0x08, 0x07, 0x08, 0x08, // ed25519, ed448
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, // rsa_pkcs1 (for the certificate chain)
	}
	ext := sniExtension(serverName)
	ext = append(ext, supportedGroupsExtension()...)
	ext = append(ext, extension(0x000d, append(uint16b(len(sigAlgs)), sigAlgs...))...)
	ext = append(ext, extension(0x002b, []byte{0x02, 0x03, 0x04})...)                    // supported_versions: 1.3
	ext = append(ext, extension(0x0033, append(uint16b(len(keyShare)), keyShare...))...) // key_share
	ext = append(ext, extension(0x002d, []byte{0x01, 0x01})...)                          // psk_key_exchange_modes: psk_dhe_ke
	b = append(b, uint16b(len(ext))...)
	b = append(b, ext...)
	return handshakeMessage(1, b)
}
