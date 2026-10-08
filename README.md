# sslcheck

`sslcheck` assesses a host's TLS the way [testssl.sh](https://testssl.sh) does, but natively in
Go and in-process — it opens ordinary and crafted TLS connections to the host and reports the
protocols and ciphers it offers, its certificate chain, the known weaknesses it has, and an
[SSL Labs](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide) grade derived from
all of it. Nothing is shelled out: there is no `testssl.sh`, no bundled `openssl`, and so no
child processes to leak or clean up, and every probe honours the context deadline.

It is a clean-room reimplementation of the *checks* testssl performs, written from the TLS RFCs,
the published descriptions of each attack, and the SSL Labs rating guide. It contains no
testssl.sh source (testssl is GPLv2); `sslcheck` is Apache-2.0 and safe to embed in a proprietary
product.

## Install

```sh
go get github.com/konlyk/sslcheck
```

Requires Go 1.23+. The only dependency is [`zcrypto`](https://github.com/zmap/zcrypto), used for
the legacy-protocol and cipher probing that the standard library will not do.

## Library usage

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/konlyk/sslcheck"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// host is the name (used for SNI and certificate matching); addr carries the IP:port to
	// connect to, so the caller chooses which address is probed.
	a, err := sslcheck.Scan(ctx, "example.com", "example.com:443", sslcheck.Options{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("grade %s (score %d)\n", a.Grade, a.Score)
	for _, p := range a.Protocols {
		if p.Offered {
			fmt.Println("protocol:", p.Name)
		}
	}
	for _, v := range a.Vulns {
		fmt.Printf("vuln: %s [%s] %s\n", v.Name, v.Severity, v.CVE)
	}
	if len(a.Certificates) > 0 {
		c := a.Certificates[0]
		fmt.Printf("cert: %s trusted=%v expires=%s\n", c.CommonName, c.Trusted, c.Expires.Format("2006-01-02"))
	}
}
```

`addr` is separate from `host` on purpose: resolve the name yourself and pass the specific
address you want assessed. This lets a caller stay within an allow-list of IPs, skip private
addresses, or probe one address of a multi-homed host. `host` is still used for SNI and for the
certificate hostname check.

### Options

```go
type Options struct {
	Timeout         time.Duration  // per connection; 0 = 10s
	ServerName      string         // SNI; defaults to host
	Roots           *x509.CertPool // trust anchors for the certificate verdict; nil = the system roots
	CheckRevocation bool           // also ask the certificate's OCSP responder (a stapled response is always read)
	SkipHTTP        bool           // skip the HTTP request that reads HSTS and HPKP, for non-HTTP services
}
```

### The result

```go
type Assessment struct {
	Protocols     []Protocol    // every version tested, offered or not
	Ciphers       []Cipher      // the accepted ciphers, best protocol first
	Certificates  []Certificate // one per certificate type the host serves (RSA, ECDSA …)
	ForwardSecret bool          // every accepted key exchange is ephemeral

	Compression         bool         // the server agreed to TLS compression (CRIME)
	SecureRenegotiation *bool        // RFC 5746 secure renegotiation; nil when only TLS 1.3 is offered
	HTTP                *HTTPHeaders // what the HTTP answer says about TLS (HSTS, HPKP); nil when not fetched

	Grade               string   // A+ … F, or M (name mismatch) / T (untrusted)
	Score               int      // 0–100; 0 when the grade is F, T or M
	ProtocolScore       int      // category 1, protocol support
	KeyExchangeScore    int      // category 2, key exchange
	CipherStrengthScore int      // category 3, cipher strength
	Reasons             []string // the grade caps that were applied
	Warnings            []string // what keeps an A from an A+ (it is then A-)
}
```

`Protocol` carries `Name` (`"SSLv2"`, `"SSLv3"`, `"TLS1"`, `"TLS1_1"`, `"TLS1_2"`, `"TLS1_3"`),
`Offered` and `Deprecated`. `Cipher` carries the IANA `Name`, the `Version` it was accepted at, a
`Strength` (`StrengthStrong` / `StrengthWeak` / `StrengthInsecure`), `Bits` and `Forward`.
`Certificate` carries `CommonName`, `AltNames`, `Issuer`, `Trusted`, `NameMismatch`, `TrustReason`,
`ChainComplete`, `ChainIncomplete`, `ChainError`, `SelfSigned`, `FingerprintSHA256`, `KeyType`,
`KeyAlg`, `KeyBits`, `RSAExponent`, `SignatureAlg`, `SignatureHash`, `Expires` and an `Expired()`
method, `OCSPStapled`, `Revoked`, `RevocationSource`, and the parsed `Leaf`/`Chain`
(`*crypto/x509.Certificate`, excluded from the JSON). `Vuln` carries `Name`, `Severity`
(`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `CVE`, `CWE` and a `Remark`.

## What it checks

- **Protocols**: SSLv2 (by a raw hello), SSLv3, TLS 1.0, 1.1, 1.2 and 1.3.
- **Ciphers**: every suite the host accepts at each version, each classified strong / weak /
  insecure, with its key size and whether its key exchange is forward-secret.
- **Certificate**: one per certificate type the host serves (an RSA and an ECDSA certificate are
  described separately), each with its common name, SANs, issuer, key algorithm and size, signature
  algorithm and hash, SHA-256 fingerprint, expiry, chain completeness, OCSP stapling and revocation,
  and whether it is trusted and valid for the hostname. A failed chain is classified the way testssl
  reads OpenSSL's verify result, so a missing intermediate is reported as an incomplete chain rather
  than depending on the platform verifier fetching it.
- **Session features**: TLS compression (CRIME) and RFC 5746 secure renegotiation.
- **HTTP**: the HSTS and HPKP headers of the host's answer to `GET /` (skip with `Options.SkipHTTP`).
- **Grade**: the SSL Labs letter and score as testssl's `run_rating` computes them — three category
  scores (protocol support, key exchange, cipher strength) weighted 30/30/40, every `set_grade_cap`
  and `set_grade_warning` rule, and A+/A- awarded from the warning set.
- **Vulnerabilities derived from what is offered**: DROWN, FREAK, LOGJAM, SWEET32, RC4, BEAST,
  POODLE (SSL), LUCKY13, and NULL / anonymous ciphers.
- **Active probes**: Heartbleed, CCS injection, Ticketbleed and ROBOT. Each is conservative — an
  error, a timeout or an answer it does not recognise is reported as *not* vulnerable, so the
  scan never raises a false alarm. The probes are detection only; they do not run the attacks.

Deliberately out of scope (testssl features with no bearing on the assessment): text/CSV/HTML
reports, mass testing, STARTTLS for mail servers, and browser simulations.

## CLI

A small demonstration command prints the assessment as JSON:

```sh
go run ./cmd/sslcheck example.com
go run ./cmd/sslcheck example.com:443
```

## Notes

- A scan opens many short connections (one per cipher per protocol, plus the probes); the protocols,
  their cipher enumerations and the active probes run concurrently, so a run usually takes seconds to
  a minute depending on how much the host offers. Bound it with the context and `Options.Timeout`.
- This is not a TLS implementation and never decrypts or recovers anything; it reads a host's
  configuration and a few flaws from how the host answers crafted records.
- Grades follow testssl's `run_rating` rather than the guide's prose where the two differ, so a
  result can be checked against a current testssl; they can still differ slightly from another
  testssl version's own opinion.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Konstantinos Lykourentzos.
