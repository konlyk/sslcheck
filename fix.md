# Review findings for the v0.3.0 candidate

Review of the five commits after `v0.2.0` (cipher order, certificate details, connection facts,
BREACH and fallback SCSV). Validation: 30-host live run, grades/protocols/ciphers/reasons identical
to `dd44b89`, `Incomplete` empty everywhere. The defects below are in the new checks only.

Status: `[ ]` open, `[x]` fixed (commit noted).

## Must fix before release

- [x] **1. `SessionTicket` can never be true.** (fixed below) zcrypto's client sends the session-ticket extension
  only when `ForceSessionTicketExt` is set or a session cache is configured; `scanConnection` sets
  neither, so no server answers with it. All 30 hosts report `false`.
  Fix: set `ForceSessionTicketExt` on that handshake.
- [ ] **2. Cipher order lacks testssl's ChaCha exception.** BoringSSL-style servers (Cloudflare,
  Google) keep a server order but honour the client's ChaCha20 preference within an
  equal-preference group; testssl reports that as "server order, prioritises ChaCha when preferred
  by clients" (OK). We see the reversed pick land on ChaCha, call it "no order", and raise
  `NO_CIPHER_ORDER` on cloudflare.com, example.com and www.google.com.
  Fix: when the two picks differ and the reversed pick is a ChaCha suite, compare again with the
  ChaCha suites removed; if that is consistent, it is an order.
- [ ] **3. Fallback SCSV reports any non-answer as "not honoured".** Everything that is not an
  inappropriate_fallback alert, including a timeout, a reset or an unrelated alert, is read as the
  server failing the check; rsa4096 and rsa8192 got a false `FALLBACK_SCSV/LOW`.
  Fix: only a ServerHello proves it is not honoured; anything else leaves the result `nil`.
- [ ] **4. Well-known-DH-group severity is wrong both ways.** testssl's `out_common_prime` grades a
  known prime harsher than an unknown one at or under 1024 bits (HIGH; CRITICAL at or under 800),
  LOW for 1025–1536, informational above that and for RFC 7919 groups. We emit MEDIUM for the known
  1024-bit nginx prime and would emit LOW for RFC 3526 group 14 / ffdhe2048, which is good practice.
  Fix: apply testssl's ladder for known primes; keep the unknown-prime ladder as is.

## Should fix

- [ ] **5. Intermediate expiry one notch too severe.** testssl: expired CRITICAL, within 20 days
  HIGH, within 40 days MEDIUM. We use CRITICAL/HIGH for 20/40.
- [ ] **6. Certificate findings cover only the first certificate.** A dual-certificate host's second
  certificate is never checked for validity length or chain issues.
- [ ] **7. Validity compared in whole days.** 398 days plus a few hours escapes the post-2020 rule
  that testssl applies by the second. Compare the duration, not the truncated day count.
- [ ] **8. `scanVulns` writes `DHBits`/`DHGroup` into the assessment it was handed** instead of
  returning them; harmless (distinct fields) but against the pattern every other step follows.

## Limitations to surface or accept

- [ ] **9. Protocols without a cipher order are computed but discarded.** Surface them so a
  `CipherOrder: false` is actionable.
- [ ] **10. ALPN unread on legacy-suite-only hosts.** It is read through crypto/tls; read it from the
  zcrypto handshake as well so 3DES/RC4-only hosts report it.
- [ ] 11. Curve and ticket are read from a legacy handshake, so TLS 1.3-only hosts show neither.
  Accepted for now (zcrypto has no TLS 1.3); noted in the field docs.
- [ ] 12. BREACH fires on 27 of 30 hosts because nearly everyone gzips. Matches testssl's
  "potentially vulnerable" at MEDIUM. Decision: keep parity; revisit if it swamps reports.
