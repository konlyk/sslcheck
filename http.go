package sslcheck

import (
	"context"
	cryptotls "crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// HTTPHeaders is what the server's answer to GET / says about its TLS: HSTS and HPKP, the two
// headers the rating looks at.
type HTTPHeaders struct {
	Status         int
	HSTS           string   // the first Strict-Transport-Security value; "" when absent
	HPKP           []string // every Public-Key-Pins value
	HPKPReportOnly []string // every Public-Key-Pins-Report-Only value
}

// fetchHTTPHeaders asks the host for / over TLS, at addr with SNI, without following redirects:
// the headers of the first answer are what a browser would pin or remember. The error says why
// there is no answer; a transport failure is retried once first. When crypto/tls has no suite in
// common with the host (one that offers only 3DES, RC4, DHE or the like), the request is made
// again over zcrypto with the suites the host was seen to accept, as testssl reads the headers
// through openssl.
func fetchHTTPHeaders(ctx context.Context, host, addr string, legacySuites []uint16, opts Options) (*HTTPHeaders, error) {
	h, err := fetchHTTPHeadersOnce(ctx, host, addr, nil, opts)
	if err != nil && isTransportFailure(err) && sleepCtx(ctx, retryBackoff) {
		h, err = fetchHTTPHeadersOnce(ctx, host, addr, nil, opts)
	}
	if err != nil && !isTransportFailure(err) && len(legacySuites) > 0 {
		h, err = fetchHTTPHeadersOnce(ctx, host, addr, legacySuites, opts)
	}
	return h, err
}

// fetchHTTPHeadersOnce makes one request, over crypto/tls, or over zcrypto offering legacySuites
// when they are given.
func fetchHTTPHeadersOnce(ctx context.Context, host, addr string, legacySuites []uint16, opts Options) (*HTTPHeaders, error) {
	// Every connection goes to the chosen address, under the connection cap, with its deadline
	// started once it exists, so time spent waiting for a slot does not eat the request's time.
	dialTCP := func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx, addr, opts)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(opts.timeout()))
		return c, nil
	}
	tr := &http.Transport{DisableKeepAlives: true}
	if legacySuites == nil {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dialTCP(ctx) }
		// TLS 1.0 as the floor: a host that offers nothing newer still has HSTS to read.
		tr.TLSClientConfig = &cryptotls.Config{ServerName: opts.ServerName, InsecureSkipVerify: true, MinVersion: cryptotls.VersionTLS10} //nolint:gosec // reading headers, not trusting
	} else {
		tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := dialTCP(ctx)
			if err != nil {
				return nil, err
			}
			tc := ztls.Client(c, &ztls.Config{
				ServerName: opts.ServerName, InsecureSkipVerify: true,
				MinVersion: ztls.VersionSSL30, MaxVersion: ztls.VersionTLS12,
				CipherSuites: legacySuites, ForceSuites: true,
			})
			if err := tc.Handshake(); err != nil {
				_ = tc.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr, // the per-connection deadline above bounds the request; no whole-request timeout
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sslcheck)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	h := &HTTPHeaders{
		Status:         resp.StatusCode,
		HPKP:           resp.Header.Values("Public-Key-Pins"),
		HPKPReportOnly: resp.Header.Values("Public-Key-Pins-Report-Only"),
	}
	if v := resp.Header.Values("Strict-Transport-Security"); len(v) > 0 {
		h.HSTS = v[0]
	}
	return h, nil
}

// hstsMinAge is testssl's threshold for a long enough HSTS max-age: 180 days.
const hstsMinAge = 180 * 86400

// hstsWarning is the rating warning an HSTS header earns, as testssl reads it: the value after
// the first "=" up to the first ";", quotes stripped, must be a number of seconds, not 0, and at
// least 180 days. No header at all is no warning.
func hstsWarning(value string) string {
	if value == "" {
		return ""
	}
	age := value
	if i := strings.IndexByte(age, '='); i >= 0 {
		age = age[i+1:]
	}
	if i := strings.IndexByte(age, ';'); i >= 0 {
		age = age[:i]
	}
	age = strings.Trim(strings.TrimSpace(age), `"`)
	n, err := strconv.ParseInt(age, 10, 64)
	switch {
	case err != nil || n < 0:
		return "HSTS max-age is misconfigured"
	case n == 0:
		return "HSTS is disabled"
	case n < hstsMinAge:
		return "HSTS max-age is too short"
	}
	return ""
}
