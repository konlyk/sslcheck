package sslcheck

import (
	"context"
	cryptotls "crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
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
// the headers of the first answer are what a browser would pin or remember.
func fetchHTTPHeaders(ctx context.Context, host, addr string, opts Options) *HTTPHeaders {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: opts.timeout()}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:   &cryptotls.Config{ServerName: opts.ServerName, InsecureSkipVerify: true}, //nolint:gosec // reading headers, not trusting
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       opts.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sslcheck)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
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
	return h
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
