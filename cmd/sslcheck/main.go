// Command sslcheck assesses the TLS of one host and prints the result as JSON. It is a thin
// demonstration of the sslcheck library.
//
//	go run ./cmd/sslcheck example.com
//	go run ./cmd/sslcheck example.com:443
//	go run ./cmd/sslcheck -ca-bundle /etc/ssl/cert.pem example.com
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/konlyk/sslcheck"
)

func main() {
	caBundle := flag.String("ca-bundle", "", "PEM file of trust anchors for the certificate verdict; empty uses the system roots (whose behaviour on a missing intermediate is platform-dependent)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-connection timeout")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sslcheck [-ca-bundle file] [-timeout d] <host[:port]>")
		os.Exit(2)
	}

	opts := sslcheck.Options{Timeout: *timeout}
	if *caBundle != "" {
		roots, err := loadRoots(*caBundle)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ca-bundle:", err)
			os.Exit(2)
		}
		opts.Roots = roots
	}

	host, port, err := net.SplitHostPort(flag.Arg(0))
	if err != nil {
		host, port = flag.Arg(0), "443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := sslcheck.Scan(ctx, host, net.JoinHostPort(host, port), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(a, "", "  ")
	fmt.Println(string(out))
}

// loadRoots reads a PEM bundle of certificates into a pool.
func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}
