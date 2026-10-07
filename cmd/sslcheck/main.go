// Command sslcheck assesses the TLS of one host and prints the result as JSON. It is a thin
// demonstration of the sslcheck library.
//
//	go run ./cmd/sslcheck example.com
//	go run ./cmd/sslcheck example.com:443
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/konlyk/sslcheck"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sslcheck <host[:port]>")
		os.Exit(2)
	}
	host, port, err := net.SplitHostPort(os.Args[1])
	if err != nil {
		host, port = os.Args[1], "443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := sslcheck.Scan(ctx, host, net.JoinHostPort(host, port), sslcheck.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(a, "", "  ")
	fmt.Println(string(out))
}
