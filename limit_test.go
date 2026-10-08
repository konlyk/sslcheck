package sslcheck

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// With a connection cap, no more than that many connections from dial are held at once, and every
// slot is given back when its connection closes. The count is taken on the client side, between
// a successful dial and the Close that releases its slot, which is exactly what the cap bounds.
func TestDialHonoursConnectionCap(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) {
		_, _ = c.Read(make([]byte, 1)) // hold the connection until the client closes it
	})
	opts := Options{Timeout: 2 * time.Second, MaxConnections: 2}
	opts.limiter = make(chan struct{}, opts.maxConnections())

	var held, peak atomic.Int32
	errs := make(chan error, 6)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dial(context.Background(), addr, opts)
			if err != nil {
				errs <- err
				return
			}
			n := held.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(50 * time.Millisecond)
			held.Add(-1)
			_ = c.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.LessOrEqual(t, peak.Load(), int32(2), "connections held at once")
	require.Empty(t, opts.limiter, "every slot was released")
}

// Without a limiter (internal calls outside Scan) dial just dials.
func TestDialWithoutLimiter(t *testing.T) {
	addr := scriptedServer(t, func(_ int, c net.Conn) { _, _ = readClientHello(c) })
	c, err := dial(context.Background(), addr, Options{Timeout: time.Second})
	require.NoError(t, err)
	_ = c.Close()
}
