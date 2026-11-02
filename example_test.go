package portsscanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// The example is placed in an internal package so that it doesn't depend on the module path:
// // you won't need to make any changes after running `go mod edit -module`.
func Example() {
	// The local server makes the example output deterministic.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	scanner, err := New(
		WithConcurrency(50),
		WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Println("new:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Port(port))
	if err != nil {
		fmt.Println("scan:", err)
		return
	}
	for r := range results {
		fmt.Println(r.Host, r.State)
	}
	// Output: 127.0.0.1 open
}
