// Command interop is the go-nethernet side of the interoperability tests.
//
// It speaks NetherNet over LAN discovery signaling on loopback, as either an
// echo listener or a dialer that checks echoes, so that the Mojo
// implementation can be exercised against pion and go-nethernet in both
// roles. See interop/README.md.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
	"github.com/df-mc/go-nethernet/endpoint"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: interop <listen|dial|http-listen|http-dial> [flags]")
	}
	switch os.Args[1] {
	case "listen":
		listen(os.Args[2:])
	case "dial":
		dial(os.Args[2:])
	case "http-listen":
		httpListen(os.Args[2:])
	case "http-dial":
		httpDial(os.Args[2:])
	default:
		fatalf("unknown command %q", os.Args[1])
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop: "+format+"\n", args...)
	os.Exit(1)
}

func logger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// payload returns the deterministic test message of the given size. The Mojo
// side generates the same bytes.
func payload(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*7 + i/251 + size) & 0xff)
	}
	return b
}

func parseSizes(s string) []int {
	var sizes []int
	for _, field := range strings.Split(s, ",") {
		if field == "" {
			continue
		}
		n, err := strconv.Atoi(field)
		if err != nil || n <= 0 {
			fatalf("invalid size %q", field)
		}
		sizes = append(sizes, n)
	}
	return sizes
}

// listen runs an echo listener: every message received on either channel is
// sent back on the same channel.
func listen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	bind := fs.String("bind", "127.0.0.1:7551", "discovery address to bind (the port must be explicit)")
	networkID := fs.Uint64("network-id", 0, "network ID (0 picks a random one)")
	anonymous := fs.Bool("anonymous", false, "accept offers without an identity")
	conns := fs.Int("conns", 1, "exit after this many connections have closed")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time limit")
	verbose := fs.Bool("v", false, "debug logging")
	_ = fs.Parse(args)

	log := logger(*verbose)
	d, err := discovery.ListenConfig{NetworkID: *networkID, Log: log}.Listen(*bind)
	if err != nil {
		fatalf("discovery listen: %v", err)
	}
	defer d.Close()
	d.ServerData(&discovery.ServerData{
		ServerName:            "go-nethernet interop",
		LevelName:             "interop",
		MaxPlayerCount:        8,
		AcceptsOnlineAuth:     true,
		AcceptsSelfSignedAuth: true,
		ConnectionType:        4,
	})
	l, err := nethernet.ListenConfig{Log: log, AllowAnonymous: *anonymous}.Listen(d)
	if err != nil {
		fatalf("nethernet listen: %v", err)
	}
	defer l.Close()

	_, port, err := net.SplitHostPort(*bind)
	if err != nil || port == "0" {
		fatalf("listen: -bind needs an explicit port")
	}
	fmt.Printf("READY %s %s\n", port, d.NetworkID())

	time.AfterFunc(*timeout, func() { fatalf("listen: timed out") })

	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		c, err := l.Accept()
		if err != nil {
			fatalf("accept: %v", err)
		}
		conn := c.(*nethernet.Conn)
		fmt.Printf("ACCEPTED %s\n", conn.RemoteAddr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			echo(conn)
			fmt.Println("CLOSED")
		}()
	}
	wg.Wait()
	fmt.Println("DONE")
}

func echo(conn *nethernet.Conn) {
	go func() {
		for {
			b, err := conn.Receive(nethernet.MessageReliabilityUnreliable)
			if err != nil {
				return
			}
			if _, err := conn.Send(b, nethernet.MessageReliabilityUnreliable); err != nil {
				return
			}
		}
	}()
	for {
		b, err := conn.ReadPacket()
		if err != nil {
			return
		}
		if bytes.Equal(b, []byte("BYE")) {
			_ = conn.Close()
			return
		}
		if _, err := conn.Write(b); err != nil {
			return
		}
	}
}

// dial finds a listener through discovery, connects, and checks that every
// message it sends comes back unchanged.
func dial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	target := fs.String("target", "", "discovery address of the listener (host:port)")
	sizes := fs.String("sizes", "1,2,100,1000", "comma-separated reliable message sizes")
	unreliable := fs.Int("unreliable", 0, "number of unreliable messages to exchange")
	identityless := fs.Bool("identityless", false, "accept answers without an identity")
	withIdentity := fs.Bool("identity", false, "attach a self-signed client identity to the offer")
	expectFail := fs.Bool("expect-fail", false, "succeed only if the dial is rejected")
	bye := fs.Bool("bye", false, "ask the listener to close instead of closing first")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time limit")
	verbose := fs.Bool("v", false, "debug logging")
	_ = fs.Parse(args)

	addr, err := net.ResolveUDPAddr("udp4", *target)
	if err != nil {
		fatalf("resolve target: %v", err)
	}
	log := logger(*verbose)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	time.AfterFunc(*timeout, func() { fatalf("dial: timed out") })

	d, err := discovery.ListenConfig{BroadcastAddress: addr, Log: log}.Listen("127.0.0.1:0")
	if err != nil {
		fatalf("discovery listen: %v", err)
	}
	defer d.Close()

	var networkID uint64
	found := false
	for !found {
		for id, response := range d.Responses() {
			var data discovery.ServerData
			if err := data.UnmarshalBinary(response); err != nil {
				fatalf("decode server data: %v", err)
			}
			fmt.Printf("FOUND %d %q %q\n", id, data.ServerName, data.LevelName)
			networkID, found = id, true
			break
		}
		if !found {
			select {
			case <-ctx.Done():
				fatalf("no listener answered discovery")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	dialer := nethernet.Dialer{Log: log, AllowIdentitylessServer: *identityless}
	if *withIdentity {
		dialer.Identity = newIdentity()
	}
	conn, err := dialer.DialContext(ctx, strconv.FormatUint(networkID, 10), d)
	if *expectFail {
		if err == nil {
			fatalf("dial succeeded but was expected to fail")
		}
		fmt.Printf("FAILED_AS_EXPECTED %v\n", err)
		fmt.Println("OK")
		return
	}
	if err != nil {
		fatalf("dial: %v", err)
	}
	exercise(conn, parseSizes(*sizes), *unreliable, *bye)
}

// exercise checks echoes on an open connection and then closes it.
func exercise(conn *nethernet.Conn, sizes []int, unreliable int, bye bool) {
	fmt.Printf("CONNECTED %s\n", conn.RemoteAddr())

	for _, size := range sizes {
		want := payload(size)
		if _, err := conn.Write(want); err != nil {
			fatalf("write %d bytes: %v", size, err)
		}
		got, err := conn.ReadPacket()
		if err != nil {
			fatalf("read echo of %d bytes: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			fatalf("echo of %d bytes differs (got %d bytes)", size, len(got))
		}
		fmt.Printf("ECHO %d\n", size)
	}

	if unreliable > 0 {
		received := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			for received < unreliable {
				b, err := conn.Receive(nethernet.MessageReliabilityUnreliable)
				if err != nil {
					return
				}
				if len(b) != 32 {
					fatalf("unreliable echo has %d bytes", len(b))
				}
				received++
			}
		}()
		for i := 0; i < unreliable; i++ {
			if _, err := conn.Send(payload(32), nethernet.MessageReliabilityUnreliable); err != nil {
				fatalf("unreliable send: %v", err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		// Loopback does not lose packets, so anything missing is a bug.
		if received != unreliable {
			fatalf("unreliable: received %d of %d", received, unreliable)
		}
		fmt.Printf("UNRELIABLE %d\n", received)
	}

	if bye {
		if _, err := conn.Write([]byte("BYE")); err != nil {
			fatalf("write BYE: %v", err)
		}
		if _, err := conn.ReadPacket(); err == nil {
			fatalf("expected the listener to close the connection")
		} else if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			fmt.Printf("CLOSED_BY_PEER %v\n", err)
		} else {
			fmt.Println("CLOSED_BY_PEER")
		}
	} else {
		if err := conn.Close(); err != nil {
			fatalf("close: %v", err)
		}
	}
	fmt.Println("OK")
}

// newIdentity returns a fresh self-signed client identity.
func newIdentity() *nethernet.Identity {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fatalf("generate identity key: %v", err)
	}
	identity, err := nethernet.SelfSignedIdentity(key, "https://authorization.franchise.minecraft-services.net/")
	if err != nil {
		fatalf("create identity: %v", err)
	}
	return identity
}

// httpListen runs the echo listener behind go-nethernet's HTTP signaling
// handler.
func httpListen(args []string) {
	fs := flag.NewFlagSet("http-listen", flag.ExitOnError)
	bind := fs.String("bind", "127.0.0.1:19132", "HTTP address to bind (the port must be explicit)")
	anonymous := fs.Bool("anonymous", false, "accept offers without an identity")
	conns := fs.Int("conns", 1, "exit after this many connections have closed")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time limit")
	verbose := fs.Bool("v", false, "debug logging")
	_ = fs.Parse(args)

	log := logger(*verbose)
	handler := endpoint.HandlerConfig{Logger: log}.New()
	l, err := nethernet.ListenConfig{Log: log, AllowAnonymous: *anonymous, DisableTrickleICE: true}.Listen(handler)
	if err != nil {
		fatalf("nethernet listen: %v", err)
	}
	defer l.Close()
	tcp, err := net.Listen("tcp", *bind)
	if err != nil {
		fatalf("tcp listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(tcp) }()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(*bind)
	fmt.Printf("READY %s %s\n", port, handler.NetworkID())

	time.AfterFunc(*timeout, func() { fatalf("http-listen: timed out") })
	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		c, err := l.Accept()
		if err != nil {
			fatalf("accept: %v", err)
		}
		conn := c.(*nethernet.Conn)
		fmt.Printf("ACCEPTED %s\n", conn.RemoteAddr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			echo(conn)
			fmt.Println("CLOSED")
		}()
	}
	wg.Wait()
	fmt.Println("DONE")
}

// httpDial connects through HTTP signaling, the way gophertunnel joins a
// server by address: probe first, then post the offer.
func httpDial(args []string) {
	fs := flag.NewFlagSet("http-dial", flag.ExitOnError)
	url := fs.String("url", "", "base URL of the server, for example http://127.0.0.1:19132")
	sizes := fs.String("sizes", "1,2,100,1000", "comma-separated reliable message sizes")
	unreliable := fs.Int("unreliable", 0, "number of unreliable messages to exchange")
	identityless := fs.Bool("identityless", false, "accept answers without an identity")
	withIdentity := fs.Bool("identity", false, "attach a self-signed client identity to the offer")
	expectFail := fs.Bool("expect-fail", false, "succeed only if the dial is rejected")
	bye := fs.Bool("bye", false, "ask the listener to close instead of closing first")
	timeout := fs.Duration("timeout", 60*time.Second, "overall time limit")
	verbose := fs.Bool("v", false, "debug logging")
	_ = fs.Parse(args)

	log := logger(*verbose)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	time.AfterFunc(*timeout, func() { fatalf("http-dial: timed out") })

	// The probe gophertunnel sends before joining.
	resp, err := http.Get(*url + "/v1/join")
	if err != nil {
		fatalf("probe: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fatalf("probe: status %d", resp.StatusCode)
	}
	fmt.Printf("STATUS %s\n", body)

	client := endpoint.ClientConfig{Logger: log}.New()
	dialer := nethernet.Dialer{Log: log, AllowIdentitylessServer: *identityless, DisableTrickleICE: true}
	if *withIdentity {
		dialer.Identity = newIdentity()
	}
	conn, err := dialer.DialContext(ctx, *url, client)
	if *expectFail {
		if err == nil {
			fatalf("dial succeeded but was expected to fail")
		}
		fmt.Printf("FAILED_AS_EXPECTED %v\n", err)
		fmt.Println("OK")
		return
	}
	if err != nil {
		fatalf("dial: %v", err)
	}
	exercise(conn, parseSizes(*sizes), *unreliable, *bye)
}
