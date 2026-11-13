package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// lossyProxy sits between an HTTP-signaling dialer and listener and puts
// packet loss on the media path.
//
// It forwards `/v1/join` requests to the upstream listener and rewrites the
// candidates in the offer and the answer so that both peers send their ICE,
// DTLS and SCTP datagrams through a pair of relay sockets. The relay drops a
// share of the datagrams in each direction. The identity assertion signs only
// the fingerprints, so rewriting candidates keeps it valid.
func lossyProxy(args []string) {
	fs := flag.NewFlagSet("lossy-proxy", flag.ExitOnError)
	bind := fs.String("bind", "127.0.0.1:0", "HTTP address to listen on")
	upstream := fs.String("upstream", "", "base URL of the real listener, for example http://127.0.0.1:19132")
	loss := fs.Float64("loss", 0.05, "probability that a datagram is dropped")
	burst := fs.Float64("burst", 0, "probability that the datagram after a dropped one is dropped too")
	seed := fs.Int64("seed", 1, "random seed for the drop pattern")
	relayIP := fs.String("relay-ip", "", "address of the relay sockets (default: the default-route address)")
	_ = fs.Parse(args)
	if *upstream == "" {
		fatalf("lossy-proxy: -upstream is required")
	}
	ip := *relayIP
	if ip == "" {
		ip = defaultRouteIP()
	}

	p := &proxy{
		upstream: strings.TrimSuffix(*upstream, "/"),
		relayIP:  net.ParseIP(ip),
		drop:     newDropper(*loss, *burst, *seed),
	}
	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		fatalf("lossy-proxy: %v", err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		p.printStats()
		os.Exit(0)
	}()
	fmt.Printf("READY %d\n", ln.Addr().(*net.TCPAddr).Port)
	_ = http.Serve(ln, p)
}

func defaultRouteIP() string {
	// Connecting a UDP socket sends nothing; it only selects the route.
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

type proxy struct {
	upstream string
	relayIP  net.IP
	drop     *dropper
	toLis    counters // dialer -> listener
	toDial   counters // listener -> dialer
}

type counters struct{ sent, dropped atomic.Int64 }

func (p *proxy) printStats() {
	fmt.Printf("STATS to-listener sent=%d dropped=%d to-dialer sent=%d dropped=%d\n",
		p.toLis.sent.Load(), p.toLis.dropped.Load(), p.toDial.sent.Load(), p.toDial.dropped.Load())
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	join := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/join/")

	var relay *relayPair
	if join {
		dialerAddr, ok := firstCandidate(string(body))
		if !ok {
			http.Error(w, "offer has no IPv4 UDP candidate", http.StatusBadRequest)
			return
		}
		var err error
		relay, err = p.newRelay(dialerAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The listener sees the dialer at the relay's listener-facing socket.
		body = []byte(rewriteCandidates(string(body), relay.toListener.LocalAddr().(*net.UDPAddr)))
	}

	req, _ := http.NewRequest(r.Method, p.upstream+r.URL.RequestURI(), bytes.NewReader(body))
	req.Header = r.Header.Clone()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if relay != nil {
			relay.close()
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	answer, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if relay != nil {
		listenerAddr, ok := firstCandidate(string(answer))
		if resp.StatusCode/100 != 2 || !ok {
			relay.close()
		} else {
			relay.start(listenerAddr)
			// The dialer sees the listener at the relay's dialer-facing socket.
			answer = []byte(rewriteCandidates(string(answer), relay.toDialer.LocalAddr().(*net.UDPAddr)))
		}
	}
	for k, v := range resp.Header {
		if k != "Content-Length" {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(answer)
}

// relayPair forwards datagrams between one dialer and one listener.
// The dialer talks to toDialer; the listener talks to toListener.
type relayPair struct {
	p          *proxy
	toDialer   *net.UDPConn
	toListener *net.UDPConn
	dialer     *net.UDPAddr
	once       sync.Once
}

func (p *proxy) newRelay(dialer *net.UDPAddr) (*relayPair, error) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: p.relayIP})
	if err != nil {
		return nil, err
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: p.relayIP})
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return &relayPair{p: p, toDialer: a, toListener: b, dialer: dialer}, nil
}

func (r *relayPair) start(listener *net.UDPAddr) {
	go r.pump(r.toDialer, r.toListener, listener, &r.p.toLis)
	go r.pump(r.toListener, r.toDialer, r.dialer, &r.p.toDial)
	// Connections in the tests last well under this.
	time.AfterFunc(5*time.Minute, r.close)
}

func (r *relayPair) pump(from, out *net.UDPConn, to *net.UDPAddr, c *counters) {
	buf := make([]byte, 65536)
	for {
		n, _, err := from.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if r.p.drop.next() {
			c.dropped.Add(1)
			continue
		}
		c.sent.Add(1)
		_, _ = out.WriteToUDP(buf[:n], to)
	}
}

func (r *relayPair) close() {
	r.once.Do(func() {
		_ = r.toDialer.Close()
		_ = r.toListener.Close()
	})
}

// dropper decides which datagrams are lost: independently with probability
// loss, or with probability burst right after a loss (a two-state model).
type dropper struct {
	mu          sync.Mutex
	rng         *rand.Rand
	loss, burst float64
	last        bool
}

func newDropper(loss, burst float64, seed int64) *dropper {
	return &dropper{rng: rand.New(rand.NewSource(seed)), loss: loss, burst: burst}
}

func (d *dropper) next() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.loss
	if d.last && d.burst > 0 {
		p = d.burst
	}
	d.last = d.rng.Float64() < p
	return d.last
}

// candidateFields splits an `a=candidate:` line into its fields, or returns
// nil for other lines.
func candidateFields(line string) []string {
	rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "a=candidate:")
	if !ok {
		return nil
	}
	f := strings.Fields(rest)
	if len(f) < 8 || !strings.EqualFold(f[2], "udp") || net.ParseIP(f[4]).To4() == nil {
		return nil
	}
	return f
}

func firstCandidate(sdp string) (*net.UDPAddr, bool) {
	for _, line := range strings.Split(sdp, "\n") {
		if f := candidateFields(line); f != nil {
			port, err := strconv.Atoi(f[5])
			if err == nil {
				return &net.UDPAddr{IP: net.ParseIP(f[4]), Port: port}, true
			}
		}
	}
	return nil, false
}

// rewriteCandidates keeps the first IPv4 UDP candidate, pointed at addr, and
// drops the rest. The m= port and c= address follow, as go-nethernet writes
// them from the default candidate.
func rewriteCandidates(sdp string, addr *net.UDPAddr) string {
	lines := strings.Split(sdp, "\n")
	out := make([]string, 0, len(lines))
	kept := false
	for _, line := range lines {
		cr := strings.HasSuffix(line, "\r")
		end := ""
		if cr {
			end = "\r"
		}
		trimmed := strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(trimmed, "a=candidate:"):
			f := candidateFields(trimmed)
			if f == nil || kept {
				continue
			}
			kept = true
			f[4], f[5] = addr.IP.String(), strconv.Itoa(addr.Port)
			out = append(out, "a=candidate:"+strings.Join(f, " ")+end)
		case strings.HasPrefix(trimmed, "m=application "):
			f := strings.Fields(trimmed)
			f[1] = strconv.Itoa(addr.Port)
			out = append(out, strings.Join(f, " ")+end)
		case strings.HasPrefix(trimmed, "c=IN IP4 "):
			out = append(out, "c=IN IP4 "+addr.IP.String()+end)
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
