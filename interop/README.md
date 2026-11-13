# Interop harness

`run.sh` builds the Go command in `go/` and the Mojo echo examples, then runs
every listener/dialer combination on loopback. See
[docs/interop.md](../docs/interop.md) for what the cases cover.

```sh
pixi run -e interop interop
```

The Go side by hand:

```sh
cd interop/go && go build -o bin/interop .
bin/interop listen -bind 127.0.0.1:7551            # echo listener, LAN discovery
bin/interop dial -target 127.0.0.1:7551 -identity  # dialer that checks echoes
bin/interop http-listen -bind 127.0.0.1:19132      # echo listener, HTTP signaling
bin/interop http-dial -url http://127.0.0.1:19132 -identity
```

## Packet loss

`lossy-proxy` sits between an HTTP-signaling dialer and listener. It rewrites
the candidates in the offer and the answer so that all ICE, DTLS and SCTP
traffic goes through a UDP relay, and drops a share of the datagrams in each
direction (`-burst` makes a drop more likely right after another one):

```sh
bin/interop http-listen -bind 127.0.0.1:19132
bin/interop lossy-proxy -upstream http://127.0.0.1:19132 -loss 0.05 -seed 1   # prints READY <port>
bin/interop http-dial -url http://127.0.0.1:<port> -identity -sizes 1,70000,600000
```

The Mojo examples take `--stats` to print their SCTP retransmission counters.

