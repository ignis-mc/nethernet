# Interoperability testing

`interop/run.sh` checks this implementation against
[go-nethernet](https://github.com/df-mc/go-nethernet), which is built on
pion's ICE, DTLS and SCTP. It needs Go and the Mojo toolchain:

```sh
pixi run -e interop interop        # everything
interop/run.sh -k http             # cases whose name contains "http"
interop/run.sh -v -k rejected      # print logs of passing cases too
```

## How it works

Two programs speak the same tiny echo protocol:

- `interop/go/` is a Go command with `listen`, `dial`, `http-listen` and
  `http-dial` modes built directly on go-nethernet.
- `examples/echo_server.mojo` and `examples/echo_client.mojo` are the Mojo
  equivalents.

A listener echoes every message on the channel it arrived on and closes the
connection when it receives `BYE`. A dialer sends deterministic payloads
(byte `i` of an `n`-byte message is `(7i + i/251 + n) mod 256`), checks each
echo byte for byte, optionally exchanges messages on the unreliable channel,
and then either closes or asks the listener to. Each case runs one listener
and one or three dialers on loopback and passes only if every process exits
cleanly.

## Cases

| Group | What varies |
|---|---|
| `mojo-to-go.*` | Mojo dials a go-nethernet listener over LAN discovery |
| `go-to-mojo.*` | go-nethernet dials a Mojo listener over LAN discovery |
| `mojo-to-mojo.*` | both ends Mojo |
| `*.http*` | the same over HTTP signaling, including Go's HTTP client and handler |
| `go-to-go.control` | both ends Go, to prove the harness itself |

Within each group: with identity assertions (the strict default on both
libraries), anonymous with the listener allowing it, anonymous rejected with
error 37, the listener closing first, a large write followed immediately by
close (which must still be delivered), and three dialers at once. Message
sizes include 1160 and 1161 bytes (pion's SCTP fragmentation boundary),
262143 and 262144 bytes (the NetherNet segment boundary) and 600000 bytes
(three segments).

## What the peer taught us

Behaviour that is not obvious from the RFCs and that this implementation
depends on:

- **pion never gathers loopback candidates** and drops packets from addresses
  it does not know. Bind the connection socket to the address you advertise;
  by default that is the address of the default route.
- **DTLS must negotiate `use_srtp`** even though no media flows; pion aborts
  otherwise.
- **SCTP must not advertise I-DATA** (chunk 64) in Supported Extensions, or
  pion aborts on plain DATA. FORWARD-TSN is negotiated by listing it there.
- **pion drops a whole SCTP packet that contains a chunk type it does not
  know**, including HEARTBEAT-ACK bundled with anything else.
- **Both ends send INIT.** A passive responder also works against pion, but
  two passive ends would deadlock.
- **Ordered streams must start at SSN 0** and count the DCEP message.
- **go-nethernet's dialer rejects an answer without `a=identity`** unless
  told otherwise, and its listener rejects an offer without one. The
  assertion's payload is rebuilt from the `a=fingerprint` line exactly as
  written, so the case of the hex digits is part of what is signed.
- **The HTTP client probes HTTPS before HTTP** within one time budget. A
  server that does not close a TLS ClientHello at once is never reached over
  plain HTTP.
- **A zero-length or one-byte data-channel message is fatal** on the Go
  side: every message carries the segment-count byte plus at least one byte.

## Real game clients

Checked by hand on 2026-11-13, on loopback:

- **Vanilla Minecraft 1.26.60** (Linux build under mcpelauncher; its
  transport is libwebrtc, not pion). It probes and joins a Mojo listener over
  HTTP signaling, shows the "Trust this server?" prompt for the Mojo identity
  assertion and, once trusted, opens both data channels and sends
  RequestNetworkSettings. Through `examples/relay.mojo` in front of a
  Dragonfly server it completes the whole join: login, resource pack
  negotiation, StartGame and chunks, and Dragonfly logs the player joining.
  The same client joining Dragonfly directly behaves the same in that world.
- **Cinnabar** (go-nethernet behind gophertunnel) joins a Mojo listener the
  same way and sends its first game packet after the trust prompt.

Two things to know when testing with a real client:

- The client starts ICE only after the trust prompt is accepted. A prompt
  left open longer than the listener's negotiation timeout fails the join
  ("Door"); go-nethernet's listener behaves the same.
- A Bedrock server compares the NetherNet identity key with the login's key,
  so a relay must dial upstream anonymously and the server must allow it.

## Loss on the wire

`interop/go` has a `lossy-proxy` command (see `interop/README.md`) that puts
real datagram loss between pion and the Mojo stack. With about 1 MB of echoes
per connection: at 5% loss each way the Mojo side recovers without T3-rtx
expiries, and at 10% it takes 3-34 s, against 18-28 s for go-nethernet with
itself through the same relay. At 20% every pair, go-nethernet with itself
included, stalls past the 170 s limit.

## Not covered

- The vanilla dedicated server (BDS) as a peer.
- Reordering and delay end to end; loss only through `lossy-proxy`.
- Xbox Live signaling, STUN/TURN, IPv6.
