# nethernet

NetherNet, the WebRTC data-channel transport of Minecraft: Bedrock Edition,
implemented in pure [Mojo](https://mojolang.org).

There is no C, no libc call and no Python in this library. Sockets, clocks
and randomness come straight from Linux system calls; ICE, DTLS, SCTP, the
cryptography under them and the NetherNet signaling on top are all written in
Mojo.

```text
            your code
               │  Conn.send / Conn.receive
┌──────────────┴───────────────────────────────────────┐
│ conn, dialer, listener      segments, two channels   │
│ datachannel (DCEP)          sdp        signaling     │
│ sctp      reliable + unreliable streams      discovery (LAN, UDP 7551)
│ dtls      DTLS 1.2, ECDHE-ECDSA-AES128-GCM   endpoint  (HTTP /v1/join)
│ ice/stun  connectivity checks, keepalives    identity  (ES384 assertion)
│ crypto    SHA-1/2, HMAC, AES-GCM, P-256, P-384, X.509
│ os        raw Linux syscalls: UDP, TCP, poll, clock, getrandom
└───────────────────────────────────────────────────────┘
```

## Status

The whole stack works and interoperates with
[go-nethernet](https://github.com/df-mc/go-nethernet) (pion) in both
directions: `interop/run.sh` runs 24 dial/listen combinations over LAN
discovery signaling and HTTP signaling, with identity assertions, messages
from 1 byte to 600 kB, the unreliable channel, and closes from either side.

It also works with real game clients. The vanilla Minecraft client 1.26.60 (libwebrtc) joins a Mojo listener over HTTP signaling, accepts its identity assertion and reaches the world through `examples/relay.mojo`; the Cinnabar client (go-nethernet) does the same. See [docs/interop.md](docs/interop.md#real-game-clients).

| Area | State |
|---|---|
| Dial and listen, reliable and unreliable channels, message segmentation | Done |
| LAN discovery and signaling (UDP 7551, `ServerData` v7) | Done |
| HTTP signaling (`GET`/`POST /v1/join`), plain HTTP | Done |
| Identity assertion (`a=identity`, ES384, self-signed tokens) | Done |
| ICE | One host candidate per connection, IPv4, both roles |
| DTLS 1.2 | Client and server, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, P-256 |
| SCTP | RFC 9260 subset, PR-SCTP (FORWARD-TSN), stream reset |
| Xbox Live / PlayFab signaling (WebSocket over TLS) | Not implemented |
| STUN/TURN candidate gathering, IPv6, TCP candidates | Not implemented |
| Platforms | Linux x86-64 (tested) and aarch64 (written, not yet run) |

## Requirements

- Linux on x86-64 or aarch64.
- Mojo 1.2.x. The repository pins it with [pixi](https://pixi.sh):

```sh
curl -fsSL https://pixi.sh/install.sh | sh
pixi install
```

## Try it

Two terminals on one machine:

```sh
pixi run examples
build/echo_server --bind 127.0.0.1:7551
build/echo_client --target 127.0.0.1:7551 --sizes 1,1000,300000
```

The client finds the server through discovery, opens a connection, and checks
that every message it sends comes back unchanged. Add `--http 127.0.0.1:19132`
to both to use HTTP signaling instead.

## Use it

The library is single-threaded and never blocks unless asked to. A listener:

```mojo
from nethernet.discovery.listener import DiscoveryListener
from nethernet.discovery.server_data import ServerData
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr


def main() raises:
    var discovery = DiscoveryListener(SocketAddr.parse("0.0.0.0:7551"))
    var data = ServerData()
    data.server_name = "My server"
    data.level_name = "world"
    discovery.set_server_data(data)

    var listener = Listener[DiscoveryListener](discovery^, ListenConfig())
    while True:
        var accepted = listener.accept(-1)
        if accepted is None:
            continue
        var conn = accepted.take()
        var message = conn.read(-1)          # one whole message
        conn.write(Span(message))            # send it back
        conn.close()
```

A dialer:

```mojo
from nethernet.dialer import DialConfig, dial
from nethernet.discovery.listener import DiscoveryListener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import wait_readable
from nethernet.os.time import monotonic_ms


def main() raises:
    var discovery = DiscoveryListener(SocketAddr(0, 0))
    var target = String()
    while target.byte_length() == 0:
        discovery.service(monotonic_ms())    # broadcasts, reads responses
        for server in discovery.responses():
            target = String(server.network_id)
        _ = wait_readable(discovery.poll_fd(), 100)

    var conn = dial(discovery, target, DialConfig())
    var hello: List[UInt8] = [0x68, 0x69]
    conn.write(Span(hello))
    print(len(conn.read(5000)), "bytes back")
    conn.close()
```

To serve many connections from one loop, call `Listener.poll()` and
`Conn.poll()` yourself and wait on their descriptors
(`Listener.add_poll_fds()`, `Conn.fd()`) with `nethernet.os.poll.PollSet`
until the earliest `next_timeout()`; `examples/echo_server.mojo` shows the
pattern.

Consumers import the package from source with `-I path/to/nethernet/src`, or
precompile it with `pixi run build` (`build/nethernet.mojoc`, tied to the
exact compiler version).

## Develop

```sh
pixi run test          # every unit test file
pixi run format        # mojo format, 80 columns
pixi run lint-docs     # every public symbol needs a docstring
pixi run build         # precompile the package
pixi run smoke         # import the precompiled package from a consumer
pixi run check         # format-check + lint-docs + smoke + test
pixi run -e interop interop   # go-nethernet interop matrix (installs Go)
pixi run bench
```

One test file: `pixi run mojo run -I src -D ASSERT=all test/nethernet/dtls/test_conn.mojo`.

- [docs/architecture.md](docs/architecture.md): how the layers fit together.
- [docs/protocol.md](docs/protocol.md): the NetherNet wire formats.
- [docs/interop.md](docs/interop.md): the interop harness and what it found.
- [AGENTS.md](AGENTS.md): rules for coding agents, and Mojo 1.2 pitfalls
  that apply to humans too.

## Security notes

- Certificates are trusted by the SHA-256 fingerprint in the SDP, as in every
  WebRTC stack. The fingerprint is only as trustworthy as the signaling
  channel unless identities are checked.
- Identity assertions prove possession of a P-384 key. A self-signed token
  says nothing about who holds it: pin `Conn.peer_public_key()` or verify the
  token's issuer yourself. Xbox-issued token chains are not validated here.
- LAN discovery packets are "encrypted" with a fixed, public key. That is
  obfuscation, exactly as in the game.
- The cryptography is written to avoid secret-dependent branches and table
  lookups (bitsliced AES, complete-formula P-256/P-384 with masked table
  scans), checked against FIPS, RFC and Wycheproof vectors, and on x86-64
  uses AES-NI and PCLMULQDQ. It has not been audited, and constant-time
  behaviour was inspected in the generated x86-64 code only.

## License

[MIT](LICENSE).
