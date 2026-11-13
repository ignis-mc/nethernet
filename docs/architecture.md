# Architecture

`nethernet` is a stack of small state machines. Each one is *sans-I/O*: it is
fed bytes and a timestamp, and hands back bytes to send, events, and the time
it next wants to be called. Only the top layer owns sockets.

```text
Listener[S] / dial()            negotiation: signals in, connections out
        │
      Conn                      one UDP socket, one of each machine below
        │
        ├── IceAgent            STUN checks  ──┐
        ├── DtlsConn            DTLS records ──┼── demultiplexed by first byte
        └── Association         SCTP packets, carried inside DTLS records
```

## Packages

| Package | Role | Depends on |
|---|---|---|
| `wire` | `Reader`, `put_*` encoders, hex | nothing |
| `json` | minimal JSON reader, string quoting | nothing |
| `os` | clock, randomness, UDP/TCP sockets, `PollSet`; `os/_sys` holds every system call | nothing |
| `crypto` | SHA-1/256/384/512, HMAC, AES, GCM, ECB, P-256, P-384, ECDSA, DER, X.509, CRC, base64 | `wire` |
| `stun` | STUN message codec, MESSAGE-INTEGRITY, FINGERPRINT | `crypto`, `os.addr` |
| `ice` | candidates, the connectivity-check agent | `stun` |
| `dtls` | handshake codec, record layer, the connection state machine | `crypto` |
| `sctp` | packet and chunk codec, sender, reassembly, the association | `crypto.crc`, `wire` |
| `datachannel` | DCEP, the two NetherNet channel definitions | `wire` |
| `sdp` | the offer/answer document | `wire` |
| `signaling` | signal codec, error codes, the `Signaling` trait, identity, HTTP endpoint | `crypto`, `json`, `os` |
| `discovery` | LAN packets, `ServerData`, the discovery listener | `crypto`, `signaling`, `os` |
| `conn`, `dialer`, `listener` | the public transport API | everything |

Lower layers never import higher ones. `wire`, `json` and `crypto` never
import `os`: randomness reaches them as bytes.

## Driving model

Mojo 1.2 has no stable threads or async, so nothing here runs in the
background. Every stateful object follows the same contract:

```mojo
conn.poll(now_ms)        # read what arrived, run timers, send what is due
conn.next_timeout()      # absolute monotonic ms of the next timer
conn.fd()                # descriptor to wait on
```

A single-connection program can use the blocking conveniences (`dial()`,
`Listener.accept()`, `Conn.read()`, `Conn.write()`, `Conn.drive()`), which
are loops around those three calls and `ppoll(2)`. A server polls its
`Listener` and every `Conn` from one loop, waiting on all descriptors with a
`PollSet` until the earliest `next_timeout()`.

Internally the same contract repeats one level down:

| Machine | Input | Output | Timers |
|---|---|---|---|
| `IceAgent` | `handle_packet(data, src, now)` | `poll_transmit()` → datagram + destination | check pacing, keepalive, liveness |
| `DtlsConn` | `handle_datagram(data, now)` | `poll_transmit()`, `poll_app_data()` | flight retransmission |
| `Association` | `handle_packet(data, now)` | `poll_transmit(now)`, `poll_event()` | T1/T3 retransmission, SACK, reconfig |

`Conn.poll()` shuttles bytes between them: datagrams whose first byte is 0–3
with the STUN cookie go to ICE; first byte 20–63 from the ICE-selected address
goes to DTLS; DTLS application data goes to SCTP; SCTP packets go back out
through DTLS; SCTP messages become DCEP handling or reassembled NetherNet
messages.

## Connection lifecycle

1. **Negotiate.** The dialer creates a `Conn` (socket, ICE credentials, a
   fresh P-256 certificate), signs its fingerprint into an identity
   assertion and signals the offer. The listener checks the offer's identity,
   creates its own `Conn`, decides the DTLS role and signals the answer.
   Candidates travel in separate `CANDIDATEADD` signals (LAN) or inside the
   SDP (HTTP).
2. **ICE.** The dialer is controlling, the listener controlled. Each side has
   exactly one host candidate: the address its socket is bound to. The
   controlling side nominates the first pair that answers.
3. **DTLS.** The answerer takes the client role (`a=setup:active`), as every
   WebRTC answerer does. Both sides present certificates; each checks the
   other's against the fingerprint from the SDP during the handshake.
4. **SCTP.** Both sides send INIT (as pion and libwebrtc do); the collision
   resolves into one association.
5. **Channels.** The dialer opens `ReliableDataChannel` and
   `UnreliableDataChannel` with DCEP on the stream IDs its DTLS role
   dictates (even for the DTLS client, odd for the server). The connection
   is open when both exist.
6. **Close.** `close()` waits for unacknowledged data, then sends an SCTP
   ABORT and a DTLS `close_notify`. A peer's ABORT, stream reset,
   `close_notify`, or 30 seconds of ICE silence closes the connection.

## Memory and compile time

Large state lives on the heap. `Conn` holds its `DtlsConn` and `Association`
through `OwnedPointer`, and `RecordCipher` holds its AES-GCM state the same
way. Mojo moves structs field by field, and LLVM's instruction selector is
quadratic in the number of scalar fields moved at once: with the AES state
inline, building the stack took 265 seconds instead of 20. Keep any struct
that is moved (returned, stored in a `List`, wrapped in an `Optional`) small.

## What is deliberately missing

- **Gathering.** No STUN or TURN client, so no server-reflexive or relayed
  candidates. That covers LAN and direct-address play, not NAT traversal
  through Xbox Live.
- **IPv6, mDNS and TCP candidates** are parsed and skipped.
- **Other DTLS suites and RSA or Ed25519 certificates.** Every WebRTC stack
  offers ECDHE-ECDSA-AES128-GCM with P-256, so one suite is enough to
  interoperate; a peer whose certificate is not ECDSA P-256 or P-384 is
  rejected.
- **TLS and WebSocket**, which Xbox Live signaling would need.
