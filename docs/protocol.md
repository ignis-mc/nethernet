# NetherNet wire formats

What this library sends and accepts, in one place. It follows go-nethernet
and what the game is known to do; section numbers below refer to RFCs where
one applies.

## Signals

Negotiation uses four text messages:

```text
<TYPE> <connection id> <data>
```

| Type | Data |
|---|---|
| `CONNECTREQUEST` | the offer SDP |
| `CONNECTRESPONSE` | the answer SDP |
| `CANDIDATEADD` | one ICE candidate line |
| `CONNECTERROR` | a decimal error code (`nethernet.signaling.signal.ERROR_*`) |

The connection ID is an unsigned 64-bit decimal chosen by the dialer. Parsing
splits on the first two spaces; the ID is read from its leading digits.

## SDP

One `m=application` section, CRLF line endings:

```text
v=0
o=- <session id> 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS
a=identity:<base64>                       optional
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=candidate:<candidate>                   only without trickle ICE
a=ice-ufrag:<16 letters>
a=ice-pwd:<32 letters>
a=ice-options:trickle
a=fingerprint:sha-256 <UPPERCASE:HEX>
a=setup:actpass | active | passive
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
```

Readers use `ice-ufrag`, `ice-pwd`, `fingerprint`, `setup`,
`max-message-size`, `identity` and every `candidate`; the rest is ignored.

A candidate line:

```text
candidate:<foundation> 1 udp <priority> <ip> <port> typ host generation 0 ufrag <ufrag> network-id <n> network-cost 0
```

## Identity

`a=identity` is base64 of:

```json
{"assertion":"<JSON string>","idp":{"domain":"self","protocol":"default"}}
```

where the assertion string is `{"fingerprints":"<JWS>","token":"<JWT>"}`.

- `fingerprints` is a detached ES384 JWS (`header..signature`) over
  `{"fingerprint":[{"algorithm":"sha-256","digest":"AA:BB:…"}]}`, built from
  the `a=fingerprint` line as written.
- `token` is an ES384 JWT with `iat`, `exp` (one minute later) and `cpk`, the
  P-384 public key as a JWK object (servers) or base64 PKIX DER (clients).

A dialer checks that the token is signed by the key it carries and that this
key signed the fingerprint. A listener checks the token's time claims and
the fingerprint signature.

## Data channels

The dialer opens two channels in-band (RFC 8832), on stream IDs 0 and 2 if
it is the DTLS client and 1 and 3 if it is the DTLS server:

| Label | Type | Use |
|---|---|---|
| `ReliableDataChannel` | ordered, reliable (`0x00`) | game packets |
| `UnreliableDataChannel` | unordered, no retransmissions (`0x81`, parameter 0) | rarely used |

Every message on either channel is:

```text
byte 0     segments still to come (0 on the last or only segment)
bytes 1..  payload fragment, at least one byte
```

A message longer than the peer's `max-message-size` minus one is split into
up to 256 consecutive messages on the reliable channel. The unreliable
channel carries single-segment messages only. Messages use PPID 53 (binary).

## LAN discovery (UDP 7551)

```text
datagram = HMAC-SHA256(key, payload) || AES-256-ECB(key, PKCS7(payload))
key      = SHA-256(EF BE AD DE 00 00 00 00)
```

The payload is little-endian:

```text
u16  length        whole payload including this field
u16  packet ID     0 request, 1 response, 2 message
u64  sender network ID
8    zero bytes
...  body
```

| Packet | Body |
|---|---|
| Request | empty; broadcast every 2 s by clients |
| Response | `u32` length, then `ServerData` as lowercase hex |
| Message | `u64` recipient ID, `u32` length (capped at 1140), then a signal |

`ServerData` version 7: `u8 7`, then strings (varuint length + bytes),
zigzag varints and one-byte booleans in this order: server name, protocol,
version, level name, player count, max players, game type, editor world,
hardcore, accepts online auth, accepts self-signed auth, nonce, connection
type (4 for LAN signaling).

## HTTP signaling

```text
GET  /v1/join                 probe; any 2xx means "NetherNet spoken here"
POST /v1/join/<client id>     body: offer SDP with candidates embedded
                              2xx body: answer SDP, or a decimal error code
```

There is no trickle ICE and no way to signal an error back to the server.
The Go server answers a failed negotiation with status 500 and the error
code as the body; a timeout is 502.
