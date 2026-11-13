# Changelog

## Unreleased

Initial implementation.

- Transport: `Conn`, `dial()` / `DialAttempt`, `Listener`, with the reliable
  and unreliable data channels and message segmentation.
- Signaling: the signal codec and error codes, LAN discovery on UDP 7551
  with `ServerData` version 7, HTTP signaling (`/v1/join`) as server and
  client, and identity assertions (`a=identity`, ES384).
- Protocols: ICE with one host candidate per connection, DTLS 1.2 client and
  server (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`), SCTP with partial
  reliability and stream reset, DCEP, the NetherNet SDP subset.
- Cryptography: SHA-1, SHA-256, SHA-384, SHA-512, HMAC, AES-128/192/256,
  AES-GCM, AES-ECB with PKCS#7, P-256 and P-384 ECDH and ECDSA, DER, X.509
  self-signed certificates, CRC-32, CRC-32C, base64.
- OS layer: UDP and TCP sockets, `ppoll`, clocks and `getrandom` through raw
  Linux system calls on x86-64 and aarch64.
- Interoperability harness against go-nethernet with 21 cases.
