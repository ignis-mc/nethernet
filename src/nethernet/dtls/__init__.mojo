"""DTLS 1.2 (RFC 6347) for WebRTC: client and server.

One cipher suite is implemented, the one every WebRTC stack supports:
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` with secp256r1 key exchange and
mutual certificate authentication. Certificates are trusted by their SHA-256
fingerprint, which the caller learns from the SDP.
"""
