"""Cryptographic primitives used by DTLS, STUN, discovery and identity.

Everything here is implemented in Mojo from the published specifications and
checked against their test vectors. The package has no I/O: callers supply
randomness as bytes.
"""
