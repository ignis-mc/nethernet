"""Timings of P-256 and P-384 key generation, ECDH, signing and verification.

Run with `mojo run -I src benchmarks/nethernet/crypto/bench_ec.mojo`. The
report gives the mean time of one operation in milliseconds.
"""

from nethernet.crypto.p256 import (
    p256_ecdh,
    p256_private_key_from_bytes,
    p256_public_key,
    p256_sign,
    p256_verify,
)
from nethernet.crypto.p384 import (
    p384_ecdh,
    p384_private_key_from_bytes,
    p384_public_key,
    p384_sign,
    p384_verify,
)
from std.benchmark import Bench, BenchConfig, BenchId, Bencher, keep


def _seed(count: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=count)
    for i in range(count):
        out.append(UInt8((i * 37 + 11) & 0xFF))
    return out^


def _bench_p256_keygen(mut b: Bencher) raises:
    # Measures deriving a P-256 private key and its public key.
    var seed = _seed(40)

    @inline(.always)
    def call_fn() {imm}:
        try:
            var d = p256_private_key_from_bytes(Span(seed))
            keep(p256_public_key(Span(d))[1])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p256_ecdh(mut b: Bencher) raises:
    # Measures one P-256 Diffie-Hellman computation, validation included.
    var seed = _seed(40)
    var d = p256_private_key_from_bytes(Span(seed))
    var peer_seed = _seed(48)
    var peer_d = p256_private_key_from_bytes(Span(peer_seed))
    var peer = p256_public_key(Span(peer_d))

    @inline(.always)
    def call_fn() {imm}:
        try:
            keep(p256_ecdh(Span(d), Span(peer))[0])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p256_sign(mut b: Bencher) raises:
    # Measures one P-256 ECDSA signature over a 32-byte digest.
    var seed = _seed(40)
    var d = p256_private_key_from_bytes(Span(seed))
    var digest = _seed(32)

    @inline(.always)
    def call_fn() {imm}:
        try:
            keep(p256_sign(Span(d), Span(digest))[0])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p256_verify(mut b: Bencher) raises:
    # Measures one P-256 ECDSA verification of a valid signature.
    var seed = _seed(40)
    var d = p256_private_key_from_bytes(Span(seed))
    var public_key = p256_public_key(Span(d))
    var digest = _seed(32)
    var sig = p256_sign(Span(d), Span(digest))

    @inline(.always)
    def call_fn() {imm}:
        keep(p256_verify(Span(public_key), Span(digest), Span(sig)))

    b.iter(call_fn)


def _bench_p384_keygen(mut b: Bencher) raises:
    # Measures deriving a P-384 private key and its public key.
    var seed = _seed(56)

    @inline(.always)
    def call_fn() {imm}:
        try:
            var d = p384_private_key_from_bytes(Span(seed))
            keep(p384_public_key(Span(d))[1])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p384_ecdh(mut b: Bencher) raises:
    # Measures one P-384 Diffie-Hellman computation, validation included.
    var seed = _seed(56)
    var d = p384_private_key_from_bytes(Span(seed))
    var peer_seed = _seed(64)
    var peer_d = p384_private_key_from_bytes(Span(peer_seed))
    var peer = p384_public_key(Span(peer_d))

    @inline(.always)
    def call_fn() {imm}:
        try:
            keep(p384_ecdh(Span(d), Span(peer))[0])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p384_sign(mut b: Bencher) raises:
    # Measures one P-384 ECDSA signature over a 48-byte digest.
    var seed = _seed(56)
    var d = p384_private_key_from_bytes(Span(seed))
    var digest = _seed(48)

    @inline(.always)
    def call_fn() {imm}:
        try:
            keep(p384_sign(Span(d), Span(digest))[0])
        except e:
            keep(0)

    b.iter(call_fn)


def _bench_p384_verify(mut b: Bencher) raises:
    # Measures one P-384 ECDSA verification of a valid signature.
    var seed = _seed(56)
    var d = p384_private_key_from_bytes(Span(seed))
    var public_key = p384_public_key(Span(d))
    var digest = _seed(48)
    var sig = p384_sign(Span(d), Span(digest))

    @inline(.always)
    def call_fn() {imm}:
        keep(p384_verify(Span(public_key), Span(digest), Span(sig)))

    b.iter(call_fn)


def main() raises:
    var m = Bench(BenchConfig(num_repetitions=1))
    m.bench_function(_bench_p256_keygen, BenchId("p256_keygen"))
    m.bench_function(_bench_p256_ecdh, BenchId("p256_ecdh"))
    m.bench_function(_bench_p256_sign, BenchId("p256_sign"))
    m.bench_function(_bench_p256_verify, BenchId("p256_verify"))
    m.bench_function(_bench_p384_keygen, BenchId("p384_keygen"))
    m.bench_function(_bench_p384_ecdh, BenchId("p384_ecdh"))
    m.bench_function(_bench_p384_sign, BenchId("p384_sign"))
    m.bench_function(_bench_p384_verify, BenchId("p384_verify"))
    m.dump_report()
