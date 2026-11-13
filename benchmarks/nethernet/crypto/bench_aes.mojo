"""Throughput of AES-GCM sealing and opening, and of single AES blocks.

Run with `mojo run -I src benchmarks/nethernet/crypto/bench_aes.mojo`. Each
line reports the default key (AES-NI and PCLMULQDQ when the target has them)
and the portable constant-time implementation.
"""

from nethernet.crypto.aes import AES_HARDWARE, Aes
from nethernet.crypto.gcm import GCM_HARDWARE, AesGcm
from std.time import perf_counter_ns


def _mb_per_s(byte_count: Int, elapsed_ns: Int) -> Float64:
    return Float64(byte_count) * 1000.0 / Float64(elapsed_ns)


def _bench_seal(gcm: AesGcm, size: Int, rounds: Int) raises -> Float64:
    var nonce = List[UInt8](length=12, fill=7)
    var aad = List[UInt8](length=13, fill=3)
    var plain = List[UInt8](length=size, fill=0x5A)
    var out = List[UInt8](capacity=size + 16)
    var sink = UInt8(0)
    var start = perf_counter_ns()
    for i in range(rounds):
        out.clear()
        nonce[11] = UInt8(i & 0xFF)
        gcm.seal(Span(nonce), Span(aad), Span(plain), out)
        sink ^= out[size]
    var elapsed = perf_counter_ns() - start
    _ = sink
    return _mb_per_s(size * rounds, Int(elapsed))


def _bench_open(gcm: AesGcm, size: Int, rounds: Int) raises -> Float64:
    var nonce = List[UInt8](length=12, fill=7)
    var aad = List[UInt8](length=13, fill=3)
    var plain = List[UInt8](length=size, fill=0x5A)
    var sealed = List[UInt8]()
    gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
    var out = List[UInt8](capacity=size)
    var sink = UInt8(0)
    var start = perf_counter_ns()
    for _ in range(rounds):
        out.clear()
        gcm.open(Span(nonce), Span(aad), Span(sealed), out)
        sink ^= out[0]
    var elapsed = perf_counter_ns() - start
    _ = sink
    return _mb_per_s(size * rounds, Int(elapsed))


def _bench_block(aes: Aes, rounds: Int) -> Float64:
    var block = Array[UInt8, 16](fill=0)
    var start = perf_counter_ns()
    for _ in range(rounds):
        block = aes.encrypt_block(block)
    var elapsed = perf_counter_ns() - start
    _ = block[0]
    return _mb_per_s(16 * rounds, Int(elapsed))


def main() raises:
    print("AES-NI compiled in:", AES_HARDWARE, " PCLMULQDQ:", GCM_HARDWARE)
    for key_len in [16, 32]:
        var key = List[UInt8](length=key_len, fill=1)
        var fast = AesGcm(Span(key))
        var soft = AesGcm.portable(Span(key))
        for size in [64, 256, 1200, 16384]:
            var rounds = 40_000_000 // (size + 200)
            print(
                t"AES-{8 * key_len}-GCM seal {size} B: default"
                t" {_bench_seal(fast, size, rounds)} MB/s, portable"
                t" {_bench_seal(soft, size, rounds // 4)} MB/s"
            )
        print(
            t"AES-{8 * key_len}-GCM open 1200 B: default"
            t" {_bench_open(fast, 1200, 30000)} MB/s, portable"
            t" {_bench_open(soft, 1200, 8000)} MB/s"
        )
        var block_fast = Aes(Span(key))
        var block_soft = Aes.portable(Span(key))
        print(
            t"AES-{8 * key_len} encrypt_block: default"
            t" {_bench_block(block_fast, 2_000_000)} MB/s, portable"
            t" {_bench_block(block_soft, 200_000)} MB/s"
        )
