from nethernet.crypto.crc import crc32, crc32c
from nethernet.crypto.ct import constant_time_eq
from nethernet.crypto.hmac import Hmac, hmac
from nethernet.crypto.sha1 import Sha1, sha1
from nethernet.crypto.sha256 import Sha256
from nethernet.crypto.sha512 import Sha384, Sha512, sha384, sha512
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def test_sha1_vectors() raises:
    var empty = List[UInt8]()
    var d0 = sha1(Span(empty))
    assert_equal(
        hex_encode(Span(d0)), "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
    var abc = bytes_of("abc")
    var d1 = sha1(Span(abc))
    assert_equal(
        hex_encode(Span(d1)), "a9993e364706816aba3e25717850c26c9cd0d89d"
    )
    var long = bytes_of(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    )
    var d2 = sha1(Span(long))
    assert_equal(
        hex_encode(Span(d2)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    )


def test_sha512_vectors() raises:
    var abc = bytes_of("abc")
    var d = sha512(Span(abc))
    assert_equal(
        hex_encode(Span(d)),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )
    var empty = List[UInt8]()
    var d0 = sha512(Span(empty))
    assert_equal(
        hex_encode(Span(d0)),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )
    var long = bytes_of(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    )
    var d2 = sha512(Span(long))
    assert_equal(
        hex_encode(Span(d2)),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    )


def test_sha384_vectors() raises:
    var abc = bytes_of("abc")
    var d = sha384(Span(abc))
    assert_equal(
        hex_encode(Span(d)),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )
    var empty = List[UInt8]()
    var d0 = sha384(Span(empty))
    assert_equal(
        hex_encode(Span(d0)),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    )


def test_hmac_sha256_rfc4231() raises:
    var key1 = List[UInt8](length=20, fill=0x0B)
    var msg1 = bytes_of("Hi There")
    var t1 = hmac[Sha256](Span(key1), Span(msg1))
    assert_equal(
        hex_encode(Span(t1)),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )
    var key2 = bytes_of("Jefe")
    var msg2 = bytes_of("what do ya want for nothing?")
    var t2 = hmac[Sha256](Span(key2), Span(msg2))
    assert_equal(
        hex_encode(Span(t2)),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    )
    # Key longer than the block size.
    var key6 = List[UInt8](length=131, fill=0xAA)
    var msg6 = bytes_of(
        "Test Using Larger Than Block-Size Key - Hash Key First"
    )
    var t6 = hmac[Sha256](Span(key6), Span(msg6))
    assert_equal(
        hex_encode(Span(t6)),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )


def test_hmac_sha1_rfc2202() raises:
    var key1 = List[UInt8](length=20, fill=0x0B)
    var msg1 = bytes_of("Hi There")
    var t1 = hmac[Sha1](Span(key1), Span(msg1))
    assert_equal(
        hex_encode(Span(t1)), "b617318655057264e28bc0b6fb378c8ef146be00"
    )
    var key2 = bytes_of("Jefe")
    var msg2 = bytes_of("what do ya want for nothing?")
    var t2 = hmac[Sha1](Span(key2), Span(msg2))
    assert_equal(
        hex_encode(Span(t2)), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    )


def test_hmac_sha384_sha512_rfc4231() raises:
    var key2 = bytes_of("Jefe")
    var msg2 = bytes_of("what do ya want for nothing?")
    var t384 = hmac[Sha384](Span(key2), Span(msg2))
    assert_equal(
        hex_encode(Span(t384)),
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
    )
    var t512 = hmac[Sha512](Span(key2), Span(msg2))
    assert_equal(
        hex_encode(Span(t512)),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    )


def test_hmac_streaming() raises:
    var key = bytes_of("key")
    var msg = bytes_of("The quick brown fox jumps over the lazy dog")
    var mac = Hmac[Sha256](Span(key))
    mac.update(Span(msg)[0:10])
    mac.update(Span(msg)[10 : len(msg)])
    var tag = mac.finish()
    assert_equal(
        hex_encode(Span(tag)),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
    )


def test_crc32_and_crc32c() raises:
    var check = bytes_of("123456789")
    assert_equal(crc32(Span(check)), 0xCBF43926)
    assert_equal(crc32c(Span(check)), 0xE3069283)
    var zeros = List[UInt8](length=32, fill=0)
    assert_equal(crc32c(Span(zeros)), 0x8A9136AA)


def test_constant_time_eq() raises:
    var a = hex_decode("00112233")
    var b = hex_decode("00112233")
    var c = hex_decode("00112234")
    assert_true(constant_time_eq(Span(a), Span(b)))
    assert_false(constant_time_eq(Span(a), Span(c)))
    assert_false(constant_time_eq(Span(a), Span(c)[0:3]))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
