from nethernet.crypto.aes import Aes
from nethernet.crypto.ecb import (
    _ecb_decrypt_with,
    _ecb_encrypt_with,
    ecb_decrypt_pkcs7,
    ecb_encrypt_pkcs7,
)
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_raises, assert_true

comptime _PLAIN = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
comptime _LAN_KEY = (
    "eed4c37861936c6ebb91ab9d195c1b489de46362d3bb8e30d8aab08bf217e6f3"
)


def _pattern(length: Int, mul: Int, add: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(UInt8((mul * i + add) & 0xFF))
    return out^


def _check_vector(
    key_hex: StringSpan, plain_hex: StringSpan, cipher_hex: StringSpan
) raises:
    # Checks the public functions and, through the helpers that take a key
    # schedule, the bitsliced implementation on every target.
    var key = hex_decode(key_hex)
    var plain = hex_decode(plain_hex)
    var cipher = hex_decode(cipher_hex)
    var sealed = List[UInt8]()
    ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
    assert_equal(hex_encode(Span(sealed)), String(cipher_hex))
    var opened = List[UInt8]()
    ecb_decrypt_pkcs7(Span(key), Span(cipher), opened)
    assert_equal(hex_encode(Span(opened)), String(plain_hex))

    var soft = Aes.portable(Span(key))
    var sealed_soft = List[UInt8]()
    _ecb_encrypt_with(soft, Span(plain), sealed_soft)
    assert_equal(hex_encode(Span(sealed_soft)), String(cipher_hex))
    var opened_soft = List[UInt8]()
    _ecb_decrypt_with(soft, Span(cipher), opened_soft)
    assert_equal(hex_encode(Span(opened_soft)), String(plain_hex))


def test_sp800_38a_f1_with_padding_block() raises:
    # NIST SP 800-38A F.1.1, F.1.3 and F.1.5 ciphertexts, each followed by
    # the block that PKCS#7 adds to a block-aligned message (from
    # `openssl enc -aes-*-ecb`).
    _check_vector(
        "2b7e151628aed2a6abf7158809cf4f3c",
        _PLAIN,
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4a254be88e037ddd9d79fb6411c3f9df8",
    )
    _check_vector(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        _PLAIN,
        "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0edaa0af074bd8083c8a32d4fc563c55cc",
    )
    _check_vector(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        _PLAIN,
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc74c45dfb3b3b484ec35b0512dc8c1c4d6",
    )


def test_lan_discovery_shaped_packet() raises:
    # A 20-byte payload under a 32-byte key, as in NetherNet LAN discovery,
    # becomes two blocks. Expected value from `openssl enc -aes-256-ecb`.
    _check_vector(
        _LAN_KEY,
        "000102030405060708090a0b0c0d0e0f10111213",
        "1f0fa291ad03f17ed0db81c6c0da04397ff779bf4baaefc55ac23ab8b60c72c0",
    )
    var key = hex_decode(_LAN_KEY)
    var plain = hex_decode("000102030405060708090a0b0c0d0e0f10111213")
    var sealed = List[UInt8]()
    ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
    assert_equal(len(plain), 20)
    assert_equal(len(sealed), 32)


def test_round_trip_every_length() raises:
    for key_len in [16, 24, 32]:
        var key = _pattern(key_len, 7, 1)
        var soft = Aes.portable(Span(key))
        for length in range(49):
            var plain = _pattern(length, 5, 3)
            var sealed = List[UInt8]()
            ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
            # Always 1..16 bytes of padding, up to the next block boundary.
            assert_equal(len(sealed), (length // 16 + 1) * 16)
            var opened = List[UInt8]()
            ecb_decrypt_pkcs7(Span(key), Span(sealed), opened)
            assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))

            var sealed_soft = List[UInt8]()
            _ecb_encrypt_with(soft, Span(plain), sealed_soft)
            assert_equal(
                hex_encode(Span(sealed_soft)), hex_encode(Span(sealed))
            )
            var opened_soft = List[UInt8]()
            _ecb_decrypt_with(soft, Span(sealed), opened_soft)
            assert_equal(hex_encode(Span(opened_soft)), hex_encode(Span(plain)))


def test_padding_bytes() raises:
    # Decrypting block by block shows the padding itself.
    var key = hex_decode(_LAN_KEY)
    var aes = Aes(Span(key))
    for length in [0, 1, 15, 16, 20, 31, 32]:
        var plain = _pattern(length, 9, 2)
        var sealed = List[UInt8]()
        ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
        var block = Array[UInt8, 16](fill=0)
        for i in range(16):
            block[i] = sealed[len(sealed) - 16 + i]
        var last = aes.decrypt_block(block)
        var pad = 16 - length % 16
        for i in range(pad):
            assert_equal(Int(last[15 - i]), pad)


def test_output_is_appended() raises:
    var key = hex_decode(_LAN_KEY)
    var plain = _pattern(20, 1, 0)
    var sealed: List[UInt8] = [0xDE, 0xAD]
    ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
    assert_equal(len(sealed), 34)
    assert_equal(hex_encode(Span(sealed)[0:2]), "dead")
    var opened: List[UInt8] = [0xBE, 0xEF]
    ecb_decrypt_pkcs7(Span(key), Span(sealed)[2:34], opened)
    assert_equal(hex_encode(Span(opened)), "beef" + hex_encode(Span(plain)))


def _assert_decrypt_fails(
    key: Span[UInt8, _], ciphertext: Span[UInt8, _], expected: StringSpan
) raises:
    var soft = Aes.portable(key)
    var out: List[UInt8] = [0xA5, 0x5A]
    with assert_raises(contains=String(expected)):
        ecb_decrypt_pkcs7(key, ciphertext, out)
    assert_equal(hex_encode(Span(out)), "a55a")
    with assert_raises(contains=String(expected)):
        _ecb_decrypt_with(soft, ciphertext, out)
    assert_equal(hex_encode(Span(out)), "a55a")


def test_rejects_bad_lengths() raises:
    var key = hex_decode(_LAN_KEY)
    var plain = _pattern(40, 3, 1)
    var sealed = List[UInt8]()
    ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
    assert_equal(len(sealed), 48)
    for n in [0, 1, 15, 17, 31, 33, 47]:
        _assert_decrypt_fails(
            Span(key),
            Span(sealed)[0:n],
            "ecb: ciphertext length must be a positive multiple of 16",
        )


def _encrypt_raw(
    key: Span[UInt8, _], plain: Span[UInt8, _]
) raises -> List[UInt8]:
    # ECB without padding, to build ciphertexts with chosen final blocks.
    var aes = Aes(key)
    var out = List[UInt8]()
    var block = Array[UInt8, 16](fill=0)
    for off in range(0, len(plain), 16):
        for i in range(16):
            block[i] = plain[off + i]
        var ct = aes.encrypt_block(block)
        for i in range(16):
            out.append(ct[i])
    return out^


def test_rejects_bad_padding() raises:
    var key = hex_decode(_LAN_KEY)
    var bad_tails = [
        # Padding length zero.
        "000102030405060708090a0b0c0d0e00",
        # Padding length above the block size.
        "00010203040506070809101112131411",
        "202020202020202020202020202020ff",
        # Padding bytes that disagree with the length.
        "000102030405060708090a0b0c0d0302",
        "00010203040506070809040404050404",
        "0f101010101010101010101010101010",
        "10101010101010101010101010101110",
        # Truncated message: the last block is ordinary data.
        "4142434445464748494a4b4c4d4e4f50",
    ]
    for tail in bad_tails:
        for prefix_blocks in [0, 1, 2]:
            var plain = _pattern(16 * prefix_blocks, 3, 1)
            var last = hex_decode(tail)
            for b in last:
                plain.append(b)
            var cipher = _encrypt_raw(Span(key), Span(plain))
            _assert_decrypt_fails(
                Span(key), Span(cipher), "ecb: invalid padding"
            )


def test_accepts_every_padding_length() raises:
    var key = hex_decode(_LAN_KEY)
    for pad in range(1, 17):
        var plain = _pattern(32 - pad, 3, 1)
        var padded = plain.copy()
        for _ in range(pad):
            padded.append(UInt8(pad))
        var cipher = _encrypt_raw(Span(key), Span(padded))
        var opened = List[UInt8]()
        ecb_decrypt_pkcs7(Span(key), Span(cipher), opened)
        assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))


def test_wrong_key_does_not_round_trip() raises:
    var key = hex_decode(_LAN_KEY)
    var other = _pattern(32, 1, 0)
    var plain = _pattern(20, 3, 1)
    var sealed = List[UInt8]()
    ecb_encrypt_pkcs7(Span(key), Span(plain), sealed)
    var opened = List[UInt8]()
    var failed = False
    try:
        ecb_decrypt_pkcs7(Span(other), Span(sealed), opened)
    except:
        failed = True
    # Either the padding is rejected or the bytes differ.
    assert_true(failed or hex_encode(Span(opened)) != hex_encode(Span(plain)))


def test_rejects_bad_key_lengths() raises:
    var plain = _pattern(20, 3, 1)
    var cipher = _pattern(32, 3, 1)
    for n in [0, 15, 17, 31, 33]:
        var key = List[UInt8](length=n, fill=1)
        var out = List[UInt8]()
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            ecb_encrypt_pkcs7(Span(key), Span(plain), out)
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            ecb_decrypt_pkcs7(Span(key), Span(cipher), out)
        assert_equal(len(out), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
