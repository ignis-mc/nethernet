from nethernet.crypto.aes import AES_BLOCK_LEN, Aes
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_raises


def _block(text: StringSpan) raises -> Array[UInt8, 16]:
    var data = hex_decode(text)
    assert_equal(len(data), 16)
    var block = Array[UInt8, 16](fill=0)
    for i in range(16):
        block[i] = data[i]
    return block^


def _ciphers(key_hex: StringSpan) raises -> List[Aes]:
    # The default cipher (AES-NI where the target has it) and the bitsliced
    # one, so every vector runs through both paths.
    var key = hex_decode(key_hex)
    var ciphers = List[Aes]()
    ciphers.append(Aes(Span(key)))
    ciphers.append(Aes.portable(Span(key)))
    return ciphers^


def _check_block(
    key_hex: StringSpan, plain_hex: StringSpan, cipher_hex: StringSpan
) raises:
    for aes in _ciphers(key_hex):
        var ct = aes.encrypt_block(_block(plain_hex))
        assert_equal(hex_encode(Span(ct)), String(cipher_hex))
        var pt = aes.decrypt_block(_block(cipher_hex))
        assert_equal(hex_encode(Span(pt)), String(plain_hex))


def test_block_len() raises:
    assert_equal(AES_BLOCK_LEN, 16)


def test_fips197_appendix_c() raises:
    # C.1, C.2 and C.3 example vectors.
    _check_block(
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    )
    _check_block(
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
    )
    _check_block(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
    )


def test_fips197_appendix_b() raises:
    _check_block(
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
    )


def _check_words(
    key_hex: StringSpan, indices: List[Int], words: List[UInt32]
) raises:
    for aes in _ciphers(key_hex):
        for i in range(len(indices)):
            assert_equal(aes._round_key_word(indices[i]), words[i])


def test_fips197_appendix_a_key_expansion() raises:
    # A.1: AES-128, w4..w8, w20, w36 and the last round key w40..w43.
    _check_words(
        "2b7e151628aed2a6abf7158809cf4f3c",
        [0, 3, 4, 5, 6, 7, 8, 20, 36, 40, 41, 42, 43],
        [
            0x2B7E1516,
            0x09CF4F3C,
            0xA0FAFE17,
            0x88542CB1,
            0x23A33939,
            0x2A6C7605,
            0xF2C295F2,
            0xD4D1C6F8,
            0xAC7766F3,
            0xD014F9A8,
            0xC9EE2589,
            0xE13F0CC8,
            0xB6630CA6,
        ],
    )
    # A.2: AES-192, w6..w8, w12, w24 and the last round key w48..w51.
    _check_words(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        [5, 6, 7, 8, 12, 24, 48, 49, 50, 51],
        [
            0x522C6B7B,
            0xFE0C91F7,
            0x2402F5A5,
            0xEC12068E,
            0x4DB7B4BD,
            0xA25E7ED5,
            0xE98BA06F,
            0x448C773C,
            0x8ECC7204,
            0x01002202,
        ],
    )
    # A.3: AES-256, w8..w12, w16, w32 and the last round key w56..w59.
    _check_words(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        [7, 8, 9, 10, 11, 12, 16, 32, 56, 57, 58, 59],
        [
            0x0914DFF4,
            0x9BA35411,
            0x8E6925AF,
            0xA51A8B5F,
            0x2067FCDE,
            0xA8B09C1A,
            0xD59AECB8,
            0x68007BAC,
            0xFE4890D1,
            0xE6188D0B,
            0x046DF344,
            0x706C631E,
        ],
    )


def test_sp800_38a_f1_ecb_blocks() raises:
    var plain = [
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ]
    # F.1.1 / F.1.2: ECB-AES128.
    var c128 = [
        "3ad77bb40d7a3660a89ecaf32466ef97",
        "f5d3d58503b9699de785895a96fdbaaf",
        "43b1cd7f598ece23881b00e3ed030688",
        "7b0c785e27e8ad3f8223207104725dd4",
    ]
    # F.1.3 / F.1.4: ECB-AES192.
    var c192 = [
        "bd334f1d6e45f25ff712a214571fa5cc",
        "974104846d0ad3ad7734ecb3ecee4eef",
        "ef7afd2270e2e60adce0ba2face6444e",
        "9a4b41ba738d6c72fb16691603c18e0e",
    ]
    # F.1.5 / F.1.6: ECB-AES256.
    var c256 = [
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
        "591ccb10d410ed26dc5ba74a31362870",
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
        "23304b7a39f9f3ff067d8d8f9e24ecc7",
    ]
    for i in range(4):
        _check_block("2b7e151628aed2a6abf7158809cf4f3c", plain[i], c128[i])
        _check_block(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            plain[i],
            c192[i],
        )
        _check_block(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            plain[i],
            c256[i],
        )


def test_all_zero_and_all_one_inputs() raises:
    var zero = "00000000000000000000000000000000"
    var ones = "ffffffffffffffffffffffffffffffff"
    _check_block(zero, zero, "66e94bd4ef8a2c3b884cfa59ca342b2e")
    _check_block(ones, ones, "bcbf217cb280cf30b2517052193ab979")
    _check_block(
        "000000000000000000000000000000000000000000000000",
        zero,
        "aae06992acbf52a3e8f4a96ec9300bd7",
    )
    _check_block(
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        ones,
        "bf70034e29ff718ee48ddf36bb8174ef",
    )
    _check_block(
        "0000000000000000000000000000000000000000000000000000000000000000",
        zero,
        "dc95c078a2408989ad48a21492842087",
    )
    _check_block(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ones,
        "d5f93d6d3311cb309f23621b02fbd5e2",
    )


def test_rejects_bad_key_lengths() raises:
    for n in [0, 1, 15, 17, 20, 23, 25, 31, 33, 48, 64]:
        var key = List[UInt8](length=n, fill=0x42)
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            _ = Aes(Span(key))
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            _ = Aes.portable(Span(key))


def _next(mut state: UInt64) -> UInt8:
    # Small deterministic generator for test inputs.
    state = state * 6364136223846793005 + 1442695040888963407
    return UInt8((state >> 56) & 0xFF)


def test_paths_agree_and_round_trip() raises:
    var state = UInt64(0x243F6A8885A308D3)
    for key_len in [16, 24, 32]:
        for _ in range(64):
            var key = List[UInt8]()
            for _ in range(key_len):
                key.append(_next(state))
            var block = Array[UInt8, 16](fill=0)
            for i in range(16):
                block[i] = _next(state)
            var fast = Aes(Span(key))
            var soft = Aes.portable(Span(key))
            var ct = soft.encrypt_block(block)
            var ct_fast = fast.encrypt_block(block)
            assert_equal(hex_encode(Span(ct_fast)), hex_encode(Span(ct)))
            var pt = soft.decrypt_block(ct)
            var pt_fast = fast.decrypt_block(ct)
            assert_equal(hex_encode(Span(pt)), hex_encode(Span(block)))
            assert_equal(hex_encode(Span(pt_fast)), hex_encode(Span(block)))


def test_copy() raises:
    var key = hex_decode("000102030405060708090a0b0c0d0e0f")
    var first = Aes(Span(key))
    var second = first.copy()
    var ct = second.encrypt_block(_block("00112233445566778899aabbccddeeff"))
    assert_equal(hex_encode(Span(ct)), "69c4e0d86a7b0430d8cdb78070b4c55a")


def _keystream(
    aes: Aes, nonce: Span[UInt8, _], counter: UInt32, length: Int
) -> List[UInt8]:
    # Counter-mode keystream built one block at a time from `encrypt_block`.
    var out = List[UInt8](capacity=length + 16)
    var cc = counter
    while len(out) < length:
        var block = Array[UInt8, 16](fill=0)
        for i in range(12):
            block[i] = nonce[i]
        block[12] = UInt8(cc >> 24)
        block[13] = UInt8((cc >> 16) & 0xFF)
        block[14] = UInt8((cc >> 8) & 0xFF)
        block[15] = UInt8(cc & 0xFF)
        var ks = aes.encrypt_block(block)
        for i in range(16):
            out.append(ks[i])
        cc += 1
    out.shrink(length)
    return out^


def _check_pass[
    n: Int
](
    aes: Aes,
    nonce: Span[UInt8, _],
    counter: UInt32,
    src: Span[UInt8, _],
    expected: Span[UInt8, _],
) raises:
    var out = List[UInt8](length=len(src), fill=0)
    for offset in range(0, len(src), 64 * n):
        aes._ctr32_pass[n](nonce, counter, src, Span(out), offset)
    assert_equal(hex_encode(Span(out)), hex_encode(expected))


def test_ctr_matches_block_encryption() raises:
    # The counter-mode helper behind GCM, at every pass width, against a
    # keystream made from single-block encryptions. 0xFFFFFFFE checks that
    # the 32-bit counter wraps without carrying into the nonce.
    var nonce = hex_decode("cafebabefacedbaddecaf888")
    var state = UInt64(7)
    for key_len in [16, 24, 32]:
        var key = List[UInt8]()
        for _ in range(key_len):
            key.append(_next(state))
        var fast = Aes(Span(key))
        var soft = Aes.portable(Span(key))
        for counter in [UInt32(0), UInt32(2), UInt32(0xFFFFFFFE)]:
            for length in [
                0,
                1,
                15,
                16,
                17,
                31,
                33,
                63,
                64,
                65,
                127,
                128,
                129,
                191,
                193,
                255,
                256,
                257,
                300,
                511,
                513,
                1200,
            ]:
                var src = List[UInt8]()
                for _ in range(length):
                    src.append(_next(state))
                var expected = _keystream(soft, Span(nonce), counter, length)
                for i in range(length):
                    expected[i] ^= src[i]

                var out = List[UInt8](length=length, fill=0)
                fast._ctr32_xor(Span(nonce), counter, Span(src), Span(out))
                assert_equal(hex_encode(Span(out)), hex_encode(Span(expected)))
                var out_soft = List[UInt8](length=length, fill=0)
                soft._ctr32_xor(Span(nonce), counter, Span(src), Span(out_soft))
                assert_equal(
                    hex_encode(Span(out_soft)), hex_encode(Span(expected))
                )
                _check_pass[1](
                    soft, Span(nonce), counter, Span(src), Span(expected)
                )
                _check_pass[2](
                    soft, Span(nonce), counter, Span(src), Span(expected)
                )
                _check_pass[4](
                    soft, Span(nonce), counter, Span(src), Span(expected)
                )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
