from nethernet.crypto.gcm import GCM_NONCE_LEN, GCM_TAG_LEN, AesGcm
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def _keys(key: Span[UInt8, _]) raises -> List[AesGcm]:
    # The default key (AES-NI and PCLMULQDQ where the target has them) and
    # the portable one, so every vector runs through both paths.
    var keys = List[AesGcm]()
    keys.append(AesGcm(key))
    keys.append(AesGcm.portable(key))
    return keys^


def _assert_open_fails(
    gcm: AesGcm,
    nonce: Span[UInt8, _],
    aad: Span[UInt8, _],
    sealed: Span[UInt8, _],
) raises:
    # `open` must raise the authentication error and leave `out` alone.
    var out: List[UInt8] = [0xA5, 0x5A, 0x00]
    var message = String("")
    try:
        gcm.open(nonce, aad, sealed, out)
    except e:
        message = String(e)
    assert_equal(message, "gcm: authentication failed")
    assert_equal(hex_encode(Span(out)), "a55a00")


def _check_valid(
    key_hex: StringSpan,
    nonce_hex: StringSpan,
    aad_hex: StringSpan,
    plain_hex: StringSpan,
    cipher_hex: StringSpan,
    tag_hex: StringSpan,
) raises:
    var key = hex_decode(key_hex)
    var nonce = hex_decode(nonce_hex)
    var aad = hex_decode(aad_hex)
    var plain = hex_decode(plain_hex)
    var expected = String(cipher_hex) + String(tag_hex)
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
        assert_equal(hex_encode(Span(sealed)), expected)
        var opened = List[UInt8]()
        gcm.open(Span(nonce), Span(aad), Span(sealed), opened)
        assert_equal(hex_encode(Span(opened)), String(plain_hex))

        # The same message must not open with a changed ciphertext or with
        # different additional data.
        if len(plain) > 0:
            var bad = sealed.copy()
            bad[len(plain) // 2] ^= 0x01
            _assert_open_fails(gcm, Span(nonce), Span(aad), Span(bad))
        var longer = aad.copy()
        longer.append(0)
        _assert_open_fails(gcm, Span(nonce), Span(longer), Span(sealed))
        if len(aad) > 0:
            var flipped = aad.copy()
            flipped[len(aad) - 1] ^= 0x80
            _assert_open_fails(gcm, Span(nonce), Span(flipped), Span(sealed))
            _assert_open_fails(
                gcm, Span(nonce), Span(aad)[0 : len(aad) - 1], Span(sealed)
            )


def _check_invalid(
    key_hex: StringSpan,
    nonce_hex: StringSpan,
    aad_hex: StringSpan,
    cipher_hex: StringSpan,
    tag_hex: StringSpan,
) raises:
    var key = hex_decode(key_hex)
    var nonce = hex_decode(nonce_hex)
    var aad = hex_decode(aad_hex)
    var sealed = hex_decode(String(cipher_hex) + String(tag_hex))
    for gcm in _keys(Span(key)):
        _assert_open_fails(gcm, Span(nonce), Span(aad), Span(sealed))


def _wycheproof(line: StringSpan) raises:
    # "tcId:key:iv:aad:msg:ct:tag:result" from Wycheproof aes_gcm_test.json,
    # where result is "v" (valid) or "i" (invalid).
    var f = line.split(":")
    assert_equal(len(f), 8)
    if f[7] == "v":
        _check_valid(f[1], f[2], f[3], f[4], f[5], f[6])
    else:
        _check_invalid(f[1], f[2], f[3], f[5], f[6])


def test_constants() raises:
    assert_equal(GCM_NONCE_LEN, 12)
    assert_equal(GCM_TAG_LEN, 16)


comptime _K128 = "feffe9928665731c6d6a8f9467308308"
comptime _K256 = (
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
)
comptime _IV = "cafebabefacedbaddecaf888"
comptime _AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
comptime _P64 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
comptime _P60 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
comptime _ZERO12 = "000000000000000000000000"
comptime _ZERO16 = "00000000000000000000000000000000"
comptime _ZERO32 = (
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def test_gcm_spec_aes128_cases_1_to_4() raises:
    # McGrew & Viega, "The Galois/Counter Mode of Operation", Appendix B.
    # Test case 1: empty plaintext and no additional data.
    _check_valid(
        _ZERO16, _ZERO12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"
    )
    # Test case 2: one block.
    _check_valid(
        _ZERO16,
        _ZERO12,
        "",
        _ZERO16,
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    )
    # Test case 3: four blocks.
    _check_valid(
        _K128,
        _IV,
        "",
        _P64,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4",
    )
    # Test case 4: additional data and a partial final block.
    _check_valid(
        _K128,
        _IV,
        _AAD,
        _P60,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    )


def test_gcm_spec_aes256_cases_13_to_16() raises:
    # Test case 13: empty plaintext and no additional data.
    _check_valid(
        _ZERO32, _ZERO12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"
    )
    # Test case 14: one block.
    _check_valid(
        _ZERO32,
        _ZERO12,
        "",
        _ZERO16,
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    )
    # Test case 15: four blocks.
    _check_valid(
        _K256,
        _IV,
        "",
        _P64,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c",
    )
    # Test case 16: additional data and a partial final block.
    _check_valid(
        _K256,
        _IV,
        _AAD,
        _P60,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    )


def test_aad_only_tag_matches_gmac() raises:
    # With no plaintext the output is just the tag over the additional data
    # (GMAC). Expected values from Go's crypto/cipher.
    var key = hex_decode(_K128)
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    var none = List[UInt8]()
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(nonce), Span(aad), Span(none), sealed)
        assert_equal(len(sealed), GCM_TAG_LEN)
        assert_equal(
            hex_encode(Span(sealed)), "346434fd51d5cd0c5887ec63e39b907a"
        )


def _pattern(length: Int, mul: Int, add: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(UInt8((mul * i + add) & 0xFF))
    return out^


def _check_long(key_hex: StringSpan, length: Int, tag_hex: StringSpan) raises:
    # Plaintext byte i is (7 * i + 3) mod 256. The tag covers every
    # ciphertext byte, so matching it checks the whole ciphertext.
    var key = hex_decode(key_hex)
    var nonce = hex_decode("101112131415161718191a1b")
    var aad = hex_decode("000102030405060708090a0b0c")
    var plain = _pattern(length, 7, 3)
    var first = String("")
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
        assert_equal(len(sealed), length + GCM_TAG_LEN)
        assert_equal(
            hex_encode(Span(sealed)[length : length + GCM_TAG_LEN]),
            String(tag_hex),
        )
        var sealed_hex = hex_encode(Span(sealed))
        if first.byte_length() == 0:
            first = sealed_hex
        else:
            assert_equal(sealed_hex, first)
        var opened = List[UInt8]()
        gcm.open(Span(nonce), Span(aad), Span(sealed), opened)
        assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))


def test_long_messages_aes128() raises:
    # Tags from Go's crypto/cipher for lengths around the multi-block
    # counter-mode pass sizes, a 1200-byte record and a larger buffer.
    comptime KEY = "000102030405060708090a0b0c0d0e0f"
    _check_long(KEY, 63, "43e153dbda04a560e5b2258c9aeae0da")
    _check_long(KEY, 64, "aa66acd049ece6418ecb2057a38eb2d4")
    _check_long(KEY, 65, "b74b84f3db056d9026a2d9aa5425b02a")
    _check_long(KEY, 127, "df29056a6dcf44534c841064a860aae5")
    _check_long(KEY, 128, "ca57ba5d5366dfc65037be212eac5377")
    _check_long(KEY, 129, "e8645e80fe3485a339bc02baff3f9fb4")
    _check_long(KEY, 191, "a210b16b530e098da2dde700c8ca692c")
    _check_long(KEY, 192, "7a3d3f8bcd2c3e09848fe27af5ea0271")
    _check_long(KEY, 193, "c6c4dfadc02480ca4616e4be84480e9a")
    _check_long(KEY, 255, "aed149989dd29873209907c9f1e80804")
    _check_long(KEY, 256, "ba1feac14d1e7825bdd3cff2f1cdab02")
    _check_long(KEY, 257, "f199909547ff845561fe0cc8ef22f552")
    _check_long(KEY, 319, "6a3941096acd5e878a3580dfb95727d7")
    _check_long(KEY, 320, "3165dc35646acc8507250d74018d711c")
    _check_long(KEY, 321, "8e6224ed90209bdd3cf239fa2655cc16")
    _check_long(KEY, 513, "634512e365a600384a6835130fdec4dc")
    _check_long(KEY, 1200, "17a90db6d3a75febfaa8ea9b8ba974a3")
    _check_long(KEY, 4099, "3af6dae9b4ebd5ca79aaa611f74b3831")


def test_long_messages_aes256() raises:
    comptime KEY = (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    _check_long(KEY, 63, "03bddee720b8585cf6b94753a306276d")
    _check_long(KEY, 64, "4250b445c6ed9279c0d3a1cea799430c")
    _check_long(KEY, 65, "298cb5c1c698bb4654c20bb7befec87e")
    _check_long(KEY, 127, "c75979ab17a7ff6e3f91f76154318571")
    _check_long(KEY, 128, "4fa946aa4b8a72267ea7b1758424a698")
    _check_long(KEY, 129, "ef329f149dc5e876b6577332997d4ab4")
    _check_long(KEY, 191, "769f17bb41874ba030f9d0274a71fda1")
    _check_long(KEY, 192, "d13672b305858946c4d91ce5004b6c14")
    _check_long(KEY, 193, "89ba83fe98b8e3d69ab47aaf8d49ce9d")
    _check_long(KEY, 255, "ed1e89d3e97b25aca1d8b60a938ad1f0")
    _check_long(KEY, 256, "61c272466cac1db11ac72f05270bf358")
    _check_long(KEY, 257, "db55d204b2bc282b701030f7a76bb4e3")
    _check_long(KEY, 319, "7b4ab1b39143216990a6194a9dd6e126")
    _check_long(KEY, 320, "c5283e235de0f90c9772f5034c24c92a")
    _check_long(KEY, 321, "6848963b26e35f9611adf346798df4c2")
    _check_long(KEY, 513, "c9adf86c2ac191eb5de22bcd190e5355")
    _check_long(KEY, 1200, "5cb199d095bc1bf86ea22b375a45290d")
    _check_long(KEY, 4099, "2815fb6a4f1a2b089d1f261910b342f9")


def test_round_trip_every_length() raises:
    var key = hex_decode(_K128)
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    var none = List[UInt8]()
    var keys = _keys(Span(key))
    for length in range(66):
        var plain = _pattern(length, 13, 1)
        for with_aad in [False, True]:
            var data = Span(aad) if with_aad else Span(none)
            var first = String("")
            for gcm in keys:
                var sealed = List[UInt8]()
                gcm.seal(Span(nonce), data, Span(plain), sealed)
                assert_equal(len(sealed), length + GCM_TAG_LEN)
                var sealed_hex = hex_encode(Span(sealed))
                if first.byte_length() == 0:
                    first = sealed_hex
                else:
                    assert_equal(sealed_hex, first)
                var opened = List[UInt8]()
                gcm.open(Span(nonce), data, Span(sealed), opened)
                assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))
                # The additional data is bound to the message.
                if with_aad:
                    _assert_open_fails(
                        gcm, Span(nonce), Span(none), Span(sealed)
                    )
                else:
                    _assert_open_fails(
                        gcm, Span(nonce), Span(aad), Span(sealed)
                    )


def test_round_trip_aes192_and_aes256() raises:
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    for key_len in [24, 32]:
        var key = _pattern(key_len, 5, 9)
        for gcm in _keys(Span(key)):
            for length in [0, 1, 16, 37, 64, 100]:
                var plain = _pattern(length, 3, 2)
                var sealed = List[UInt8]()
                gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
                var opened = List[UInt8]()
                gcm.open(Span(nonce), Span(aad), Span(sealed), opened)
                assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))


def test_any_flipped_bit_is_rejected() raises:
    var key = hex_decode(_K128)
    var nonce = hex_decode(_IV)
    var aad = hex_decode("000100000000000117fefd0015")
    var plain = _pattern(21, 11, 4)
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
        # Every bit of the ciphertext and of the tag.
        for bit in range(8 * len(sealed)):
            var bad = sealed.copy()
            bad[bit >> 3] ^= UInt8(1) << UInt8(bit & 7)
            _assert_open_fails(gcm, Span(nonce), Span(aad), Span(bad))
        # Every bit of the additional data.
        for bit in range(8 * len(aad)):
            var bad = List[UInt8](aad)
            bad[bit >> 3] ^= UInt8(1) << UInt8(bit & 7)
            _assert_open_fails(gcm, Span(nonce), Span(bad), Span(sealed))
        # Every bit of the nonce.
        for bit in range(8 * len(nonce)):
            var bad = nonce.copy()
            bad[bit >> 3] ^= UInt8(1) << UInt8(bit & 7)
            _assert_open_fails(gcm, Span(bad), Span(aad), Span(sealed))
        # The untouched message still opens.
        var opened = List[UInt8]()
        gcm.open(Span(nonce), Span(aad), Span(sealed), opened)
        assert_equal(hex_encode(Span(opened)), hex_encode(Span(plain)))


def test_truncated_input_is_rejected() raises:
    var key = hex_decode(_K128)
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    var plain = _pattern(40, 11, 4)
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
        for keep in range(len(sealed)):
            _assert_open_fails(
                gcm, Span(nonce), Span(aad), Span(sealed)[0:keep]
            )
        # Extra bytes after the tag are not ignored either.
        var extended = sealed.copy()
        extended.append(0)
        _assert_open_fails(gcm, Span(nonce), Span(aad), Span(extended))


def test_wrong_key_is_rejected() raises:
    var key = hex_decode(_K128)
    var other = hex_decode("feffe9928665731c6d6a8f9467308309")
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    var plain = _pattern(33, 11, 4)
    var sealed = List[UInt8]()
    AesGcm(Span(key)).seal(Span(nonce), Span(aad), Span(plain), sealed)
    for gcm in _keys(Span(other)):
        _assert_open_fails(gcm, Span(nonce), Span(aad), Span(sealed))


def test_nonce_length_errors() raises:
    var key = hex_decode(_K128)
    var aad = hex_decode(_AAD)
    var plain = _pattern(20, 1, 0)
    var good = hex_decode(_IV)
    for gcm in _keys(Span(key)):
        var sealed = List[UInt8]()
        gcm.seal(Span(good), Span(aad), Span(plain), sealed)
        for n in [0, 1, 8, 11, 13, 16, 32]:
            var nonce = List[UInt8](length=n, fill=0xCA)
            var out: List[UInt8] = [1, 2, 3]
            with assert_raises(contains="gcm: nonce must be 12 bytes"):
                gcm.seal(Span(nonce), Span(aad), Span(plain), out)
            assert_equal(hex_encode(Span(out)), "010203")
            with assert_raises(contains="gcm: nonce must be 12 bytes"):
                gcm.open(Span(nonce), Span(aad), Span(sealed), out)
            assert_equal(hex_encode(Span(out)), "010203")


def test_key_length_errors() raises:
    for n in [0, 15, 17, 31, 33]:
        var key = List[UInt8](length=n, fill=1)
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            _ = AesGcm(Span(key))
        with assert_raises(contains="aes: key must be 16, 24 or 32 bytes"):
            _ = AesGcm.portable(Span(key))


def test_output_is_appended() raises:
    var key = hex_decode(_K128)
    var nonce = hex_decode(_IV)
    var aad = hex_decode(_AAD)
    var plain = hex_decode(_P60)
    for gcm in _keys(Span(key)):
        var sealed: List[UInt8] = [0xDE, 0xAD]
        gcm.seal(Span(nonce), Span(aad), Span(plain), sealed)
        assert_equal(len(sealed), 2 + len(plain) + GCM_TAG_LEN)
        assert_equal(hex_encode(Span(sealed)[0:2]), "dead")
        assert_equal(
            hex_encode(Span(sealed)[len(sealed) - GCM_TAG_LEN : len(sealed)]),
            "5bc94fbc3221a5db94fae95ae7121a47",
        )
        var opened: List[UInt8] = [0xBE, 0xEF]
        gcm.open(Span(nonce), Span(aad), Span(sealed)[2 : len(sealed)], opened)
        assert_equal(hex_encode(Span(opened)), "beef" + String(_P60))


def test_copy() raises:
    var key = hex_decode(_ZERO16)
    var nonce = hex_decode(_ZERO12)
    var no_aad = List[UInt8]()
    var no_text = List[UInt8]()
    var first = AesGcm(Span(key))
    var second = first.copy()
    var sealed = List[UInt8]()
    second.seal(Span(nonce), Span(no_aad), Span(no_text), sealed)
    assert_equal(hex_encode(Span(sealed)), "58e2fccefa7e3061367f1d57a4e7455a")
    assert_true(len(sealed) == GCM_TAG_LEN)


def test_wycheproof_aes128() raises:
    # Wycheproof testvectors_v1/aes_gcm_test.json, groups with a 96-bit IV and
    # a 128-bit tag: known-answer, special-case and pseudorandom vectors (empty
    # message, additional data only, additional data up to 257 bytes), then
    # the modified-tag cases. Vectors with a message or
    # additional data of 511 bytes or more are left out to keep this short.
    _wycheproof(
        "1:5b9604fe14eadba931b0ccf34843dab9:028318abc1824029138141a2::001d0c231287c1182784554ca3a21908:26073cc1d851beff176384dc9896d5ff:0a3ea7a5487cb5f7d70fb6c58d038554:v"
    )
    _wycheproof(
        "2:5b9604fe14eadba931b0ccf34843dab9:921d2507fa8007b7bd067d34:00112233445566778899aabbccddeeff:001d0c231287c1182784554ca3a21908:49d8b9783e911913d87094d1f63cc765:1e348ba07cca2cf04c618cb4d43a5b92:v"
    )
    _wycheproof(
        "3:aa023d0478dcb2b2312498293d9a9129:0432bc49ac34412081288127:aac39231129872a2:2035af313d1346ab00154fea78322105:eea945f3d0f98cc0fbab472a0cf24e87:4bb9b4812519dadf9e1232016d068133:v"
    )
    _wycheproof(
        "4:bedcfb5a011ebc84600fcb296c15af0d:438a547a94ea88dce46c6c85::::960247ba5cde02e41a313c4c0136edc3:v"
    )
    _wycheproof(
        "5:384ea416ac3c2f51a76e7d8226346d4e:b30c084727ad1c592ac21d12::35:54:7c1e4ae88bb27e5638343cb9fd3f6337:v"
    )
    _wycheproof(
        "6:cae31cd9f55526eb038241fc44cac1e5:b5e006ded553110e6dc56529::d10989f2c52e94ad:a036ead03193903f:3b626940e0e9f0cbea8e18c437fd6011:v"
    )
    _wycheproof(
        "7:dd6197cd63c963919cf0c273ef6b28bf:ecb0c42f7000ef0e6f95f24d::4dcc1485365866e25ac3f2ca6aba97:8a9992388e735f80ee18f4a63c10ad:1486a91cccf92c9a5b00f7b0e034891c:v"
    )
    _wycheproof(
        "8:ffdf4228361ea1f8165852136b3480f7:0e1666f2dc652f7708fb8f0d::25b12e28ac0ef6ead0226a3b2288c800:f7bd379d130477176b8bb3cb23dbbbaa:1ee6513ce30c7873f59dd4350a588f42:v"
    )
    _wycheproof(
        "9:c15ed227dd2e237ecd087eaaaad19ea4:965ff6643116ac1443a2dec7::fee62fde973fe025ad6b322dcdf3c63fc7:0de51fe4f7f2d1f0f917569f5c6d1b009c:6cd8521422c0177e83ef1b7a845d97db:v"
    )
    _wycheproof(
        "10:a8ee11b26d7ceb7f17eaa1e4b83a2cf6:fbbc04fd6e025b7193eb57f6::c08f085e6a9e0ef3636280c11ecfadf0c1e72919ffc17eaf:7cd9f4e4f365704fff3b9900aa93ba54b672bac554275650:f4eb193241226db017b32ec38ca47217:v"
    )
    _wycheproof(
        "11:28ff3def08179311e2734c6d1c4e2871:32bcb9b569e3b852d37c766a:c3:dfc61a20df8505b53e3cd59f25770d5018add3d6:f58d453212c2c8a436e9283672f579f119122978:5901131d0760c8715901d881fdfd3bc0:v"
    )
    _wycheproof(
        "12:e63a43216c08867210e248859eb5e99c:9c3a4263d983456658aad4b1:834afdc5c737186b:b14da56b0462dc05b871fc815273ff4810f92f4b:bf864616c2347509ca9b10446379b9bdbb3b8f64:a97d25b490390b53c5db91f6ee2a15b8:v"
    )
    _wycheproof(
        "13:38449890234eb8afab0bbf82e2385454:33e90658416e7c1a7c005f11:4020855c66ac4595058395f367201c4c:f762776bf83163b323ca63a6b3adeac1e1357262:a6f2ef3c7ef74a126dd2d5f6673964e27d5b34b6:b8bbdc4f5014bc752c8b4e9b87f650a3:v"
    )
    _wycheproof(
        "14:6a68671dfe323d419894381f85eb63fd:9f0d85b605711f34cd2a35ba:76eb5f147250fa3c12bff0a6e3934a0b16860cf11646773b:0fc67899c3f1bbe196d90f1eca3797389230aa37:bd64802cfebaeb487d3a8f76ce943a37b3472dd5:fce9a5b530c7d7af718be1ec0ae9ed4d:v"
    )
    _wycheproof(
        "15:bb571c160132b0c8d5d190d0bc356ddc:2596c440cf0232950ec66bc4::053be1b6190a717fc74c879e6fd62dc44628495507e50d662271dee795a4ad26e0c4f86cb6b20ac6bd9d682d2d8a05c9dad875a6911b49ea0af4f17c97a5f2:b1cfad142a462f3656e0921627fd41d4f1fa8e2f8bd94bb51fdcf06f606296f7d2885337bed7a4ca6ddb4a9fc7fdb2476b5f7fa5220e1d6752a5e7c31c916c:a231b617352ffdb63d32d69d99e7d629:v"
    )
    _wycheproof(
        "16:e12260fcd355a51a0d01bb1f6fa538c2:5dfc37366f5688275147d3f9::d902deeab175c008329a33bfaccd5c0eb3a6a152a1510e7db04fa0aff7ce4288530db6a80fa7fea582aa7d46d7d56e708d2bb0c5edd3d26648d336c3620ea55e:d33bf6722fc29384fad75f990248b9528e0959aa67ec66869dc3996c67a2d559e7d77ce5955f8cad2a4df5fdc3acccafa7bc0def53d848111256903e5add0420:8bc833de510863b4b432c3cbf45aa7cc:v"
    )
    _wycheproof(
        "17:97ec85a69a05131cd4ff643972f6d8f9:9189e0eedcc413a0ba1e63d2::10acefa6f3959faecb5cfdaee8aaf09d4381b2b147e0b13450c26ee07f29edaa9a1f1af4e2d111dea7ff681a19fc3a4fd66df6a17985b06543a3b6c0e4e51a54b7:eefdf89997244e065ff19ac2374dc92ee76899ddcbe7c834dcc657242fc0f6dd38272373ba9b549316a36f1522e1cab246157875898c966eec563d57eca5c7d32d:23aaa2c6b680fcaaeb2c7a55726d4bc0:v"
    )
    _wycheproof(
        "18:65d38f0b268f180d6ba548d509111dde:e14dfc27394ac846c2373ea7::1fa76d7995dc996a5f5dabaa4be401be14f4d4706a213a4dd725df386ec147a6be074947c733094f47a7222552376740aa8348a0ae1c7f2d972a0ad664f8b8ec81dfc9af078b61daea5dde874fd73775b4cd65acf069ada0b2b9bfbb4a9817ba41d4dcaff7653df5c8cd9ce7f59eec92ae9e61314e03ef48839810ea825520:40dc9b139e888f1811391134b15e914826414a99db512a0632dc4c56d70f7b7991e9945a2025890e951699cf6b2ccee093c9a6a752b98ff696240126759f480299c1dd82aa2c4f462a4a8ad1ad0c7a755f07908c9c0d336d57dbdebc940bbae28ba0336dccaf6bfdc93623686f9487ef0884d100b6b98949afbd4217dc4640:4218d6ac98c0444bc64ecbe1d763136a:v"
    )
    _wycheproof(
        "19:3c55f88e9faa0d68ab50d02b47161276:d767c48d2037b4bd2c231bbd::5d6add48e7a5704e54f9c2829a9b4283dce0d3a65b133eba3793c4fbfa1d8e3a2539d0d4f3de381598ce5b2360173fbd149476c31692c5d6e872fce40219378949c2e70b5f1b9f0a1d5f38352ad814b2a035bb3f3f26425d831a2f7a5e65c5dfcd91a315c2b24f53a662605ea40857dd980e9be5cdad000c569f2d204d4bd3b0:17d72d90bd23e076d8364a87ecb9ac58acc5de4629bfd590409b8bf1fcd3a2f602731b4614cec15e773ea65a65e7210994256bf5450a25acb527269c065f2e2f2279d1fe8b3eda98dcf87b348f1528377bbdd258355d46e035330483d8097e80c7de9bbb606ddf723f2909217ffdd18e8bdbd7b08062f1dcba960e5c0d290f5f:090b8c2ec98e4116186d0e5fbefeb9c2:v"
    )
    _wycheproof(
        "20:62b3881832d428b6f900cacfa0fc5cd8:f4cb98cc99e7bc424a98384e::0b91dd36a6fa967a257b267d12cbc20b56ed615b205d044a04b4ae8aaa365bd29a3b8f47a0828ef63324d1ff924c68090abaaad78df602edee0621b823f94c35ada7b62d81f21dd9945d1abb4ef882cfab12c2e4cec705df3d669183fe681753503a99a871637953537ef479b1f62de7819dbb5c950de7722090942d38129aefa7:00574615883e222657bdf34e9327888f5d532d086581834c62adf54c7fee46927ca27cba193d86c6140b3610a2cd16ba295814b5b7d6a1c8d3f039e0e8f8d7942b0616a9b9f0012884311b0c370f9dd6b9a3d8b6ff36177683c0dd858850dd29993b3eec89a2ab8068038e2c86a2e71b5cacdb38ad69ac0580e29a6f7813c17258:88b99f768364ff9e95a94ccbbc1b166e:v"
    )
    _wycheproof(
        "21:8aeaa2591a452e626b9a6468b623bdfc:b90f446f68aea588d843d01a::f0721c3b68d905092cada6d568df3a2da39573c7bb0e9a4ed159a2634237f9e788488c06fe8a7e1e01d1a1c985543ecf90f3d32e57d33c3df6c165b7edc6fbcf8bf2d043d1b7c0060309a29565a004ea3214d4e4f7dedeac2d74576c019b5fa000d025917af6f86310942102a34d92781972d4f1f57bbdd6f9b08cc979a358aacf6cb62334bfc916c249f18bcee644a8907ef576b41437098bdf0069767fb5ed1c0f1385e5895e4a5d70f5941a93014333436a7af465ec1038fdfa006410a0871225d64848e6c59ac23f176df663ee2171c9eaec0477f9ebd280880d9f2967a2e791cc998f6b23518ca97bbc6405d6ced3373ebf3d208c2a909274460a614a:7bb36313569ff8b5c58e41b17a78fa5d780073bee20b55f004532288e7f0a9475076364d8922d389ecd189f597a8a677cb2484513ed7afe2d0691717cd0ac0e27bf7e2257dd7e4ffc0bbf59e92d258e1116fac9bfc84a2df728bdd7ab221754dd341f7229e030dce06474d00f99a5e457943bd9e8f345bcbb5407690d072dfb0113b64bc0e658eeb7226409a5898dd27d995a0be021f351091f9b907ae3a9625f240dee2bf4bb15eb4f30f4abf1ff25ca5536def969d2588188fecacfc7dc75f5c676ca7851f9e805f498372c6b98f5c7d12403723619f80ce5badfe5844643d5631d4998ee0426a2b29159cae2590dc81646c78be5c9e8ffe056aa0d3552e:fc62295c70d140dbc354fdbc8003eb41:v"
    )
    _wycheproof(
        "22:e88d95eabe88fcf158fae858af951221:a65834a9d231b34709383e9a::2decaccc8b424fa4963890ece15b3fc281b6215780ff6baee57edcd25afe260ff80ed4f25cc04d2802a1e90a2e6e96d1ee73a4a53dcf60025d484054d146f275ab34c33b102001a07d804cc94a40fd78c16780d1b648487fac035386e5d25c2b9edbf7a52d102d1943958c009eb6d88e00a3227c4c788e445003fabb4dbefccd3fe1716d916446fee2111615d560ecc59d7bd288268ab321e7002545887183fe023fdec2a6d3b73b94d1548cee19638d31d2c5a32b15d2aae3f42950a787115e200b00022d4929105da0b4d10ccb0b3886b3169b32ac5df7a637c23362e2d4ed9c137f35bbd578c2cda0377e0f1e64f7d31e9ef4d7603ea1363523758385c761:9b3833c356f83d19f59ac4770c9586aad457810f9dc55112cc6b87e94d8dc71184b227a14500c0a8619d544435db4c001467ef2acba95007299d717fadc0c0717c4c8e748d03ffe2cf2fd06f0009b0e6590f956c212a2c926d5679bdbb79d87636ae9faefa5c8330c570e84b94626f87d6a53b121574f74c9e3211d9451811e9940db5e74d128364328fb8f40f850a25c3e7ba4fdeb0ef6a639060a11d1c32ae0531d2518f905952c9814236b00b9393fd31f8c0522f8e3072b864a3a5cebe1ceb15585c9042f3f5b95390c62d8c1b513550defd21b481fcfbd9fdd6c262ff6ed4e0a6051be309788a763e567107f039e988757f96ad95436792a3bd26f38590:4f4c265edd3158c641ce9555b58650db:v"
    )
    _wycheproof(
        "23:a294e70fa2ac10a1fb00c588b888b673:dfe20d1c4350e6235d987af1::6ed1d7d618d158741f52078006f28494ba72a2454f27160ae8722793fcebc538ebc2f67c3ace3e0fe7c47b9e74e081182b47c930144e3fc80d0ad50611c3afcfe2dbc5279edbbba087c0e390355f3daffcd25ad4dea007c284ad92e7fcbecb438fb60623ff89a599dca2aac141b26651386ca55b739b94901ef6db609c344d8acf4544568e31bb09361112754b1c0c6a3c875bd9453b0ee0081412151398a294ecad75add521611db5288b60ac3c0128f6e94366b69e659e6aa66f058a3a3571064edbb0f05c11e5dde938fb46c3935dd5193a4e5664688f0ae67c29b7cc49a7963140f82e311a20c98cd34fbcab7b4b515ae86557e62099e3fc37b9595c85a75c:5bc6dbafc401101c7a08c81d6c2791aa147ce093aad172be18379c747384a54a41a747ba955cade8fdfb8967aa808b43fee3d757cc80f11163b800e5e59df932757f76c40b3d9cba449aaf11e4f80e003b1f384eafa4f76e81b13c09ec1ad88e7650c750d442fe46d225a373e8a1b564b4915a5c6c513cfdfa22d929d5741ca5ebefaedcba636c7c3bbef18863fdc126b4b451611049c35d814fc2eb7e4b8f1a8995ecb4a3c86652a068c0b2a3e1c5941d59c210b458d5d5d3b06420ec2053465ccceca7c20f67404985460379e2ee806a46e8409dfab2e0dd67ea3cf46d5ad4eb78756827358c3ef1fdbd07c33834f3d9eca3ff13b744a01059a6c17a315a8fd4:c7587e7da41bed682c37377ea4324029:v"
    )
    _wycheproof(
        "27:5a475f9976ed117ab37a4fffab0592eb:6bce45bea6ad59bd2a08f7b3:e8bb51b694b6b0763e097bad1152f5c762a878a3e7f7a9d78e809838de78567900281b7e4f0f185493fd85e28db79b595541aba7e158b3936490b632355d74:dc6ab0e261412cc709422289ea202021d9298060:35d3ab0534102884ed0db4694a221df1bf94dcdb:d78d2c197deb70ed52933f4fa0b09856:v"
    )
    _wycheproof(
        "28:c4b03435b91fc52e09eff27e4dc3fb42:5046e7e08f0747e1efccb09e:75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb1695a5e5a6317b83690ba0538fb11e325ca:8e887b224e8b89c82e9a641cf579e6879e1111c7:b6786812574a254eb43b1cb1d1753564c6b520e9:ad8c09610d508f3d0f03cc523c0d5fcc:v"
    )
    _wycheproof(
        "29:f64d1bc47b081afb21181bdc16ffbcca:2c03293704f79612181609d3:a883d23e25a62b492f1271d3d79b8689dde7250a0575b8175a6b69d48d1b4bc2df1b4dc4a2b1eb506bc0e8c11e7dc2f3d08b475214551df7c53e581ec55c0d0a2d:85b24904bf12ced33d78df7437b36fff83d1e817:b00975863c673f0f19326294ebc4c77f7287c279:ae57622c1d175ebbca77bd4ee812ed89:v"
    )
    _wycheproof(
        "30:7e0e0cf8c9ac58867ef3e3315d0a4338:a03461bd9ffedb16a65c0389:c70f009be65ade8465cc05b5227963c12c60b68247ae2e431b2445bb6aa69c0a7820177861e5f6e3585269fd15efaf38c3713e6af0e93362d2d9a6e3296712f581563ae3980298f8bb7276859afecc7052fef63b060bc8f219ffe200e14dbde1f0a36233b5994a0b68c4690b437d495ddff991993e75039bcba4c19d7a6f01:de4451316ad820471a43906965af9fa221c0360f:8b9dcbd9c9573509d978db0d910e269612c907bf:61ae3afdb06a01d8ee6f7e739ec30a4e:v"
    )
    _wycheproof(
        "31:7e37d56e6b1d0172d40d64d6111dd424:517c55c2ec9bfea90addc2bd:8ed8a9be4c3d32a5098434ee5c0c4fc20f78ef5e25ed8b72a840a463e36b67b881e048b5e49f515b2541ad5ce4ebb3a917c16bcdc0dc3cb52bb4ed5a1dffcf1e1866544e8db103b2ad99c6fa6e7de1d8b45bff57ec872f1cfc78b0e4870f6f200ff1291cae033defc3327ba82792ba438e35c4bfbb684fec5ce5e3ae167d01d7:6a7dea03c1bba70be8c73da47d5ee06d72a27430:cfb631790767d0645d8ec6f23bf7fa8b19ce79ee:c5767ddaa747158446231766bd20490c:v"
    )
    _wycheproof(
        "32:d9218931dc592aef3bffb924c9e0b02c:17d824f4f2f191e9c9dc0a52:76dcb9948575b503fea75cb3d4949bb96ae3d2c1780f185e0fb3cd5b83eb7090be7a966f6146a4db7ef82f8adb9b10158b69d4bb19dffe4c639fe278d0334e68aaf1b68451a8e6778ddbb29aac4b25bcb2ea059601ee2eba439134aecd0ceacd98e388c40114c11969dfd4a16beeaf3d1c7410e99e674894445821e8fcda7b7ba7:29f29bfc5b09ff158d74fbf7532c06aa3afa936c:d0d22cc0893261b105c021f534737599cac3b10d:f55f4ac6d836fc288036a63f53b0ddd4:v"
    )
    _wycheproof(
        "33:bf2056baaf45c5a00a733b49f10b7dd0:fef1b243b44ba92b47c6626b:1bb3a17907279ebff63593de97a64e5ceaf9e1d407e5a5eec1ce0f62586f0dfddb7a3a83fd164e800bcbc6fb089d6a247dfa444633f4663ae1e0bdf37b50a7a01f506e2220bbdd4b08c59fe60e455bdaeda7e5a0cdb2e6dfca66381a72962fa8a6f9847a87135ccf02a40da5b3b8e91e6e1f31542f85f90bce1de05188fe57355329031c66b3fde18bbdcbd2cbec42ea1d0fc803abed2f15c41d2f122674ea91b7280e818acb7549fe63135d2109b4014ec6002745301bd0ac59ca8e4f8d2fb699347b74e17818e3a57fa69c759312dcfde155b2a558a2385c8adab8a6d57f0f497eaf0833e3d930e83fed88c91e18a74c4f5ff45925a2bbdda22f9a4f1196:7e8c2d8a65f539210c047422ae57549195a08393:1fcc05bf4960fd02475c072f9eee8150994edcb9:f3e092f2415f7f0ce88f37a2495dce48:v"
    )
    _wycheproof(
        "34:6f8307bb3d83d67866c2fa5b26f9cade:dfe93ed879e4b391ebbbfd37:1d72720dbbc40333e819a4def81f7bae137d8e52dc010ed901a390bf8c0ab6b435b08ef0184888bc83b14b98b59f6c56afd46131c5627b9e2a44f0a12a9a5356d9090c8b19c94f3f8651d49c74276bd9ae1071cad5f5040fbe1e99124ef44f3f813b13dff958e7331b949193bdf558fd14032c54f0e0ae7ac4d2e6a99d82a5da41135f0543ad377d217152497cf86435d24ee0c75997e3863133d322017aec98050b2fbc1dd8542293ae706889e754daf6ff8c91fb6533c5db7375dd3e365e6a18c546fa9463dfdb21d51c9cf23c9284a63cbfad197f376601101cb2f8a67b6e866569218043cd1745d25ecddf609ce2f9a8f76fb883780a393ea18b7624376b:81ebf69754857be5ad7ddf0062f866421089d136:4d8ff72d859bae1114201c419c098476e74eece9:3b2e9e1b378d707bd2a961bd7811f0c7:v"
    )
    _wycheproof(
        "35:3076741408f734ce25d48f982e8b844b:a2712eac5e06d3cc2864aa8b:18526e4efd995a0bf6405d9f906725c290278958d49554974d8fe025e7860daa225c1285b0573916a4b6741f7cc2e29ce4e525e12f436cb7ce0ad47df3d0f5bd80fb27e47635a4985fdaedf0e821f1c8959985cac49c97a4a02438d92b4afd4c855dcc7ef41ecfc36866334fcc05b2bb93ef13f00c5ea9b921e8a519d77f648e0efe9b5a62305a2ecf7d4999663a6ddfca517f1f36f0899b0bdef9f433c4bb2663c0cc1bb616e7d1949e522bec85485d371d1134c90eede75e865dc7be405b54c33f0acbace6cf780c78035b8035b6ea3f562a8d30a156c199fdafd25be06ee895581195ef125cb4e629e4f18e0bee979d31513896db8466e448e6b4600a316757:414ec6b149e54735302dada888b98b7fdb4c127c:e4d3f4898cb3d9732641d1f8d9d889b2c98af930:76d4fbb69d529b64175b328be00b1068:v"
    )
    _wycheproof(
        "39:00112233445566778899aabbccddeeff:000000000000000000000000::ebd4a3e10cf6d41c50aeae007563b072:f62d84d649e56bc8cfedc5d74a51e2f7:ffffffffffffffffffffffffffffffff:v"
    )
    _wycheproof(
        "40:00112233445566778899aabbccddeeff:ffffffffffffffffffffffff::d593c4d8224f1b100c35e4f6c4006543:431f31e6840931fd95f94bf88296ff69:00000000000000000000000000000000:v"
    )
    _wycheproof(
        "41:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d9847dbc326a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "42:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:da847dbc326a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "43:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:58847dbc326a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "44:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8857dbc326a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "45:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847d3c326a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "46:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc336a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "47:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc306a06e988c77ad3863e6083:i"
    )
    _wycheproof(
        "48:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a066988c77ad3863e6083:i"
    )
    _wycheproof(
        "49:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e989c77ad3863e6083:i"
    )
    _wycheproof(
        "50:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e908c77ad3863e6083:i"
    )
    _wycheproof(
        "51:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988e77ad3863e6083:i"
    )
    _wycheproof(
        "52:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77bd3863e6083:i"
    )
    _wycheproof(
        "53:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3873e6083:i"
    )
    _wycheproof(
        "54:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3843e6083:i"
    )
    _wycheproof(
        "55:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3063e6083:i"
    )
    _wycheproof(
        "56:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3863e6082:i"
    )
    _wycheproof(
        "57:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3863e6081:i"
    )
    _wycheproof(
        "58:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3863e60c3:i"
    )
    _wycheproof(
        "59:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a06e988c77ad3863e6003:i"
    )
    _wycheproof(
        "60:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d9847dbc326a06e989c77ad3863e6083:i"
    )
    _wycheproof(
        "61:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847d3c326a066988c77ad3863e6083:i"
    )
    _wycheproof(
        "62:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d8847dbc326a066988c77ad3863e6003:i"
    )
    _wycheproof(
        "63:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:277b8243cd95f9167738852c79c19f7c:i"
    )
    _wycheproof(
        "64:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:00000000000000000000000000000000:i"
    )
    _wycheproof(
        "65:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:ffffffffffffffffffffffffffffffff:i"
    )
    _wycheproof(
        "66:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:5804fd3cb2ea86690847fa5306bee003:i"
    )
    _wycheproof(
        "67:000102030405060708090a0b0c0d0e0f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:eb156d081ed6b6b55f4612f021d87b39:d9857cbd336b07e889c67bd2873f6182:i"
    )


def test_wycheproof_aes192() raises:
    # The first twelve valid and six modified-tag cases.
    _wycheproof(
        "176:00112233445566778899aabbccddeeff1021324354657687:000000000000000000000000::0b4dbbba8982e0f649f8ba85f3aa061b:3f875c9bd7d8511448459468e398c3b2:ffffffffffffffffffffffffffffffff:v"
    )
    _wycheproof(
        "177:00112233445566778899aabbccddeeff1021324354657687:ffffffffffffffffffffffff::1ae93688ef7e2650a9342ad4718b2780:210dabea4364c6d5b3429e7743322936:00000000000000000000000000000000:v"
    )
    _wycheproof(
        "178:5019eb9fef82e5750b631758f0213e3e5fcca12748b40eb4:ff0ddb0a0d7b36d219da12b5::::7971284e6c9e6aac346fe2b7a0a064c2:v"
    )
    _wycheproof(
        "179:21218af790428f8024d3e7e1428c9fcf578c216636d60e73:34047bc39b9c608384dff5b8::e3:fe:2e982e24b81cd120d35a70fe6935e665:v"
    )
    _wycheproof(
        "180:3a8bf543c480925632118245bcbf5d01522b987a31a33da3:4ebc13cf4636cc7c45e560a7::53fc72e71b59eeb3:99f2ff1c8a44e5f2:6870f104ddc514477b400336fb01860e:v"
    )
    _wycheproof(
        "181:92f4d2672fceec43963ccffb17e6ea7578b11418b06a3b82:6e7ff7f0797685cfc44b05ff::c3ec16adb184affa8ae9738bffb916:afe8ef41591bfcc00db3c880ceb186:29fff7f285768645c9c8bf7a471c9393:v"
    )
    _wycheproof(
        "182:bcb6bc5ee6743df1396a34639327b25809ec9c81dd6a0c0e:be0326d23bdc2c64648d13f4::80474a3a3b809560eee2ce7a7a33ea07:90339dca02ef717f1603994aee6cf6d2:e3d33e01ce64f271783147de226228bc:v"
    )
    _wycheproof(
        "183:5e1d28213e092536525bbae09e214af4c891e202b2b4fa4f:b6be6cd0681235d826aa28ea::53d59433a7db7f41b31ccb6d4a2d789965:b98ed6321679941a3e521834296686ad98:9f50c03e055e519712c582ec9db3235b:v"
    )
    _wycheproof(
        "184:7f672d85e151aa490bc0eec8f66b5e5bee74af11642be3ff:b022067048505b20946216ef::ef6412c72b03c643fa02565a0ae2378a9311c11a84065f80:addd303651119e52f6170dfc7a915064253d57532987b9ab:fa0484f8baa95f5b7a31c56d1b34c58b:v"
    )
    _wycheproof(
        "185:969fed5068541d65418c2c1de8fe1f845e036030496e1272:817fe51c31f2879141a34335:cb:3d8233191a2823bf767e99167b1d4af4f4848458:0d2c3a3c0cc4b40e70ed45e188e356a0e1533b31:92909a80e90540e1878ab59ef300072b:v"
    )
    _wycheproof(
        "186:fa5b9b41f93f8b682c04ba816c3fecc24eec095b04dd7497:62b9cf1e923bc1138d05d205:2ed8487153e21b12:18159841813a69fc0f8f4229e1678da7c9016711:c7c1cbb85ce2a0a3f32cb9ef01ad45ec1118b66d:253317f98bdab87531ece20475cd9ebb:v"
    )
    _wycheproof(
        "187:fbfb395662787e2d25a2e7510f818e825936a35114e237c9:3f1a1e02e90a4ba7a1db9df2:74318d8876528243f1944b73eb77e96e:2952a3d64107d5cbb9602239d05a5c5c222cf72b:ecf5e403f19c007c8da7a456caf0a6d75762829b:e0877a100f9dd9d6795f0e74c56a9fab:v"
    )
    _wycheproof(
        "213:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:b5e44c5b2fe90e4c78f358da0d99cb64:i"
    )
    _wycheproof(
        "214:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:b6e44c5b2fe90e4c78f358da0d99cb64:i"
    )
    _wycheproof(
        "215:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:34e44c5b2fe90e4c78f358da0d99cb64:i"
    )
    _wycheproof(
        "216:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:b4e54c5b2fe90e4c78f358da0d99cb64:i"
    )
    _wycheproof(
        "217:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:b4e44cdb2fe90e4c78f358da0d99cb64:i"
    )
    _wycheproof(
        "218:000102030405060708090a0b0c0d0e0f1011121314151617:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:458256842dfd297f30bd2f8f15c92db0:b4e44c5b2ee90e4c78f358da0d99cb64:i"
    )


def test_wycheproof_aes256() raises:
    # The same selection as for AES-128.
    _wycheproof(
        "91:92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20:00112233445566778899aabb:00000000ffffffff:00010203040506070809:e27abdd2d2a53d2f136b:9a4a2579529301bcfb71c78d4060f52c:v"
    )
    _wycheproof(
        "92:29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123:00112233445566778899aabb:aabbccddeeff:::2a7d77fa526b8250cb296078926b5020:v"
    )
    _wycheproof(
        "93:80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0:4da5bf8dfd5852c1ea12379d::::4771a7c404a472966cea8f73c8bfe17a:v"
    )
    _wycheproof(
        "94:cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273:99e23ec48985bccdeeab60f1::2a:06:633c1e9703ef744ffffb40edf9d14355:v"
    )
    _wycheproof(
        "95:51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152:4f07afedfdc3b6c2361823d3::be3308f72a2c6aed:cf332a12fdee800b:602e8d7c4799d62c140c9bb834876b09:v"
    )
    _wycheproof(
        "96:67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb:68ab7fdbf61901dad461d23c::51f8c1f731ea14acdb210a6d973e07:43fc101bff4b32bfadd3daf57a590e:ec04aacb7148a8b8be44cb7eaf4efa69:v"
    )
    _wycheproof(
        "97:59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a:2fcb1b38a99e71b84740ad9b::549b365af913f3b081131ccb6b825588:f58c16690122d75356907fd96b570fca:28752c20153092818faba2a334640d6e:v"
    )
    _wycheproof(
        "98:3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011:45aaa3e5d16d2d42dc03445d::3ff1514b1c503915918f0c0c31094a6e1f:73a6b6f45f6ccc5131e07f2caa1f2e2f56:2d7379ec1db5952d4e95d30c340b1b1d:v"
    )
    _wycheproof(
        "99:0212a8de5007ed87b33f1a7090b6114f9e08cefd9607f2c276bdcfdbc5ce9cd7:e6b1adf2fd58a8762c65f31b::10f1ecf9c60584665d9ae5efe279e7f7377eea6916d2b111:0843fff52d934fc7a071ea62c0bd351ce85678cde3ea2c9e:7355fde599006715053813ce696237a8:v"
    )
    _wycheproof(
        "100:b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4:98bc2c7438d5cd7665d76f6e:c0:fcc515b294408c8645c9183e3f4ecee5127846d1:eb5500e3825952866d911253f8de860c00831c81:ecb660e1fb0541ec41e8d68a64141b3a:v"
    )
    _wycheproof(
        "101:cdccfe3f46d782ef47df4e72f0c02d9c7f774def970d23486f11a57f54247f17:376187894605a8d45e30de51:956846a209e087ed:e28e0e9f9d22463ac0e42639b530f42102fded75:feca44952447015b5df1f456df8ca4bb4eee2ce2:082e91924deeb77880e1b1c84f9b8d30:v"
    )
    _wycheproof(
        "102:f32364b1d339d82e4f132d8f4a0ec1ff7e746517fa07ef1a7f422f4e25a48194:5a86a50a0e8a179c734b996d:ab2ac7c44c60bdf8228c7884adb20184:43891bccb522b1e72a6b53cf31c074e9d6c2df8e:43dda832e942e286da314daa99bef5071d9d2c78:c3922583476ced575404ddb85dd8cd44:v"
    )
    _wycheproof(
        "103:ff0089ee870a4a39f645b0a5da774f7a5911e9696fc9cad646452c2aa8595a12:bc2a7757d0ce2d8b1f14ccd9:972ab4e06390caae8f99dd6e2187be6c7ff2c08a24be16ef:748b28031621d95ee61812b4b4f47d04c6fc2ff3:a929ee7e67c7a2f91bbcec6389a3caf43ab49305:ebec6774b955e789591c822dab739e12:v"
    )
    _wycheproof(
        "104:6efca98126918ab564d88c6bec02e8998b2be50e3f906ff9adfdd185f373e756:4abd6cfc83bd06b11efaa2a7::bbec79c086d41e602d090f7e40494d6bf3faa1dc6df0ab8a88ea5d35d426b248c2ad880351e223f6170d37cc9655e10459e59cbd6d1c092ed31d72ccc7af20:97b4c73a4d8b5b21bc4b50dbb70dfa77b1a7bf0bbe7cf16ecf5bb60ba8070acc5740780435ed145a62a613dd9881b721168fbb3f5af385ee5d4f856cf93cba:27ac8c4010d8e81b7051ceb06b30fe2d:v"
    )
    _wycheproof(
        "105:5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701:d61040a313ed492823cc065b::d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82:c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf:f15612f6c40f2e0db6dc76fc4822fcfe:v"
    )
    _wycheproof(
        "106:81b6b27e5ed90ab99fe6756d4cb41e3f07269687f5afabdb426e29096b5e4466:13e727486031cca21f733375::9a95a23cfb1e35d89a7597570df0fb0efcbb7429f53bebcbbfa49fa247b251a8508ad497066855d08688576188e4ffb12d1d084dcabec3d57806daf215dcc97edd:7ede7368bca3c93d9f1d7f7750d6e44b1cb92c30e3c9834b0b69efd2470911644ae6f6d75715e13aea8781f8da611a13ac6364c406c1a715b7e97acb22b6e6156e:74e20a93802f43407c8989a37f013802:v"
    )
    _wycheproof(
        "107:ea1d436f6359caec010789fa94fe08b167c3e497d8917282f47ad2a8f95fd0f1:73fe022202767af834e32126::adf9b6df5c5cc9473e0bb579f9a6aad396f93d28bf83e98136f978cfb9d501d09ef778c122b43c876c22e40d74a48d908978465a06be9e80891710c8c2690a762bc9eb8bcb2aa2707db149abafb9c17c1f0b68c7adcea98aebf4c6a39e5a8f693133eaaa5bb0b3708720d7b86424101bad56aa190c67d25fe35a4a34e1f4fd:2e6b19520d9c91e41f523bfd80cb3d577df762879b04a586b865280bac651102fa60164b8586f91c02b2151cc2fd29f4c6e92839cdd873be12c1443141f8bcb8754965aec7c0829fb391e56563ba76e896ec81932b5efbad23bb965ebbf8d8fda98f9cbd48f37b2c46db609e40768266c2b36a7810d2b79133f377d0377b41:f9a0eba513904c4a7168d762000f34be:v"
    )
    _wycheproof(
        "108:d7addd3889fadf8c893eee14ba2b7ea5bf56b449904869615bd05d5f114cf377:8a3ad26b28cd13ba6504e260::c877a76bf595560772167c6e3bcc705305db9c6fcbeb90f4fea85116038bc53c3fa5b4b4ea0de5cc534fbe1cf9ae44824c6c2c0a5c885bd8c3cdc906f12675737e434b983e1e231a52a275db5fb1a0cac6a07b3b7dcb19482a5d3b06a9317a54826cea6b36fce452fa9b5475e2aaf25499499d8a8932a19eb987c903bd8502fe:53cc8c920a85d1accb88636d08bbe4869bfdd96f437b2ec944512173a9c0fe7a47f8434133989ba77dda561b7e3701b9a83c3ba7660c666ba59fef96598eb621544c63806d509ac47697412f9564eb0a2e1f72f6599f5666af34cffca06573ffb4f47b02f59f21c64363daecb977b4415f19fdda3c9aae5066a57b669ffaa257:5e63374b519e6c3608321943d790cf9a:v"
    )
    _wycheproof(
        "109:7f7c5804a680f61924966725dba2a80d85267c2e03c7c234b045b24ec8e23528:2d9bf8b636f337d265b0904c::e2f85fb176840c38345da0f0f8db6cdbc45a123165f244ff5389fe65bf341fa131130751b5c739a9931d5a57b141dc7b5b0c5a2ca07331c2dc04b2657b0289878dea0ef7d5601465b78a65795f0f3181304e58a261feb1d394f3c33cabae189941755d7654bb7bef08c31bd2c5ce1203eebc015ae040da2a851c2ba3c62e699356:d7380d10b22c3ae584531e9e4ee73d387f69dbbb3d3d9fdb4971ed2750b31913f79e4c00cf1b76933bbb75d39d8a6429a2528e9bd60e65fa6ffff9e01a8758e7b58409fa3f370cc32a63aa60a54c36d733e8f6dfccd5c3120d05c6e33140c00562865532b2c689de98769d3386e7a3ae679e404e062536ca046261211a426fb586:753f6c57c0cc2a075e68d082f6e83590:v"
    )
    _wycheproof(
        "110:01e75ae803d3045e6b28b7f67937eee2d8d98f77b4892d48ab1f15f57fa88bbe:6902e8f0ef1e9ec60a3e46f0::32dde3b9bc671fad1265b26cad3d8dd0f099134f6755f98613024e1bd10da9a62bad01a997f973101e855ee1c7e60e6b6aa1df9d80fa567d0ccca0f956680be76ed37c71fdedef560e2523e8c5fdb9516250017304f8ff416b9b8e5d17c1f062ded4616ea9d462ed6ca0dfddb9f5295b7a127c0825ffab56ea4983c01eec867f93e24a18be48ceb540986c530104fd466318eb812eb42fd04355615f92503e53799742cdc71830eaa44aeec914b6ff1cbb4f6f81ab595078331d645c8d083b469731174a706b1666e5e450cb62671067032a566f597b9866b71514a409e38fcabe844964581b3ab5152696b76e49ace66581d21f512e28e077c44948a65260:6323ddbf9eb0463714d5857d1841a9f65529516c2f412956bc835f4f252d22a2ce743f21767fcb28859882b570ca053970b72e86f451ff0c77e87f3a03c0536b3859394fce324442ac197874f81a2ce649b99feb442e23123f7ab361d2ce6768a1badb30c509e79bee9277d378fadaa64e77e26f726df86110526530cd439429b017ae2bcec8cc24f994f5885a8a76fab6339c7054df76aa6f450193a635d21d22f71f1ae6856036e6caaeed8840bbfbc8236c25a31e775cba5f6e189fcbc3e96970ca5378fd5c29a712f5dc17641ad88ab566d8c78fff1bb57f9b2f7c9db838b4307c63e04a73d3ef8121f48932ec318dffaead58a83a7f79bc44a1587990:0c92bb5291e981bf562293877f4ddb5f:v"
    )
    _wycheproof(
        "111:dc4dbf811f9509e33a45a8a0743e9391de333f69c56ee4f0fe90ce21c238ee59:1859d3ba4710cdd300baa029::df91c48591f4cae8c4d659d024dfd0a3535981487764bf19b012713e6ac6d578aa0b3a51d7ac97cd503fdc8682cabdb6a5256e9890458356f39b9749f6ab158112fbe4f91acd333477998b9f0d7cc0be2d40acfa5103adc1b0d0a5cc94733d703e0d8c26e09e9d079fa6a65cf35240a16280826ab7c0d8ac5882c89e58444233c2f60aaae0cbd1a7ed850065242a9378c340232fd86f1fd52a92c960a9a86f529f431acf3aa94133785803f4ac1a22378332daa22dea3d34d2fdb7c308fa44ab93b3fb02f428be22fad6c0b10c138af97b92a199296dd947c93fbc40674c34c5623d26d9c90dc6b3357018b9f9250fb4dd5c11518191a236745a2bd42f863766:9c511d08f244cb6971a39b70639c4a53ae48254fcb3d2eea4796ecc996f1fe26a8e30932258a48fe4237e5bfb0e1320dc591256dc83cd56dbf5d9b377b7805b7fac0497b2f99e3310e9e2cc8009141a82f26f8a02299d64138bb1fe8a1243df3e9fb37b52bd3c2cc19f543b3f4928e5a73730a7a6e6d75919d117d3dfe10e863a9846b2ca260de5dddba7ceac37019e615b89a2ab94df8d1a790749998cb8531fef1ef5f8a28a8ad60e813f7e78412ca4d95b9604a24a16e4a3ca8ee33bfbb7809048014943e5fd7966a7db214e052d1cc546a6da72ec89d1c3398aefdcb881dfc3d800b7323abcd7583e9c8a31f03b6995d4aeac17c5a56d8af492a2b108fe3:17090ce50e35244a59bafc80eba5dae5:v"
    )
    _wycheproof(
        "112:317ba331307f3a3d3d82ee1fdab70f62a155af14daf631307a61b187d413e533:a6687cf508356b174625deaa::32c1d09107c599d3cce4e782179c966c6ef963689d45351dbe0f6f881db273e54db76fc48fdc5d30f089da838301a5f924bba3c044e19b3ed5aa6be87118554004ca30e0324337d987839412bf8f8bbdd537205d4b0e2120e965373235d6cbd2fb3776ba0a384ec1d9b7c631a0379ff997c3f974a6f7bbf4fd23016211f5fc10acadb5e400d2ff0fdfd193f5c6fc6d4f7271dfd1349ed80fbedaebb155b9b02fb3074495d55f9a2455f59bf6f113191a029c6b0ba75d97cdc0c84f131836337f29f9d96ca448eec0cc46d1ca8b3735661979d83302fec08fffcf5e58f12b1e7050657b1b97c64a4e07e317f554f8310b6ccb49f36d48c57816d24952aada711d4f:d7eebc9587aa21136fa38b41cf0e2db03a7ea2ba9eaddf83d33f781093617bf50f49b2bfe2f7173b113912e2e1775f40edfed8b3b0099b9e1c220dd103be6166210b01029feb24ed9e20614eddc3cebe41b0079a9a8c117b596c90288effd3796fbd0c7e8eab00609a64be3ad9597cdbf3a818c260cd938bdf232e4059ae35a2571a838887fc196912179486e046a62227a4caddce38cbbc37587bb9439ec637602b6818c5cbe3c71a7c4143960533dc74174bd315c8db227b69b55bb7fc30ba1d5213a752ec33925043cefbc1a62943ee5f34d5da01799e69094d732aef52f8e036980d0070e22e173c67c4bbcca61cc1eedbd6016516c592144819df13204dee:bf0540d34b20f761101bc608b02458f2:v"
    )
    _wycheproof(
        "116:0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04:7147973339d86789a2c9a958:37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c61e6e946c504f348296918219e51bf2c5598589cff:102e5804dda1fb5d656077edb15cadb5d0bdee8c:618ac626ae0e8d06c2fd2fb66be253dc26ed6e38:d8d93ff975cb988f09174dcd439cb6a4:v"
    )
    _wycheproof(
        "117:2ce6b4c15f85fb2da5cc6c269491eef281980309181249ebf2832bd6d0732d0b:c064fae9173b173fd6f11f34:498d3075b09fed998280583d61bb36b6ce41f130063b80824d1586e143d349b126b16aa10fe57343ed223d6364ee602257fe313a7fc9bf9088f027795b8dc1d3:f8a27a4baf00dc0555d222f2fa4fb42dc666ea3c:aed58d8a252f740dba4bf6d36773bd5b41234bba:01f93d7456aa184ebb49bea472b6d65d:v"
    )
    _wycheproof(
        "118:52350da5a572911ee0e0fcedb115af6f4570fbf9c74a11bc184444d6a621d60f:d68ad045c1b9c2923cf5404c:03a94b3841292d9bbf72f413c09167c54ee10537c049afe2bbcec43b18f3890b2fcdd3bb31e6d709274e199c0c4648eb3d8b38e0c1bf7f309443bef6937cde4123:4e6e6dad2c16cfc6e7cac03636a4a6d88bd6a13e:c7764411be13cfeaaece761bd3bb13552f088048:bcc2544e79f34ea1076a12b76441d6fa:v"
    )
    _wycheproof(
        "119:d058304c0ba039b2e2d08661fd8f6db88779bd5ce580eb766c1d6ab34b94ee94:3c553397fafda0eb06a59f23:cfb1fe1c47e2450109eaed4e1aac9431aa5db1e3b7eeacad3ebc9e8e1f3e0a823f757f619761e61ad05af8cef83104890940cd592137eb7ba5879b95759c8be1525f9a01fc01582d93a2a841336a104d169968c274b5a8c30883b4bd621725f69079bb94a174a3c94db62f2ae746d03200f01c19aaa8a3b89e78b99a62f76f:0a064cd5e49845c4efb60fb343dc03faffa36c49:a7d84ff71dc713161359b757af42c74dddbf53ce:736e48a2b7792acc599baa651629a203:v"
    )
    _wycheproof(
        "120:44c8d0cdb8f7e736cfd997c872a5d9c5ef30afbe44b6566606b90aa5e3e8b797:6f39afba021e4c36eb92962e:98d1ca1788cbeb300ea5c6b1eec95eb2347177201400913d45225622b6273eec8a74c3f12c8d5248dabee586229786ff192c4df0c79547f7ad6a92d78d9f8952758635783add2a5977d386e0aef76482211d2c3ae98de4baadb3f8b35b510464755dc75ceb2bf25b233317523f399a6c507db214f085fa2818f0d3702b10952b:2e6f40f9d3725836ac0c858177938fd67be19432:b42428f8094ef7e65c9e8c45ef3e95c28ce07d72:32b25dfbb896d0f9d79c823bdd8e5d06:v"
    )
    _wycheproof(
        "121:e27e718e4b66c91e221f2a3df9da0013f7e14340006eca50dc30c4cc2ddeb679:b46fed185e8b33215dd474dd:2d2b6247f9c342f8d0432ce0715749d0bac0e2e3f28b785be8dc84b3a0e57a161afde34227277512204ffa4bceb6e0a4d021031b765540f7f613045f74e7e6e4977c04b78b5d3f8d4e420a9748c12d1f9aa5e03a27749be2785dd555a8cf0182c0826f2d60eed3c4059adf8872f3c4d81a963592472965cc0c66102167e4cb1ca2:e39aeaf1d214f78915601fee9a3527d777674651:750232115a5edea7b249a22c0cdae17f725d6f99:4a72d8c30fc7e0f1806d9a817adae14a:v"
    )
    _wycheproof(
        "122:fc1bfd0b58515c4e7906e2052596bb92de8c879806af47a4c726ff08c9ba47cc:f3da3be574337b8f8c052866:d26f7ff887725228f3109924ed9eaeaa8c103cfcaac1d6e3874d11afd8424fd030fea80547212fe7c8ac9f4ecbe304b62e5bb206ac3a8318a819b9701f494aefd22e84d227922102f5130f0685e88e25115c3ab9e8bb290c0df0715c4adb00a2ecc9bab5bbcc49cec60305a5b04f646b1d0f951673cf1eb4742c1a52beb2cd2f43a2e413e4a9f5679123b4d59f2ae14c27ee84e970cafcbb5a0736ad2636833cb644c9f2fb61a4a09fad511f4c1781c5685f94814d242c5e3eb4abe165732ab0258a2461c56d452ef1cf48b4ff0f331b91c2c71ce1c03877552837a12dfe75f78bf1cd615b3b2b864fd9503a5f5bea652870bce4cad5c726f1c512dae7f5f8:9adfced8e23f7897b66efcc3468d63b87da79a24:1875d3d76930b58361103d64220591feaad5c9a2:223099bb16c30cba134e639ed95615b7:v"
    )
    _wycheproof(
        "123:7ec20e38aa1b1f018d79903fc1cf6e260cec3733a19ad9e30f60b54e2ea6ebcc:5ccd9cdcf97ac61364687bbb:d9d2ee145b5c31a17dce932538c7e45da1c82abb80b0553251e442dbc5af9c126d3a76a24767c39b229bec8976a0df89fa70ea9ad872aa36d6b8b09aaa54698e7f29c2c2d12efb0b301cfb97076473dfa7ec030350e26839fbb7e1612dad93ff08e1119168c5fca56816c62b042f06d89e5a95da6a615e13ba4cad9f942534c539520d00509d0d4ac6d80c59e769d7e1aa7e12987ee05fb6a19b383c3348df6cbdcff604ef218338910a8e275d9a62b802cb07ec9249c9635e2437f8339dff3e21f79e9eb2acc2bbbadd520a84c58f0ddaaf8c32496d173b6b8c0c274352d40d47bfbd93069abdcc3d21c2cd330a8c16847f0e5299beb6a2d33be746de5c71f2:bab28e0987509b1d6f9cf3aa90030795f125ee44:ce4c58d3c7354d2d27e3bb41a62e5941fb1e39f3:e177391d5e2cefa2f7d35e33a76566aa:v"
    )
    _wycheproof(
        "124:e40003d6e08ab80b4bfc8400ef112945a901ec64a1b6536ca92665090d608bc4:9f095dafe6f6e0fbafbbe02e:422d5efcffe364905984533f0a579d80b18bda7b29e6e46498effba53c350112c0bbb8dc4ce03bb0c69e1d0baa19f0637108aa4a16b09a281f232839d87b6d0e42be1baa7c67f1be970ea169d3960b9fe0a61f11cd2eb7398c19e641feb43f778e257a397063db5b3a6707e9db62387054f9f9d44f143583e63edad45a00251e5173d7505f22a8bce232e56c2c276a58033ae30d5dbf4e35a862e42af573be38c6406d9b4c7acbf275fe36c0ecf2c4642898a30e6146fac992a16405f98312126b7a3722f5dfb7dd4e4911c1426b2e01d04e9be6db3771100f7d7d4282e4ea585f3646241e807ca64f06a7fa9b7003d710b801d66f517d2d5ebd740872deba13d0:38c3f44bc5765de1f3d1c3684cd09cddefaf298d:d4a79f729487935950ec032e690ab8fe25c4158e:876d2f334f47968b10c103859d436db8:v"
    )
    _wycheproof(
        "128:00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f:000000000000000000000000::561008fa07a68f5c61285cd013464eaf:23293e9b07ca7d1b0cae7cc489a973b3:ffffffffffffffffffffffffffffffff:v"
    )
    _wycheproof(
        "129:00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f:ffffffffffffffffffffffff::c6152244cea1978d3e0bc274cf8c0b3b:7cb6fc7c6abc009efe9551a99f36a421:00000000000000000000000000000000:v"
    )
    _wycheproof(
        "130:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9de8fef6d8ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "131:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ee8fef6d8ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "132:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:1ce8fef6d8ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "133:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce9fef6d8ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "134:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fe76d8ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "135:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d9ab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "136:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6daab1bf1bf887232eab590dd:i"
    )
    _wycheproof(
        "137:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1b71bf887232eab590dd:i"
    )
    _wycheproof(
        "138:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1be887232eab590dd:i"
    )
    _wycheproof(
        "139:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf13f887232eab590dd:i"
    )
    _wycheproof(
        "140:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bfa87232eab590dd:i"
    )
    _wycheproof(
        "141:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887332eab590dd:i"
    )
    _wycheproof(
        "142:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232ebb590dd:i"
    )
    _wycheproof(
        "143:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232e8b590dd:i"
    )
    _wycheproof(
        "144:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf8872326ab590dd:i"
    )
    _wycheproof(
        "145:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232eab590dc:i"
    )
    _wycheproof(
        "146:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232eab590df:i"
    )
    _wycheproof(
        "147:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232eab5909d:i"
    )
    _wycheproof(
        "148:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1bf1bf887232eab5905d:i"
    )
    _wycheproof(
        "149:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9de8fef6d8ab1bf1be887232eab590dd:i"
    )
    _wycheproof(
        "150:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fe76d8ab1b71bf887232eab590dd:i"
    )
    _wycheproof(
        "151:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9ce8fef6d8ab1b71bf887232eab5905d:i"
    )
    _wycheproof(
        "152:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:631701092754e40e40778dcd154a6f22:i"
    )
    _wycheproof(
        "153:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:00000000000000000000000000000000:i"
    )
    _wycheproof(
        "154:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:ffffffffffffffffffffffffffffffff:i"
    )
    _wycheproof(
        "155:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:1c687e76582b9b713f08f2b26a35105d:i"
    )
    _wycheproof(
        "156:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:505152535455565758595a5b::202122232425262728292a2b2c2d2e2f:b2061457c0759fc1749f174ee1ccadfa:9de9fff7d9aa1af0be897333ebb491dc:i"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
