from nethernet.crypto.ecdsa_der import ecdsa_signature_from_der
from nethernet.crypto.p256 import (
    P256_POINT_LEN,
    P256_SCALAR_LEN,
    P256_SIGNATURE_LEN,
    p256_ecdh,
    p256_private_key_from_bytes,
    p256_public_key,
    p256_sign,
    p256_verify,
)
from nethernet.crypto.sha256 import sha256
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _stream(label: StringSpan, count: Int) -> List[UInt8]:
    # Deterministic test bytes: SHA-256(label || counter), concatenated.
    var out = List[UInt8](capacity=count)
    var counter = UInt8(0)
    while len(out) < count:
        var block = bytes_of(label)
        block.append(counter)
        var digest = sha256(Span(block))
        for byte in digest:
            if len(out) < count:
                out.append(byte)
        counter += 1
    return out^


def _public_hex(private_key: StringSpan) raises -> String:
    var d = hex_decode(private_key)
    var point = p256_public_key(Span(d))
    return hex_encode(Span(point))


def _public_fails(private_key: StringSpan) raises -> Bool:
    var d = hex_decode(private_key)
    try:
        _ = p256_public_key(Span(d))
        return False
    except e:
        return True


def _sign_fails(private_key: StringSpan) raises -> Bool:
    var d = hex_decode(private_key)
    var digest = _stream("digest", 32)
    try:
        _ = p256_sign(Span(d), Span(digest))
        return False
    except e:
        return True


def _ecdh_hex(private_key: StringSpan, public_key: StringSpan) raises -> String:
    # The shared secret in hex, or "error" if the function raised.
    var d = hex_decode(private_key)
    var point = hex_decode(public_key)
    try:
        var shared = p256_ecdh(Span(d), Span(point))
        return hex_encode(Span(shared))
    except e:
        return "error"


def _derive_hex(seed: StringSpan) raises -> String:
    var bytes = hex_decode(seed)
    var d = p256_private_key_from_bytes(Span(bytes))
    return hex_encode(Span(d))


def _verify_hex(
    public_key: StringSpan, digest: StringSpan, signature: StringSpan
) raises -> Bool:
    var key = hex_decode(public_key)
    var d = hex_decode(digest)
    var sig = hex_decode(signature)
    return p256_verify(Span(key), Span(d), Span(sig))


def _check_message(
    label: StringSpan,
    public_key: StringSpan,
    message: StringSpan,
    signature: StringSpan,
    valid: Bool,
) raises:
    # Verifies a raw signature over SHA-256(message).
    var key = hex_decode(public_key)
    var msg = hex_decode(message)
    var sig = hex_decode(signature)
    var digest = sha256(Span(msg))
    assert_equal(
        p256_verify(Span(key), Span(digest), Span(sig)),
        valid,
        msg=String(label),
    )


def _check_der_message(
    label: StringSpan,
    public_key: StringSpan,
    message: StringSpan,
    der: StringSpan,
    valid: Bool,
) raises:
    # As TLS does: strict DER decoding first, then verification.
    var key = hex_decode(public_key)
    var msg = hex_decode(message)
    var encoded = hex_decode(der)
    var digest = sha256(Span(msg))
    var ok: Bool
    try:
        var sig = ecdsa_signature_from_der(Span(encoded), P256_SCALAR_LEN)
        ok = p256_verify(Span(key), Span(digest), Span(sig))
    except e:
        ok = False
    assert_equal(ok, valid, msg=String(label))


def test_lengths() raises:
    assert_equal(P256_SCALAR_LEN, 32)
    assert_equal(P256_POINT_LEN, 65)
    assert_equal(P256_SIGNATURE_LEN, 64)


def test_rfc6979_key_and_signatures() raises:
    # RFC 6979 A.2.5: key pair and the SHA-256 signatures.
    var private_key = hex_decode(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    )
    var public_key = p256_public_key(Span(private_key))
    assert_equal(
        hex_encode(Span(public_key)),
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    )
    var sample = bytes_of("sample")
    var sample_digest = sha256(Span(sample))
    var sample_sig = p256_sign(Span(private_key), Span(sample_digest))
    assert_equal(
        hex_encode(Span(sample_sig)),
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    )
    assert_true(
        p256_verify(Span(public_key), Span(sample_digest), Span(sample_sig))
    )
    var test = bytes_of("test")
    var test_digest = sha256(Span(test))
    var test_sig = p256_sign(Span(private_key), Span(test_digest))
    assert_equal(
        hex_encode(Span(test_sig)),
        "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    )
    assert_true(
        p256_verify(Span(public_key), Span(test_digest), Span(test_sig))
    )
    # Each signature belongs to its own message only.
    assert_false(
        p256_verify(Span(public_key), Span(test_digest), Span(sample_sig))
    )
    assert_false(
        p256_verify(Span(public_key), Span(sample_digest), Span(test_sig))
    )


def test_rfc5903_ecdh() raises:
    # RFC 5903 section 8.1.
    var i = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433"
    var gi = "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"
    var r = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53"
    var gr = "04d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"
    var shared = (
        "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
    )
    assert_equal(_public_hex(i), gi)
    assert_equal(_public_hex(r), gr)
    assert_equal(_ecdh_hex(i, gr), shared)
    assert_equal(_ecdh_hex(r, gi), shared)


def test_cavp_key_pairs() raises:
    # NIST CAVP 186-3 KeyPair.rsp.
    assert_equal(
        _public_hex(
            "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357"
        ),
        "04d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f",
    )
    assert_equal(
        _public_hex(
            "710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d"
        ),
        "04f6836a8add91cb182d8d258dda6680690eb724a66dc3bb60d2322565c39e4ab91f837aa32864870cb8e8d0ac2ff31f824e7beddc4bb7ad72c173ad974b289dc2",
    )
    assert_equal(
        _public_hex(
            "78d5d8b7b3e2c16b3e37e7e63becd8ceff61e2ce618757f514620ada8a11f6e4"
        ),
        "0476711126cbb2af4f6a5fe5665dad4c88d27b6cb018879e03e54f779f203a854ea26df39960ab5248fd3620fd018398e788bd89a3cea509b352452b69811e6856",
    )
    assert_equal(
        _public_hex(
            "2a61a0703860585fe17420c244e1de5a6ac8c25146b208ef88ad51ae34c8cb8c"
        ),
        "04e1aa7196ceeac088aaddeeba037abb18f67e1b55c0a5c4e71ec70ad666fcddc8d7d35bdce6dedc5de98a7ecb27a9cd066a08f586a733b59f5a2cdb54f971d5c8",
    )
    assert_equal(
        _public_hex(
            "01b965b45ff386f28c121c077f1d7b2710acc6b0cb58d8662d549391dcf5a883"
        ),
        "041f038c5422e88eec9e88b815e8f6b3e50852333fc423134348fc7d79ef8e8a1043a047cb20e94b4ffb361ef68952b004c0700b2962e0c0635a70269bc789b849",
    )


def test_cavp_public_key_validation() raises:
    # NIST CAVP 186-3 PKV.rsp. ECDH with the private key 1 returns the
    # x-coordinate of a point that passes validation. Coordinates that
    # do not fit in 32 bytes cannot be encoded and are left out.
    var one = "0000000000000000000000000000000000000000000000000000000000000001"
    # P (0 )
    assert_equal(
        _ecdh_hex(
            one,
            "04e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b786d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0",
        ),
        "e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7",
    )
    # F (2 - Point not on curve)
    assert_equal(
        _ecdh_hex(
            one,
            "04f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc1227332bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd",
        ),
        "error",
    )
    # P (0 )
    assert_equal(
        _ecdh_hex(
            one,
            "042c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525daced9783713a8a2a09eff366987639c625753295d9a85d0f5325e32dedbcada0b",
        ),
        "2c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525da",
    )
    # F (2 - Point not on curve)
    assert_equal(
        _ecdh_hex(
            one,
            "04a40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3",
        ),
        "error",
    )
    # P (0 )
    assert_equal(
        _ecdh_hex(
            one,
            "042633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0ad6b2f738e3873cc8364a2d364038ce7d0798bb092e3dd77cbdae7c263ba618d2",
        ),
        "2633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0a",
    )
    # P (0 )
    assert_equal(
        _ecdh_hex(
            one,
            "042fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f15b994346137988c58c14ae2152ac2f6ad96d97decb33099bd8a0210114cd1141",
        ),
        "2fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f1",
    )
    # F (2 - Point not on curve)
    assert_equal(
        _ecdh_hex(
            one,
            "04f8c6dd3181a76aa0e36c2790bba47041acbe7b1e473ff71eee39a824dc595ff09c965f227f281b3072b95b8daf29e88b35284f3574462e268e529bbdc50e9e52",
        ),
        "error",
    )
    # F (2 - Point not on curve)
    assert_equal(
        _ecdh_hex(
            one,
            "047a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be3808862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb",
        ),
        "error",
    )


def test_cavp_signature_verification() raises:
    # NIST CAVP 186-3 SigVer.rsp, [P-256,SHA-256].
    _check_message(
        "SigVer 0: F (3 - S changed)",
        "0487f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9",
        "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
        "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6",
        False,
    )
    _check_message(
        "SigVer 1: F (2 - R changed)",
        "045cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85",
        "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
        "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c",
        False,
    )
    _check_message(
        "SigVer 2: F (4 - Q changed)",
        "042ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64",
        "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
        "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda89467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc",
        False,
    )
    _check_message(
        "SigVer 3: P (0 )",
        "04e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
        "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
        "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
        True,
    )
    _check_message(
        "SigVer 4: P (0 )",
        "04e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d28647f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a",
        "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08",
        "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a",
        True,
    )
    _check_message(
        "SigVer 5: F (2 - R changed)",
        "04a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad86bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b471",
        "666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2b263ff6cb837bd04399de3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a282572bd01d0f41e3fd066e3021575f0fa04f27b700d5b7ddddf50965993c3f9c7118ed78888da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548",
        "25acc3aa9d9e84c7abf08f73fa4195acc506491d6fc37cb9074528a7db87b9d69b21d5b5259ed3f2ef07dfec6cc90d3a37855d1ce122a85ba6a333f307d31537",
        False,
    )
    _check_message(
        "SigVer 6: F (4 - Q changed)",
        "043dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5dff22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1bb",
        "7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f894edcbbc57b34ce37089c0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25b8e32fcf05b76d644573a6df4ad1dfea707b479d97237a346f1ec632ea5660efb57e8717a8628d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd",
        "548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5ae93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75",
        False,
    )
    _check_message(
        "SigVer 7: F (1 - Message changed)",
        "0469b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f",
        "1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f22d88c353965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169",
        "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979",
        False,
    )
    _check_message(
        "SigVer 8: F (3 - S changed)",
        "04bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc682069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba03",
        "3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076115c7043ab8733403cd69c7d14c212c655c07b43a7c71b9a4cffe22c2684788ec6870dc2013f269172c822256f9e7cc674791bf2d8486c0f5684283e1649576efc982ede17c7b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970",
        "f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d",
        False,
    )
    _check_message(
        "SigVer 9: F (2 - R changed)",
        "04224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9de178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2b9",
        "983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312a2ad418fe69dbc61db230cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd9644f828ffec538abc383d0e92326d1c88c55e1f46a668a039beaa1be631a89129938c00a81a3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c",
        "87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d24044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66",
        False,
    )
    _check_message(
        "SigVer 10: F (3 - S changed)",
        "0443691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a066228369f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9ccac",
        "4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac287339e043b4ffa79528faf199dc917f7b066ad65505dab0e11e6948515052ce20cfdb892ffb8aa9bf3f1aa5be30a5bbe85823bddf70b39fd7ebd4a93a2f75472c1d4f606247a9821f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af",
        "8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1cecfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154",
        False,
    )
    _check_message(
        "SigVer 11: F (1 - Message changed)",
        "049157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb596972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e8296405",
        "0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db0718239de700785581514321c6440a4bbaea4c76fa47401e151e68cb6c29017f0bce4631290af5ea5e2bf3ed742ae110b04ade83a5dbd7358f29a85938e23d87ac8233072b79c94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216",
        "dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2",
        False,
    )
    _check_message(
        "SigVer 12: F (4 - Q changed)",
        "04072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfdda9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8f5",
        "785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc28581dce51f490b30fa73dc9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c60fa720ef4ef1c5d2998f40570ae2a870ef3e894c2bc617d8a1dc85c3c55774928c38789b4e661349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e",
        "09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d",
        False,
    )
    _check_message(
        "SigVer 13: F (1 - Message changed)",
        "0409308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c24f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8ee5",
        "76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e7229ef8cd72ad58b1d2d20298539d6347dd5598812bc65323aceaf05228f738b5ad3e8d9fe4100fd767c2f098c77cb99c2992843ba3eed91d32444f3b6db6cd212dd4e5609548f4bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca",
        "5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e739c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7",
        False,
    )
    _check_message(
        "SigVer 14: P (0 )",
        "042d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b6d9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e230a",
        "60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855dbe435acf7882e84f3c7857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddbd1c211fbc2e6d884cddd7cb9d90d5bf4a7311b83f352508033812c776a0e00c003c7e0d628e50736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84",
        "06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c1795962b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce",
        True,
    )


def test_cavp_ecdh() raises:
    # NIST CAVP KAS ECC validity test, static unified model, Z only.
    # F (2 - CAVS's Static public key Y fails PKV 5.6.2.5)
    assert_equal(
        _ecdh_hex(
            "72cc52808f294b64b6f7233c3d2f5d96cc1d29287320e39e1c151deef0bc14eb",
            "04202cb5a224e6c2a84e624094486edf04116c8d68ec1f4a0e0ed9ee090e1a900bcacf3a5789bb33954be600425d62d9eae5371f90f88167258814213e4a4f4b1a",
        ),
        "error",
    )
    # F (1 - CAVS's Static public key X fails PKV 5.6.2.5)
    assert_equal(
        _ecdh_hex(
            "fecbeddcbb8c104ba194c31d539a94a193f9f9fad48bc618023a1f2bfee058ea",
            "042a76d1b52ecc5683fba272bdeff3895878f04c467be1e658be52d6e05bbacb0c03b382191e99deaf8c5d0087cc6238bf54dbf54fe9a9eb1102804e5b87e67186",
        ),
        "error",
    )
    # P (0 - Correct)
    assert_equal(
        _ecdh_hex(
            "8087ab163864bfa81001c72f736b6d94e7612559ac4c847d06ba2171840684d6",
            "045a3955c54a49645ed818f3774ea10971a1db88c370d8966c5a6e88234ed5d82003b13f0dad73f64532f42b8b2fa6d1450d9ab24896e95c24674298f2da07ccda",
        ),
        "0cb890a0dcc277c3dde0f91b4322a32e6365d7ec85316185d3286b4977849410",
    )
    # P (0 - Correct)
    assert_equal(
        _ecdh_hex(
            "64e23f7a2d279930f1de66b4bc147786b168d059f581268c24f6650362246e63",
            "04acbcb31f5f6798a00f28aa4a634873744768db612925336efca98122a76d1b5e7dcefeb3ccb530029a8b62e5a7f00c42fc7ebeac8f469c289ea77b6186d661f0",
        ),
        "f70e4fc9ba68aafe07be1767620e64dd5e5bb7ab279f0657465cddeb69e36fa9",
    )
    # P (0 - Correct)
    assert_equal(
        _ecdh_hex(
            "8171000763de347d0eb650dd6fddac2ad48ec122c162d66c3df257aea13192fb",
            "04758b2f0e79a3d0a94f521ae31dcff50fabd394bb4bbec8fa37d1566f463444e7b981e686e53e9e9dc2e3f263e810c89b4c271e62392f59ed45ed30ac3a5bfd33",
        ),
        "5cbea453310285b22f128178bd09b906fde9e660b5a17a7cec809a5a9a1e9287",
    )
    # P (0 - Correct)
    assert_equal(
        _ecdh_hex(
            "5d81fbc91b4438ed44dff0eedf26f41af06c1a6c1c503930f0a43091273f46d7",
            "040bfc3fcea237936f24d6d65b968474522b9c4eb24a265b2dfa261d44cacd4831bb612adccba051c5ab1b6972e9d2e1e651e7016462b5ff75cb90026185024db5",
        ),
        "b04774b748ce404f3a8017481174e396e32d757b26277a857d2991d9fa9f4a1e",
    )
    # P (13 - Z value should have leading 0 nibble )
    assert_equal(
        _ecdh_hex(
            "5530f938f747c6e2cdd7724d4d0b984c615a4a93548f8c8048f38d82d3225139",
            "044b7d65e1063d8f5378339f7fa29bc74dde3b7d21d31f5db3b793d7b0972a43a8b6087f382ffe5a2c3b83204b4e6a6f7bd6f5e51d657750c3862518e6a2e4a1c0",
        ),
        "0e5beabfc56fb7cc83f02e0f1caafa562c5764c01682b2b1cc274a2c423d9a0d",
    )
    # P (13 - Z value should have leading 0 nibble )
    assert_equal(
        _ecdh_hex(
            "5d965d0465d1945051a077faef54c52e0317b2924474c5cc5484b5252660e205",
            "04f84de7551e0f47a52d2d780126d18f5bd7d5d19acf76f0ecc881dc2d6bbcd7419a0a05252ed78a6afdaa4756ab074973ac8456d56cd5219561b71b1b15f69604",
        ),
        "0ba5c59a7ea550d6b0e3fab1279426b1de88362eeadc16830cee9bff6d72a538",
    )
    # F (1 - CAVS's Static public key X fails PKV 5.6.2.5)
    assert_equal(
        _ecdh_hex(
            "bd4b63809464ce4305dd2263629c1014a06ba9d93ff5d94080c3c2d0f2673c1b",
            "04e1740cc58da344a039dc5b6f15958656abcd2f79efe14a6592b0b261b70abe2b3b2fe7d5a54e09a6e3ffb50da17d5b240021b3df34286b80810a1169ca1ee61a",
        ),
        "error",
    )
    # F (2 - CAVS's Static public key Y fails PKV 5.6.2.5)
    assert_equal(
        _ecdh_hex(
            "f2232ef76c128acba732b2032a7cde7562224719ef03f55577bfc832f9b7db57",
            "045744842237c9fa37ad967a02df3bb744c446c26f458d62f240837640953843319ee62c75bd07bcd37ff8d6a5fd0c0942483d93d6f56d3a07eec5d8eb08be6a37",
        ),
        "error",
    )


def test_wycheproof_ecdsa_valid() raises:
    # Wycheproof ecdsa_secp256r1_sha256_p1363_test, one vector per kind
    # of edge case.
    _check_message(
        "tcId 1: signature malleability",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
        True,
    )
    _check_message(
        "tcId 60: Edge case for Shamir multiplication",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "3639383139",
        "64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
        True,
    )
    _check_message(
        "tcId 61: special case hash",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "343236343739373234",
        "16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
        True,
    )
    _check_message(
        "tcId 115: k*G has a large x-coordinate",
        "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
        "313233343030",
        "000000000000000000000000000000004319055358e8617b0c46353d039cdaabffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        True,
    )
    _check_message(
        "tcId 117: r,s are large",
        "04ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c58220455419235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d45",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        True,
    )
    _check_message(
        "tcId 118: r and s^-1 have a large Hamming weight",
        "0480984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c5611feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed95",
        "313233343030",
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
        True,
    )
    _check_message(
        "tcId 120: small r and s",
        "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
        "313233343030",
        "00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001",
        True,
    )
    _check_message(
        "tcId 138: small r and s^-1",
        "04d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
        "313233343030",
        "00000000000000000000000000000000000000000000000000000000000001008f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
        True,
    )
    _check_message(
        "tcId 139: smallish r and s^-1",
        "044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
        "313233343030",
        "000000000000000000000000000000000000000000000000002d9b4d347952d6ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
        True,
    )
    _check_message(
        "tcId 140: 100-bit r and small s^-1",
        "047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
        "313233343030",
        "000000000000000000000000000000000000001033e67e37b32b445580bf4eff8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
        True,
    )
    _check_message(
        "tcId 141: small r and 100 bit s^-1",
        "045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
        "313233343030",
        "0000000000000000000000000000000000000000000000000000000000000100ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
        True,
    )
    _check_message(
        "tcId 142: 100-bit r and s^-1",
        "041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
        "313233343030",
        "00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
        True,
    )
    _check_message(
        "tcId 143: r and s^-1 are close to n",
        "04083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        True,
    )
    _check_message(
        "tcId 144: r and s are 64-bit integer",
        "04e075effd9607d08d5f34e3652f64cfa3bd6d20c58d0a232f058491260ab212a4cc61760ac8b0680c1b644c03cc628ba9dc4a3c0561368489c692bd40f43aa3ca",
        "313233343030",
        "0000000000000000000000000000000000000000000000009c44febf31c3594f000000000000000000000000000000000000000000000000839ed28247c2b06b",
        True,
    )
    _check_message(
        "tcId 146: r and s are 100-bit integer",
        "04cffb758c3073ea3c08efd9f7f17a85b6ae385c5a140c146ad5f1f5a826718bc8dfdc6bebc894144c6d418ac5d97339726ad2ae925df868426e5628e9f4e62342",
        "313233343030",
        "0000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a",
        True,
    )
    _check_message(
        "tcId 148: r and s are 128-bit integer",
        "04b98740e69e61a325d5f772e3b5c4f67fb7150b16a9afeca9ddc4afcbb6fa0549c446e814138e4ebc82dbf86a390056d4595dcf45e381fef217a4597d7bd51498",
        "313233343030",
        "000000000000000000000000000000008a598e563a89f526c32ebec8de26367c0000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf",
        True,
    )
    _check_message(
        "tcId 150: r and s are 160-bit integer",
        "0484536a270c3932bb2084732adf2c768efc6d3977e5220229ea9a44888b8f9d7b1766398cdac2fc8000017b29a7ba15a58f196037f35f7008ed4286ddff00fd46",
        "313233343030",
        "000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9",
        True,
    )
    _check_message(
        "tcId 152: s == 1",
        "048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000001",
        True,
    )
    _check_message(
        "tcId 154: edge case modular inverse",
        "0461722eaba731c697c7a9ba4d0afdbb5713d8aa12b0eab601bb33dbaf792c5adc272cd993b2b663aba5b3a26c101182ff178684945e83879e71598b95fe647dfc",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c7002f676969f451a8ccafa4c4f09791810e6d632dbd60b1d5540f3284fbe1889b0",
        True,
    )
    _check_message(
        "tcId 170: edge case for signature malleability",
        "04f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b86f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2dd",
        "313233343030",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a97fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
        True,
    )
    _check_message(
        "tcId 172: u1 == 1",
        "0469da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8b866d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a847002",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
        True,
    )
    _check_message(
        "tcId 173: u1 == n - 1",
        "04d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff3233e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362e1",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c7044a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
        True,
    )
    _check_message(
        "tcId 174: u2 == 1",
        "043623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab7858db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8fe",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        True,
    )
    _check_message(
        "tcId 175: u2 == n - 1",
        "04cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922f1e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2e9",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c70aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        True,
    )
    _check_message(
        "tcId 176: edge case for u1",
        "04db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff773504f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a206",
        "313233343030",
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffde91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
        True,
    )
    _check_message(
        "tcId 190: edge case for u2",
        "0467e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb7460a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38ba0",
        "313233343030",
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
        True,
    )
    _check_message(
        "tcId 204: point duplication during verification",
        "045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249e9",
        "313233343030",
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
        True,
    )
    _check_message(
        "tcId 209: extreme value for k and edgecase s",
        "044fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbcc5d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b280",
        "313233343030",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        True,
    )
    _check_message(
        "tcId 210: extreme value for k and s^-1",
        "04c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c3107bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db589e",
        "313233343030",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
        True,
    )
    _check_message(
        "tcId 214: extreme value for k",
        "040d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb343195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33c5",
        "313233343030",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997816a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
        True,
    )
    _check_message(
        "tcId 225: pseudorandom signature",
        "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
        "",
        "b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
        True,
    )
    _check_message(
        "tcId 229: x-coordinate of the public key has many trailing 0's",
        "044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
        "4d657373616765",
        "d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f19b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
        True,
    )
    _check_message(
        "tcId 232: y-coordinate of the public key has many trailing 0's",
        "043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
        "4d657373616765",
        "664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
        True,
    )
    _check_message(
        "tcId 241: x-coordinate of the public key is large",
        "04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
        "4d657373616765",
        "766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
        True,
    )
    _check_message(
        "tcId 247: y-coordinate of the public key is small",
        "04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
        "4d657373616765",
        "31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb070f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
        True,
    )
    _check_message(
        "tcId 253: r = 5, x = 5 is valid",
        "04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e64",
        "68656c6c6f2c20776f726c64",
        "0000000000000000000000000000000000000000000000000000000000000005ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        True,
    )
    _check_message(
        (
            "tcId 257: r = 3, x = n + 3 is the smallest possible x with a"
            " reduction"
        ),
        "04ce24c99032d52ac6ead23c0ae3ec68ef41e51a281fd457808c83136d7dcce90e8f7a154b551e9f39c59279357aa491b2a62bdebc2bb78613883fc72936c057e0",
        "68656c6c6f2c20776f726c64",
        "0000000000000000000000000000000000000000000000000000000000000003ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        True,
    )
    _check_message(
        "tcId 261: s = 2^128",
        "046955a72c0dad4ed60356f7692649b951fa8ea474bf1cc9549b96c68de4782dfae012ffc24e92c72be71ff2622ee7e549dcb59e7b708f6921c4d4ea29512e2aba",
        "68656c6c6f2c20776f726c64",
        "5f6d3aa0d327c13702513d4299f297ab182fcf670f96291fab19572e7a6e01c40000000000000000000000000000000100000000000000000000000000000000",
        True,
    )
    _check_message(
        "tcId 262: s = n - 2^128",
        "046955a72c0dad4ed60356f7692649b951fa8ea474bf1cc9549b96c68de4782dfae012ffc24e92c72be71ff2622ee7e549dcb59e7b708f6921c4d4ea29512e2aba",
        "68656c6c6f2c20776f726c64",
        "5f6d3aa0d327c13702513d4299f297ab182fcf670f96291fab19572e7a6e01c4ffffffff00000000fffffffffffffffebce6faada7179e84f3b9cac2fc632551",
        True,
    )


def test_wycheproof_ecdsa_invalid() raises:
    # Wycheproof ecdsa_secp256r1_sha256_p1363_test, one vector per kind
    # of edge case.
    _check_message(
        "tcId 2: replaced r by r + n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf536900b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 3: replaced r by r + 256 * n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "01002ba3a7be6b94d6ec80a6d9d1190a432be6dfbb2cb98d6d4d72972df620817f180000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 4: replaced r by n - r",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 5: replaced r by r + 2**256",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1800b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 6: replaced r by r + 2**320",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "0100000000000000002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18000000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 7: replaced s by s + n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "01b329f478a2bbd0a6c384ee1493b1f518276e0e4a5375928d6fcd160c11cb6d2c00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 8: replaced s by s + 256 * n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "0100b329f379a2bbd1a5c384ee1493b1f4d55181c143c3fc78fc35de0e45788d98db0000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 9: replaced s by s + 2**256",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "01b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 10: replaced s by s + 2**320",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "010000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db000000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_message(
        "tcId 11: Signature with special case values r=0 and s=0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        False,
    )
    _check_message(
        "tcId 12: Signature with special case values r=0 and s=1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        False,
    )
    _check_message(
        "tcId 18: Signature with special case values r=1 and s=0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
        False,
    )
    _check_message(
        "tcId 20: Signature with special case values r=1 and s=n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        False,
    )
    _check_message(
        "tcId 23: Signature with special case values r=1 and s=p",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        False,
    )
    _check_message(
        "tcId 26: Signature with special case values r=n and s=1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000001",
        False,
    )
    _check_message(
        "tcId 34: Signature with special case values r=n - 1 and s=n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        False,
    )
    _check_message(
        "tcId 43: Signature with special case values r=n + 1 and s=n + 1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        False,
    )
    _check_message(
        "tcId 47: Signature with special case values r=p and s=1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000001",
        False,
    )
    _check_message(
        "tcId 59: Signature with special case values r=p + 1 and s=p + 1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000",
        False,
    )
    _check_message(
        "tcId 116: r too large",
        "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
        "313233343030",
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffcffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        "tcId 121: incorrect size of signature",
        "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
        "313233343030",
        "0501",
        False,
    )
    _check_message(
        "tcId 136: r is larger than n",
        "04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
        "313233343030",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325570000000000000000000000000000000000000000000000000000000000000007",
        False,
    )
    _check_message(
        "tcId 137: s is larger than n",
        "043a72476291571193b4d109b2c37b59f2807e8fe9cffd804eacded903e77ca0da592dbc74fee0ca7508cc7bc282b0c51a143286ff53c60131668e7a0929e4ed04",
        "313233343030",
        "0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
        False,
    )
    _check_message(
        "tcId 153: s == 0",
        "048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000000",
        False,
    )
    _check_message(
        "tcId 169: point at infinity during verify",
        "04b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f2871b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
        "313233343030",
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        False,
    )
    _check_message(
        "tcId 205: duplication bug",
        "045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc469637c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616",
        "313233343030",
        "6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
        False,
    )
    _check_message(
        "tcId 206: point with x-coordinate 0",
        "046adda82b90261b0f319faa0d878665a6b6da497f09c903176222c34acfef72a647e6f50dcc40ad5d9b59f7602bb222fad71a41bf5e1f9df4959a364c62e488d9",
        "313233343030",
        "0000000000000000000000000000000000000000000000000000000000000001555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
        False,
    )
    _check_message(
        "tcId 208: comparison with point at infinity",
        "04dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d25045d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
        "313233343030",
        "555555550000000055555555555555553ef7a8e48d07df81a693439654210c703333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
        False,
    )
    _check_message(
        "tcId 221: public key shares x-coordinate with generator",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "313233343030",
        "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
        False,
    )
    _check_message(
        "tcId 254: r = 6, x = 5 is invalid",
        "04add76677e54a92e79bbee36a70e1754838273ec4b39295e4018a587290a7fc73f240d625642c943e610d80d953c5c6b8a12760a624ba3b90a0b7902755e1ae79",
        "68656c6c6f2c20776f726c64",
        "0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        "tcId 255: r = 5 + n, x = 5 is invalid; r was not reduced mod n",
        "04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e64",
        "68656c6c6f2c20776f726c64",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        "tcId 256: r = n - 3, x = n - 2 is invalid",
        "04e7e49dd82812432744fefe723f7f69663214ad1b85c02b2650b4ca0354743a325223c51c415f457aec69cb019bbe3d27585b38f8b79c39dfea6c27c2f0d8146a",
        "68656c6c6f2c20776f726c64",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254effffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        "tcId 258: r = 4, x = n + 3 is invalid",
        "04c981c75ddfd3910387eb147098fe5658c43aaaa34c681cd6d514b6ad5b6baa6d14fbddb53a6e6db18e90602bc60f2e736d625765f7f2cca4be76f4eeccf12c18",
        "68656c6c6f2c20776f726c64",
        "0000000000000000000000000000000000000000000000000000000000000004ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        (
            "tcId 259: r = p - n + 5, x = 5 is invalid; r is too large to"
            " compare r + n with x"
        ),
        "040ec505bc19b14a43e05678cccf07a443d3e871a2e19b68a4da91859a0650f32477300e4f64e9982d94dff5d294428bb37cc9be66117cae9c389d2d495f68b987",
        "68656c6c6f2c20776f726c64",
        "000000000000000000000000000000004319055358e8617b0c46353d039cdab3ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )
    _check_message(
        (
            "tcId 260: r = 2^256 - n + 5, x = 5 is invalid; r + n is too large"
            " to compare r + n with x, and overflows 2^256 bits"
        ),
        "04d42ce21e730f3d2a84e949828574b4dceeb77d4f89556735f34fba03028ee3ed32daf8bfd3f0a7a0821170840f4e032056722386b35d9bdd4f4f450696f4fb52",
        "68656c6c6f2c20776f726c64",
        "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdab4ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
        False,
    )


def test_wycheproof_ecdsa_der() raises:
    # Wycheproof ecdsa_secp256r1_sha256_test: DER-encoded signatures.
    _check_der_message(
        "tcId 1: pseudorandom signature",
        "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
        "",
        "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
        True,
    )
    _check_der_message(
        "tcId 2: pseudorandom signature",
        "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
        "4d7367",
        "30450220530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23022100d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
        True,
    )
    _check_der_message(
        "tcId 6: Legacy: ASN encoding of s misses leading 0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180220b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 8: length of sequence [r, s] uses long form encoding",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30814502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 9: length of sequence [r, s] contains a leading 0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3082004502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 10: length of sequence [r, s] uses 70 instead of 69",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304602202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 11: length of sequence [r, s] uses 68 instead of 69",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304402202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 12: uint32 overflow in length of sequence [r, s]",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3085010000004502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 13: uint64 overflow in length of sequence [r, s]",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "308901000000000000004502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 14: length of sequence [r, s] = 2**31 - 1",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30847fffffff02202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 15: length of sequence [r, s] = 2**31",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30848000000002202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 23: appending 0's to sequence [r, s]",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304702202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000",
        False,
    )
    _check_der_message(
        "tcId 24: prepending 0's to sequence [r, s]",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3047000002202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 26: appending null value to sequence [r, s]",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304702202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0500",
        False,
    )
    _check_der_message(
        "tcId 30: including undefined tags",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304daa00bb00cd00304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 48: indefinite length",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "308002202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db0000",
        False,
    )
    _check_der_message(
        "tcId 67: length of r uses long form encoding",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30460281202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 68: length of r contains a leading 0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3047028200202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 114: length of s uses long form encoding",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304602202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1802812100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 115: length of s contains a leading 0",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304702202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e180282002100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 152: replaced r by r + n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30460221012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf5369022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 153: replaced r by r - n",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30460221ff2ba3a8bf6b94d5eb80a6d9d1190a436f42fe12d7fad749d4c512a036c0f908c7022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 155: replaced r by -r",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30450220d45c5741946b2a137f59262ee6f5bc91001af27a5e1117a64733950642a3d1e8022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 156: replaced r by n - r",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3046022100d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 158: replaced r by r + 2**256",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "30460221012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 159: replaced r by r + 2**320",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "304e02290100000000000000002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
        False,
    )
    _check_der_message(
        "tcId 232: Signature encoding contains incorrect types: r=0, s=0.25",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3008020100090380fe01",
        False,
    )
    _check_der_message(
        "tcId 233: Signature encoding contains incorrect types: r=0, s=nan",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3006020100090142",
        False,
    )
    _check_der_message(
        "tcId 234: Signature encoding contains incorrect types: r=0, s=True",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3006020100010101",
        False,
    )
    _check_der_message(
        "tcId 235: Signature encoding contains incorrect types: r=0, s=False",
        "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
        "313233343030",
        "3006020100010100",
        False,
    )


def test_wycheproof_ecdh_valid() raises:
    # Wycheproof ecdh_secp256r1_ecpoint_test, one vector per kind of
    # edge case. Private keys are padded to 32 bytes.
    # tcId 1: normal case
    assert_equal(
        _ecdh_hex(
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
        ),
        "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
    )
    # tcId 3: shared secret has x-coordinate that satisfies x**2 = 0
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "0458fd4168a87795603e2b04390285bdca6e57de6027fe211dd9d25e2212d29e62080d36bd224d7405509295eed02a17150e03b314f96da37445b0d1d29377d12c",
        ),
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    # tcId 4: shared secret has x-coordinate p-3
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "04a1ecc24bf0d0053d23f5fd80ddf1735a1925039dc1176c581a7e795163c8b9ba2cb5a4e4d5109f4527575e3137b83d79a9bcb3faeff90d2aca2bed71bb523e7e",
        ),
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    )
    # tcId 5: shared secret has x-coordinate 2**16 + 0
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "041b0e7437c33d379929430d3ec10df59bed7fe2a1d950c5791e1e9ddeef1f4d70fbdb0e3bbce63a27f27838c685207f2ccaf689d25eb622744db1168ac92619e8",
        ),
        "0000000000000000000000000000000000000000000000000000000000010000",
    )
    # tcId 15: shared secret has x-coordinate with repeating bit-pattern of size 2
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "04e25ead8342888d1fbd2bd211e9db5bc761da9cfa1e805078b53606df9e5444403d3421fa70f940dba104d842034d2efec9332161ccfb654a8e9f2ec42fc1a837",
        ),
        "5555555555555555555555555555555555555555555555555555555555555554",
    )
    # tcId 41: shared secret has an x-coordinate of approx p//3
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "04e9c0af0bf6dadd8fbe04c5cf3fce80683a9c267b0dc9850cbc1bcdfeb744c3516efe878223dd9dd924e83e3ab22c9bf304129ab59c1f3d30fb58b8770bf9d9bf",
        ),
        "5555555500000000555555555555555555555555aaaaaaaaaaaaaaaaaaaaaaab",
    )
    # tcId 45: y-coordinate of the public key is small
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "043cbc1b31b43f17dc200dd70c2944c04c6cb1b082820c234a300b05b7763844c74fde0a4ef93887469793270eb2ff148287da9265b0334f9e2609aac16e8ad503",
        ),
        "7fffffffffffffffffffffffeecf2230ffffffffffffffffffffffffffffffff",
    )
    # tcId 48: y-coordinate of the public key is small
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "047fffffffffffffffffffffffeecf2230ffffffffffffffffffffffffffffffff00000001c7c30643abed0af0a49fe352cb483ff9b97dccdf427c658e8793240d",
        ),
        "6fd26661851a8de3c6d06f834ef3acb8f2a5f9c136a985ffe10d5eeb51edcfa3",
    )
    # tcId 57: y-coordinate of the public key has many trailing 1's
    assert_equal(
        _ecdh_hex(
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "049a0f0e3dd31417bbd9e298bc068ab6d5c36733af26ed67676f410c804b8b2ca1b02c82f3a61a376db795626e9400557112273a36cddb08caaa43953965454730",
        ),
        "7fffffffffffffffffffffffca089011ffffffffffffffffffffffffffffffff",
    )
    # tcId 60: y-coordinate of the public key has many trailing 1's
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "047fffffffffffffffffffffffca089011ffffffffffffffffffffffffffffffff267bfdf8a61148decd80283732dd4c1095e4bb40b9658408208dc1147fffffff",
        ),
        "44236c8b9505a19d48774a3903c0292759b0f826e6ac092ff898d87e53d353fc",
    )
    # tcId 69: ephemeral key has x-coordinate that satisfies x**2 = 0
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        ),
        "cfe4077c8730b1c9384581d36bff5542bc417c9eff5c2afcb98cc8829b2ce848",
    )
    # tcId 70: ephemeral key has x-coordinate p-3
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "04ffffffff00000001000000000000000000000000fffffffffffffffffffffffc19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        ),
        "4c25702d10cd12ec7e77c4f1979237976d6aa809c645d75a59d399a52377eb7b",
    )
    # tcId 71: ephemeral key has x-coordinate 2**16 + 0
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "04000000000000000000000000000000000000000000000000000000000001000073ca30641acabe581170b4d5253f7a342b039a87ab2447badad08ece2cf19f52",
        ),
        "4cfd639fd80c84b935c33cfaacceeb256b2f7e273c3ae5f0ff92b74957376f22",
    )
    # tcId 81: ephemeral key has x-coordinate with repeating bit-pattern of size 2
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "0455555555555555555555555555555555555555555555555555555555555555540a46712790e63f981f0103b2a609fa691c5291a17974eb0c3b518faac21535d6",
        ),
        "be033e3db6216d3b3f9d66c96ca3b24475813ba8eb7820d7d6ff29c72fd39c64",
    )
    # tcId 107: ephemeral key has an x-coordinate of approx p//3
    assert_equal(
        _ecdh_hex(
            "55d55f11bb8da1ea318bca7266f0376662441ea87270aa2077f1b770c4854a48",
            "045555555500000000555555555555555555555555aaaaaaaaaaaaaaaaaaaaaaab79dfbfa5e66fbea30e75ecc703e65db43e027416c01f6e20fe129be0e43457d8",
        ),
        "f9ee8b2b668e2a76ed66dfc57006b6403ef8e388c066a0b0493ee0425f8dbe3e",
    )
    # tcId 111: edge case for computation of x with projective coordinates
    assert_equal(
        _ecdh_hex(
            "e461c5b5e63d75b4c8c123bf8b9cd45e712af08f7e2e494a8f255ac9d80e058b",
            "04851eb1b8699d1cc01c6b6048139797dab3981c924f9ef81bd1f464c3182c870901285b2ae7cbcabfd5bccb9441eb3376b491595f60a1ec21dbe9f972bc32abbe",
        ),
        "6d03fef6b354840f4642fba1c8fce9f7d1cda8ae27b6ca01510fb44573fdaffb",
    )
    # tcId 170: edge case for computation of y with projective coordinates
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "0442e831d5dfd2b9f5387263cd686ee03dfa235cbc07f6f3a87a7e8150556362b32be47f8e3011572855ca487ffb594f7722ef9fc3292902a23146c19bbf6da76a",
        ),
        "e6d3991eecb1a4b78aa700ea56934a38785b3662c59766e2ee5b157f77ecbb7c",
    )
    # tcId 199: point with coordinate x = 0
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        ),
        "40eafb850ca7e08f19ee6447f196aeabf292e27397856e106e60a6c8b48cdb27",
    )
    # tcId 202: point with coordinate x = 0 in left to right addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "04dbfa466f12013255f9d57a6496c158ee7dd202a1ce4a5a53005b3564d509a0bbf2578007e857bdd082751ef2f3b4b9c38a0b87bab413d55ccb26a574f2b4be9d",
        ),
        "e2d57eeec983756c9124f885a4d118ed5b8de7d2895fd91264cf291496949a12",
    )
    # tcId 218: point with coordinate x = 0 in precomputation or right to left addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "0441e9d4cfa8efe80b895a8cbcce2568e251db7ecdfd20a7ad710d4a4bf2addc6b5ec36a8339168a03f15b8c80f2a2a828f151d38791584853ba2ff44a2a0460a1",
        ),
        "b48e119d29eef7dbb76b64218e728ddbf6ec600505ec7ced6ab6fb8763308da5",
    )
    # tcId 223: point with coordinate x = 0 in right to left addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "04d8e13fbd017f1f9a26be35c611d7b2299f5d10de3c8a26362273fffb85238f3ed1426b748c1f87e3afa2c1e7a0224310c980655e07399590d1494d6d6bea0396",
        ),
        "d2a5bc66498c6036aecdfaad041cef732a893de190a0a5b42ff71e13f09280e7",
    )
    # tcId 228: point with coordinate y = 1
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "0409e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96c0000000000000000000000000000000000000000000000000000000000000001",
        ),
        "28f67757acc28b1684ba76ffd534aed42d45b8b3f10b82a5699416eff7199a74",
    )
    # tcId 237: point with coordinate y = 1 in left to right addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "048270f8179d57436b34dfc0bdf7d417a5c895116b90cb51aec718614f864a635d174804e0c0e06e3d68d3149e0b956621c6aa2bde83f4d17d03d28ef8aa389fff",
        ),
        "3db29ec6f978d2269e92e9c7eb5c8b5a8e56c2228a4fb9e483feca50aa3e451f",
    )
    # tcId 285: point with coordinate y = 1 in precomputation or right to left addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "049a4487fcfce8396688e7449e095fe803caa253d4bd7c66dbc6261cc9d9f883a50e5251bae29c5a5cdfa31bc61105671a88a018467398158d35b88829237c0bff",
        ),
        "7e83fd2c3d713bc85d6d85d9078b3a0842824d410e8abde04da0fd71c7d94705",
    )
    # tcId 300: point with coordinate y = 1 in right to left addition chain
    assert_equal(
        _ecdh_hex(
            "809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "04341592390ccce485de8880f3d727f664c381914a1becec383b35586751fc81c2add71852b87016e1019cae7a9080e75ce0b0b8aac175d692d5e7b4dad088f5cc",
        ),
        "4ce2701b2be63a0083a4c53f7a0bf04cf871654f5edb6f625e3ea5e7d0bdcc90",
    )
    # tcId 315: edge case private key
    assert_equal(
        _ecdh_hex(
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0431028f3377fc8f2b1967edaab90213acad0da9f50897f08f57537f78f116744743a1930189363bbde2ac4cbd1649cdc6f451add71dd2f16a8a867f2b17caa16b",
        ),
        "85a0b58519b28e70a694ec5198f72c4bfdabaa30a70f7143b5b1cd7536f716ca",
    )
    # tcId 330: CVE-2017-8932
    assert_equal(
        _ecdh_hex(
            "2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
            "04023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882eaf93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
        ),
        "4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3",
    )


def test_wycheproof_ecdh_invalid() raises:
    # Points that are not on the curve, compressed or otherwise malformed
    # encodings (only the uncompressed form is supported) and points on the
    # twist must all be rejected.
    # tcId 2: compressed public key (acceptable)
    assert_equal(
        _ecdh_hex(
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            "0362d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26",
        ),
        "error",
    )
    # tcId 332: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        "error",
    )
    # tcId 333: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        ),
        "error",
    )
    # tcId 334: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "040000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ),
        "error",
    )
    # tcId 335: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "040000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        "error",
    )
    # tcId 336: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
        ),
        "error",
    )
    # tcId 337: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001",
        ),
        "error",
    )
    # tcId 338: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "040000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ),
        "error",
    )
    # tcId 339: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "040000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        "error",
    )
    # tcId 340: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000fffffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "error",
    )
    # tcId 341: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000fffffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000001",
        ),
        "error",
    )
    # tcId 342: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000fffffffffffffffffffffffeffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ),
        "error",
    )
    # tcId 343: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000fffffffffffffffffffffffeffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        "error",
    )
    # tcId 344: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "error",
    )
    # tcId 345: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000001",
        ),
        "error",
    )
    # tcId 346: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
        ),
        "error",
    )
    # tcId 347: point is not on curve (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        "error",
    )
    # tcId 348: empty public key (invalid)
    assert_equal(
        _ecdh_hex(
            "7e4aa54f714bf01df85c50269bea3a86721f84afe74f7b41ea58abcf3474e88d",
            "",
        ),
        "error",
    )
    # tcId 349: invalid public key (invalid)
    assert_equal(
        _ecdh_hex(
            "6f953faff3599e6c762d7f4cabfeed092de2add1df1bc5748c6cbb725cf35458",
            "02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535",
        ),
        "error",
    )
    # tcId 350: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "d27edf0ff5b6b6b465753e7158370332c153b468a1be087ad0f490bdb99e5f02",
            "03efdde3b32872a9effcf3b94cbf73aa7b39f9683ece9121b9852167f4e3da609b",
        ),
        "error",
    )
    # tcId 351: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "d27edf0ff5b6b6b465753e7158370332c153b468a1be087ad0f490bdb99e5f03",
            "02efdde3b32872a9effcf3b94cbf73aa7b39f9683ece9121b9852167f4e3da609b",
        ),
        "error",
    )
    # tcId 352: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "95ead84540c2d027aa3130ff1b47888cc1ed67e8dda46156e71ce0991791e835",
            "02c49524b2adfd8f5f972ef554652836e2efb2d306c6d3b0689234cec93ae73db5",
        ),
        "error",
    )
    # tcId 353: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "a8681ef67fb1f189647d95e8db00c52ceef6d41a85ba0a5bd74c44e8e62c8aa4",
            "0318f9bae7747cd844e98525b7ccd0daf6e1d20a818b2175a9a91e4eae5343bc98",
        ),
        "error",
    )
    # tcId 354: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "a8681ef67fb1f189647d95e8db00c52ceef6d41a85ba0a5bd74c44e8e62c8aa5",
            "0218f9bae7747cd844e98525b7ccd0daf6e1d20a818b2175a9a91e4eae5343bc98",
        ),
        "error",
    )
    # tcId 355: public key is a low order point on twist (invalid)
    assert_equal(
        _ecdh_hex(
            "95ead84540c2d027aa3130ff1b47888cc1ed67e8dda46156e71ce0991791e834",
            "03c49524b2adfd8f5f972ef554652836e2efb2d306c6d3b0689234cec93ae73db5",
        ),
        "error",
    )


def test_private_key_from_bytes() raises:
    # d = (seed mod (n - 1)) + 1; expected values from Python integers.
    assert_equal(
        _derive_hex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    assert_equal(
        _derive_hex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000001"
        ),
        "0000000000000000000000000000000000000000000000000000000000000002",
    )
    assert_equal(
        _derive_hex(
            "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e"
        ),
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
    )
    assert_equal(
        _derive_hex(
            "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"
        ),
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    )
    assert_equal(
        _derive_hex(
            "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
        ),
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    assert_equal(
        _derive_hex(
            "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        ),
        "0000000000000000000000000000000000000000000000000000000000000002",
    )
    assert_equal(
        _derive_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
        "fffffffe00000001431905529c0166cd22159165b6faae71f756a572fc632550",
    )
    assert_equal(
        _derive_hex(
            "6ebbec4cc598e827750b79840a35e888cea8684b60033cd65db233956ea88f4b4f72fd3f7d254db8"
        ),
        "3aa461aad5e11414ebae69caf283dd2d0270120fa8de374aee72b6b687122579",
    )
    assert_equal(
        _derive_hex(
            "f0969fe15284b2bf8e56916a518a4444aacdabbb49c9c6072c54a01283037cadfde8ec5e3e154459"
        ),
        "e0db44280e6ef1a4e9dc9b49735f472e87ed0456d5d98ee37ba58bcfdeba525a",
    )
    assert_equal(
        _derive_hex(
            "45fff12fb4d7a20d294b97d08e7981664997082c8b7e20bfd2aeeaf914c7d3fd9a1ac067541b8ee6"
        ),
        "de2339dc93a1ee2a5befdbbf2bd4c21d27e4f01d364e4a9eafe25062c841e027",
    )
    assert_equal(
        _derive_hex(
            "c4fde9c7e9675be2b6da6f2974beeb65d108c25300fecf0c9277eeb71d894a472bf09b30460cce5b34"
        ),
        "41cb0b6659a5bb64aa7766ae8c3f579da55b132af3c68315a15bf9fcd97fe935",
    )
    assert_equal(
        _derive_hex(
            "5d64f7d65e0466a76c3472ad2271615630ce9ba502f93eb042e9c091a7d0ba3f0605fca2d7a7836fcaf25f54c66f555c240a97759009eb69b50f9ca5376f3052"
        ),
        "83658b03be0548c64b7b877aca6cc8772829f2882562cfcd5fbf0ca95d105ee3",
    )
    assert_equal(
        _derive_hex(
            "d346ca86eee02c31e6fba31f1d6bd29b395698b7d6e88563b8e3469886f176c967728fccae594d414121f6bb4fd3386e8af6c3d82958f8e113b4655fe0629f22f3f763a8c9cc3e8a7a0e0583f37151c4d7bea6cd4808ebb5723bdd10f425233bff64e594"
        ),
        "ef3d816daa89016adfccabf8b18cebccb8f6e3d70070f11f67eea28703ccb185",
    )
    # Fewer than 40 bytes would leave a detectable bias.
    for count in [0, 1, 32, 39]:
        var short = _stream("short seed", count)
        var raised = False
        try:
            _ = p256_private_key_from_bytes(Span(short))
        except e:
            raised = True
        assert_true(raised)
    # Every derived key is usable.
    for i in range(4):
        var seed = _stream(String(t"usable {i}"), 40)
        var d = p256_private_key_from_bytes(Span(seed))
        var public_key = p256_public_key(Span(d))
        assert_equal(public_key[0], 0x04)


def test_invalid_private_keys_are_rejected() raises:
    var zero = (
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    var order = (
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    )
    var above = (
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"
    )
    var ones = (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    var short = "00000000000000000000000000000000000000000000000000000000000001"
    var long = (
        "000000000000000000000000000000000000000000000000000000000000000001"
    )
    var g = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    for key in [zero, order, above, ones, short, long, ""]:
        assert_true(_public_fails(key))
        assert_true(_sign_fails(key))
        assert_equal(_ecdh_hex(key, g), "error")
    # The two ends of the valid range work.
    assert_equal(
        _public_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ),
        g,
    )
    assert_equal(
        _public_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
        ),
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    )
    assert_false(
        _sign_fails(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
    )
    assert_false(
        _sign_fails(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
        )
    )
    assert_equal(
        _ecdh_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
            g,
        ),
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    )


def test_sign_verify_round_trip() raises:
    for i in range(6):
        var seed = _stream(String(t"key {i}"), 40)
        var d = p256_private_key_from_bytes(Span(seed))
        var public_key = p256_public_key(Span(d))
        # Digest lengths below, at and above the order size, and empty.
        for count in [0, 20, 32, 48, 64]:
            var digest = _stream(String(t"digest {i} {count}"), count)
            var sig = p256_sign(Span(d), Span(digest))
            assert_true(p256_verify(Span(public_key), Span(digest), Span(sig)))
            # Deterministic nonces give the same signature again.
            var again = p256_sign(Span(d), Span(digest))
            assert_equal(hex_encode(Span(again)), hex_encode(Span(sig)))
            # Another key or another digest must not verify.
            var other = _stream(String(t"other {i} {count}"), count + 1)
            assert_false(p256_verify(Span(public_key), Span(other), Span(sig)))
            var g = hex_decode(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
            assert_false(p256_verify(Span(g), Span(digest), Span(sig)))


def test_digest_truncation() raises:
    # FIPS 186-4: only the leftmost 32 bytes of a longer digest count.
    var seed = _stream("truncation key", 40)
    var d = p256_private_key_from_bytes(Span(seed))
    var public_key = p256_public_key(Span(d))
    var long = _stream("long digest", 48)
    var sig = p256_sign(Span(d), Span(long))
    var prefix = p256_sign(Span(d), Span(long)[0:32])
    assert_equal(hex_encode(Span(sig)), hex_encode(Span(prefix)))
    assert_true(p256_verify(Span(public_key), Span(long)[0:32], Span(sig)))
    long[47] ^= 0x01
    assert_true(p256_verify(Span(public_key), Span(long), Span(sig)))
    long[31] ^= 0x01
    assert_false(p256_verify(Span(public_key), Span(long), Span(sig)))
    # A shorter digest is not the same as one padded with zeros on the right.
    var short = _stream("short digest", 20)
    var short_sig = p256_sign(Span(d), Span(short))
    var padded = short.copy()
    padded.append(0x00)
    assert_false(p256_verify(Span(public_key), Span(padded), Span(short_sig)))
    # ... but it is the same as one padded on the left up to the order size.
    var left = List[UInt8](length=12, fill=0)
    for byte in short:
        left.append(byte)
    assert_true(p256_verify(Span(public_key), Span(left), Span(short_sig)))


def test_verify_rejects_every_single_bit_flip() raises:
    var seed = _stream("bit flip key", 40)
    var d = p256_private_key_from_bytes(Span(seed))
    var point = p256_public_key(Span(d))
    var public_key = List[UInt8](Span(point))
    var digest = _stream("bit flip digest", 32)
    var raw = p256_sign(Span(d), Span(digest))
    var sig = List[UInt8](Span(raw))
    assert_true(p256_verify(Span(public_key), Span(digest), Span(sig)))
    for bit in range(8 * len(digest)):
        digest[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
        assert_false(p256_verify(Span(public_key), Span(digest), Span(sig)))
        digest[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
    for bit in range(8 * len(sig)):
        sig[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
        assert_false(p256_verify(Span(public_key), Span(digest), Span(sig)))
        sig[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
    for bit in range(8 * len(public_key)):
        public_key[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
        assert_false(p256_verify(Span(public_key), Span(digest), Span(sig)))
        public_key[bit // 8] ^= UInt8(1) << UInt8(bit % 8)
    assert_true(p256_verify(Span(public_key), Span(digest), Span(sig)))


def test_verify_rejects_malformed_input() raises:
    # The RFC 6979 A.2.5 "sample" signature, then damaged copies of it.
    var key = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    var digest = (
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    )
    var r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    var s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    assert_true(_verify_hex(key, digest, r + s))
    # The (r, n - s) twin is a valid ECDSA signature too.
    assert_true(
        _verify_hex(
            key,
            digest,
            r
            + "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
        )
    )
    # r or s zero, equal to n, or above n.
    var zero = (
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    var order = (
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    )
    var ones = (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert_false(_verify_hex(key, digest, zero + s))
    assert_false(_verify_hex(key, digest, r + zero))
    assert_false(_verify_hex(key, digest, zero + zero))
    assert_false(_verify_hex(key, digest, order + s))
    assert_false(_verify_hex(key, digest, r + order))
    assert_false(_verify_hex(key, digest, ones + s))
    assert_false(_verify_hex(key, digest, r + ones))
    # Swapped halves and wrong lengths.
    assert_false(_verify_hex(key, digest, s + r))
    assert_false(_verify_hex(key, digest, ""))
    assert_false(_verify_hex(key, digest, r))
    assert_false(_verify_hex(key, digest, r + s + "00"))
    assert_false(_verify_hex(key, digest, "00" + r + s))
    assert_false(
        _verify_hex(
            key,
            digest,
            r
            + "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acd",
        )
    )
    # Malformed public keys: empty, truncated, extended, wrong prefix,
    # compressed, off the curve, coordinates not below p.
    assert_false(_verify_hex("", digest, r + s))
    assert_false(_verify_hex("04", digest, r + s))
    assert_false(
        _verify_hex(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622",
            digest,
            r + s,
        )
    )
    assert_false(_verify_hex(key + "00", digest, r + s))
    assert_false(
        _verify_hex(
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "0060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d446229a",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            digest,
            r + s,
        )
    )
    assert_false(
        _verify_hex(
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            digest,
            r + s,
        )
    )
    # The negated key is a valid point but the wrong signer.
    assert_false(
        _verify_hex(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb686fc01eef74743675be51616a9d7439b0d0e4df4d28160ae885c3d6b2bb9dd66",
            digest,
            r + s,
        )
    )


def test_ecdh_is_symmetric() raises:
    for i in range(6):
        var seed_a = _stream(String(t"alice {i}"), 40)
        var seed_b = _stream(String(t"bob {i}"), 48)
        var a = p256_private_key_from_bytes(Span(seed_a))
        var b = p256_private_key_from_bytes(Span(seed_b))
        var public_a = p256_public_key(Span(a))
        var public_b = p256_public_key(Span(b))
        var ab = p256_ecdh(Span(a), Span(public_b))
        var ba = p256_ecdh(Span(b), Span(public_a))
        assert_equal(hex_encode(Span(ab)), hex_encode(Span(ba)))
        # A key agreed with oneself is the x-coordinate of d^2 G; it must
        # differ from the secret shared with the other party.
        var aa = p256_ecdh(Span(a), Span(public_a))
        assert_false(hex_encode(Span(aa)) == hex_encode(Span(ab)))


def test_ecdh_rejects_invalid_points() raises:
    var d = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    var good = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    assert_false(_ecdh_hex(d, good) == "error")
    # Off the curve, on the twist, coordinates not below p.
    assert_equal(
        _ecdh_hex(
            d,
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d446229a",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb77903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        "error",
    )
    # x = 5 is on the curve; x + p names the same point but is not
    # a canonical field element.
    assert_false(
        _ecdh_hex(
            d,
            "040000000000000000000000000000000000000000000000000000000000000005459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc",
        )
        == "error"
    )
    assert_equal(
        _ecdh_hex(
            d,
            "04ffffffff00000001000000000000000000000001000000000000000000000004459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc",
        ),
        "error",
    )
    # Wrong lengths and encodings.
    assert_equal(_ecdh_hex(d, ""), "error")
    assert_equal(_ecdh_hex(d, "00"), "error")
    assert_equal(_ecdh_hex(d, "04"), "error")
    assert_equal(
        _ecdh_hex(
            d,
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d44622",
        ),
        "error",
    )
    assert_equal(_ecdh_hex(d, good + "00"), "error")
    assert_equal(
        _ecdh_hex(
            d,
            "0560fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
        "error",
    )
    assert_equal(
        _ecdh_hex(
            d,
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        ),
        "error",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
