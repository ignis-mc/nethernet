from nethernet.crypto.ec import (
    AffinePoint,
    Curve,
    ProjectivePoint,
    Rfc6979,
    ecdsa_sign,
    ecdsa_verify,
)
from nethernet.crypto.hash import Hash
from nethernet.crypto.mont import (
    ct_eq,
    ct_is_zero,
    limbs_from_be_bytes,
    limbs_to_be_bytes,
)
from nethernet.crypto.p256 import p256_curve
from nethernet.crypto.p384 import p384_curve
from nethernet.crypto.sha1 import Sha1, sha1
from nethernet.crypto.sha256 import Sha256, sha256
from nethernet.crypto.sha512 import Sha384, Sha512, sha384, sha512
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _limbs[n: Int](text: StringSpan) raises -> Array[UInt64, n]:
    var bytes = hex_decode(text)
    return limbs_from_be_bytes[n](Span(bytes))


def _hex[n: Int](a: Array[UInt64, n]) -> String:
    var bytes = limbs_to_be_bytes(a)
    return hex_encode(Span(bytes))


def _point_hex[n: Int](curve: Curve[n], p: ProjectivePoint[n]) -> String:
    # The uncompressed encoding, or "infinity".
    if curve.is_infinity(p) != 0:
        return "infinity"
    var encoded = curve.encode_point(curve.to_affine(p))
    return hex_encode(Span(encoded))


def _point[
    n: Int
](curve: Curve[n], text: StringSpan) raises -> ProjectivePoint[n]:
    if text == "infinity":
        return curve.infinity()
    var zero = Array[UInt64, n](fill=0)
    var point = AffinePoint[n](zero.copy(), zero^)
    var bytes = hex_decode(text)
    assert_true(curve.decode_point(Span(bytes), point))
    return curve.to_projective(point)


def _check_constants[
    n: Int
](
    curve: Curve[n],
    p: StringSpan,
    order: StringSpan,
    b: StringSpan,
    gx: StringSpan,
    gy: StringSpan,
) raises:
    # The literal constants must equal what the deriving constructor gives.
    var derived = Curve[n](
        _limbs[n](p),
        _limbs[n](order),
        _limbs[n](b),
        _limbs[n](gx),
        _limbs[n](gy),
    )
    assert_equal(_hex(curve.field.m), p)
    assert_equal(curve.field.m0_inv, derived.field.m0_inv)
    assert_equal(_hex(curve.field.one), _hex(derived.field.one))
    assert_equal(_hex(curve.field.rr), _hex(derived.field.rr))
    assert_equal(_hex(curve.field.m_minus_2), _hex(derived.field.m_minus_2))
    assert_equal(_hex(curve.scalar.m), order)
    assert_equal(curve.scalar.m0_inv, derived.scalar.m0_inv)
    assert_equal(_hex(curve.scalar.one), _hex(derived.scalar.one))
    assert_equal(_hex(curve.scalar.rr), _hex(derived.scalar.rr))
    assert_equal(_hex(curve.scalar.m_minus_2), _hex(derived.scalar.m_minus_2))
    assert_equal(_hex(curve.b), _hex(derived.b))
    assert_equal(_hex(curve.field.from_mont(curve.b)), b)
    assert_equal(_hex(curve.generator.x), _hex(derived.generator.x))
    assert_equal(_hex(curve.generator.y), _hex(derived.generator.y))
    assert_equal(_hex(curve.field.from_mont(curve.generator.x)), gx)
    assert_equal(_hex(curve.field.from_mont(curve.generator.y)), gy)
    assert_equal(_hex(curve.order_minus_one), _hex(derived.order_minus_one))
    for i in range(30 * n):
        assert_equal(curve.comb[i], derived.comb[i])
    # Comb entry 1 is the generator itself.
    for i in range(n):
        assert_equal(curve.comb[i], curve.generator.x[i])
        assert_equal(curve.comb[n + i], curve.generator.y[i])


def _check_group_law[n: Int](curve: Curve[n]) raises:
    var g = curve.to_projective(curve.generator)
    var inf = curve.infinity()
    assert_true(curve.is_on_curve(curve.generator.x, curve.generator.y))
    assert_false(
        curve.is_on_curve(
            curve.generator.x,
            curve.field.add(curve.generator.y, curve.field.one),
        )
    )
    assert_false(curve.is_on_curve(curve.generator.y, curve.generator.x))
    assert_true(curve.is_infinity(inf) != 0)
    assert_true(curve.is_infinity(g) == 0)
    var g_hex = _point_hex(curve, g)
    # Identity handling, in both argument orders and for doubling.
    assert_equal(_point_hex(curve, curve.add(g, inf)), g_hex)
    assert_equal(_point_hex(curve, curve.add(inf, g)), g_hex)
    assert_equal(_point_hex(curve, curve.add(inf, inf)), "infinity")
    assert_equal(_point_hex(curve, curve.double(inf)), "infinity")
    assert_equal(
        _point_hex(curve, curve.add_mixed(inf, curve.generator)), g_hex
    )
    # Adding a point to itself must agree with doubling.
    var g2 = curve.double(g)
    assert_equal(_point_hex(curve, curve.add(g, g)), _point_hex(curve, g2))
    assert_equal(
        _point_hex(curve, curve.add_mixed(g, curve.generator)),
        _point_hex(curve, g2),
    )
    # A point plus its inverse is the identity.
    var neg_g = ProjectivePoint[n](g.x.copy(), curve.field.neg(g.y), g.z.copy())
    assert_equal(_point_hex(curve, curve.add(g, neg_g)), "infinity")
    assert_equal(_point_hex(curve, curve.add(neg_g, g)), "infinity")
    assert_equal(
        _point_hex(curve, curve.add_mixed(neg_g, curve.generator)), "infinity"
    )
    # Mixed and full addition agree on unnormalised operands, and the group
    # law is associative and commutative.
    var g3 = curve.add(g2, g)
    var g4 = curve.double(g2)
    var g5 = curve.add(g4, g)
    assert_equal(
        _point_hex(curve, curve.add_mixed(g4, curve.generator)),
        _point_hex(curve, g5),
    )
    assert_equal(_point_hex(curve, curve.add(g2, g3)), _point_hex(curve, g5))
    assert_equal(_point_hex(curve, curve.add(g3, g2)), _point_hex(curve, g5))
    assert_equal(
        _point_hex(curve, curve.add(curve.add(g, g2), g2)),
        _point_hex(curve, curve.add(g, curve.add(g2, g2))),
    )
    # to_affine of the identity is the (0, 0) placeholder.
    var placeholder = curve.to_affine(inf)
    assert_true(ct_is_zero(placeholder.x) != 0)
    assert_true(ct_is_zero(placeholder.y) != 0)
    # Scaling the projective representation does not change the point.
    var scaled = ProjectivePoint[n](
        curve.field.mul(g5.x, curve.b),
        curve.field.mul(g5.y, curve.b),
        curve.field.mul(g5.z, curve.b),
    )
    assert_equal(_point_hex(curve, scaled), _point_hex(curve, g5))


def _check_multiple[
    n: Int
](curve: Curve[n], k_hex: StringSpan, expected: StringSpan) raises:
    # Expected points were computed with an independent affine reference.
    var k = _limbs[n](k_hex)
    assert_equal(_point_hex(curve, curve.scalar_base_mul(k)), expected)
    var g = curve.to_projective(curve.generator)
    assert_equal(_point_hex(curve, curve.scalar_mul(k, g)), expected)
    var zero = Array[UInt64, n](fill=0)
    assert_equal(
        _point_hex(curve, curve.double_scalar_mul_vartime(k, zero, g)),
        expected,
    )
    assert_equal(
        _point_hex(curve, curve.double_scalar_mul_vartime(zero, k, g)),
        expected,
    )


def _check_scalar_mul[
    n: Int
](
    curve: Curve[n],
    k_hex: StringSpan,
    point: StringSpan,
    expected: StringSpan,
) raises:
    var k = _limbs[n](k_hex)
    var p = _point(curve, point)
    assert_equal(_point_hex(curve, curve.scalar_mul(k, p)), expected)


def _check_double_scalar[
    n: Int
](
    curve: Curve[n],
    u1_hex: StringSpan,
    u2_hex: StringSpan,
    point: StringSpan,
    expected: StringSpan,
) raises:
    var u1 = _limbs[n](u1_hex)
    var u2 = _limbs[n](u2_hex)
    var q = _point(curve, point)
    assert_equal(
        _point_hex(curve, curve.double_scalar_mul_vartime(u1, u2, q)),
        expected,
    )
    # The constant-time routines must agree with the variable-time one.
    var sum = curve.add(curve.scalar_base_mul(u1), curve.scalar_mul(u2, q))
    assert_equal(_point_hex(curve, sum), expected)


def test_precomputed_constants_p256() raises:
    _check_constants(
        p256_curve(),
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )


def test_group_law_p256() raises:
    _check_group_law(p256_curve())


def test_base_point_multiples_p256() raises:
    ref curve = p256_curve()
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "infinity",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000002",
        "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000003",
        "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000f",
        "04f0454dc6971abae7adfb378999888265ae03af92de3a0ef163668c63e59b9d5fb5b93ee3592e2d1f4e6594e51f9643e62a3b21ce75b5fa3f47e59cde0d034f36",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000010",
        "0476a94d138a6b41858b821c629836315fcd28392eff6ca038a5eb4787e1277c6ea985fe61341f260e6cb0a1b5e11e87208599a0040fc78baa0e9ddd724b8c5110",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000011",
        "0447776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73eaa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000ffffffffffffffff",
        "04fcb7116120d0174bc4191acf8423c0baff33d7071d3980926f3136898abf6bd1deeae37c8366664424aa32136e277d6a41f3c2388752102333192f74f86c5bd9",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000010000000000000000",
        "040fa822bc2811aaa58492592e326e25de29493baaad651f7e90e75cb48e14db63bff44ae8f5dba80d6f4ad4bcb3df188b34b1a65050fe82f5e41124545f462ee7",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000000000000000000010000000000000000",
        "040fa822bc2811aaa58492592e326e25de29493baaad651f7e90e75cb48e14db63bff44ae8f5dba80d6f4ad4bcb3df188b34b1a65050fe82f5e41124545f462ee7",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000ffffffffffffffff",
        "04fcb7116120d0174bc4191acf8423c0baff33d7071d3980926f3136898abf6bd1deeae37c8366664424aa32136e277d6a41f3c2388752102333192f74f86c5bd9",
    )
    _check_multiple(
        curve,
        "0000000000000000000000000000000100000000000000010000000000000001",
        "04eb5d7745b21141eaa2e8f483f43e43917ccd84e70d715f26e48ecafffc5cde01eafd72ebdbecc17b0990e6a158006cee85f22cfe2844b645cac917e2731a3479",
    )
    _check_multiple(
        curve,
        "0000000000000001000000000000000000000000000000000000000000000000",
        "04a6d39677a78492762736ff8344315fc596439591a3c6b94a6cf20ffb313728be674f84749b0b881666b8babd2d27ecdf824a920c2284059bf2bab833c357f5f4",
    )
    _check_multiple(
        curve,
        "8000000000000000000000000000000000000000000000000000000000000000",
        "0477b20a912e6b23135066e911891524bc4efe3560e3e92350b52dec8f375f2b54a3dc291825cea3f7f7b10bfcdd038a72df623da1e850e0f1caa801fcd6cc67ff",
    )
    _check_multiple(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
        "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978f888aaee24712fc0d6c26539608bcf244582521ac3167dd661fb4862dd878c2e",
    )
    _check_multiple(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
    )
    _check_multiple(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "infinity",
    )
    _check_multiple(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "04f72cbd240e26c0d21b1023179586eb532c6102c49c3677cc1a3d132b9db9d31a43e4ca77e2a36621dc0dbd91bfe7a5d223250ef0cdca831ee453d93fa83408a7",
    )
    _check_multiple(
        curve,
        "9ebe2de52517508454c2686dfd49a3031b1436b6677975545dd5073b6a51c7c0",
        "04853980dcb9b7928a730e8abe58662a77ec03309a6f5da991f78d58d87142e182c01576314a122f57e52d4886266fbd39a9f18d22707e112322314731de6f3de7",
    )
    _check_multiple(
        curve,
        "62ca16a6692e64880183913a1edbae62b210b26fa3b9d506e102498e304fc5f0",
        "042a6a1d44c1d5b5640baa662674fdff0bae37fa2f47d84541c88700ba07eef1d377c5672b118d2984ad3c25eca1a564a22500107ccee65008b07b1e733752ff5f",
    )
    _check_multiple(
        curve,
        "91cad90a9d9ded33bd556b678c6c28b64123b775a3aa914e8fdd47dae9d982de",
        "04968ed421bcea9181156b0c595fe6c1482480ed796ddc0699bdf29f183972f2bb8e857610b253447478ca868c33d9379c00f1414ebef96375a67ad771957e3a8c",
    )
    _check_multiple(
        curve,
        "7e8d3db28baa34760d86ec35273a5c6ca8d439cdc7395d538bc8ec268522095a",
        "0400644d3dadb02e98301e08fa914f99228f652c4a4dd1946c67df11ea6514165c6f6a8e4c0a48f8acc804921c2a3892fbdfca1e322cefa9441b5f624f1620edf6",
    )
    _check_multiple(
        curve,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794",
    )
    _check_multiple(
        curve,
        "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        "04ec1b5435703b3a7af44594edcd99e1247484e2fb6f1ba3d10b2dbdbddd3d6a69684e0383d6a12f2819c1c94c861dbff390b69cfc74ba9868aaf00fb7f5217012",
    )
    _check_multiple(
        curve,
        "8888888888888888888888888888888888888888888888888888888888888888",
        "047f22411445de76e65c4a6f8089e84514a5e1075c05acee891106eaf375a577d1ff30faa71c10969eee5bab7afbaad6eb478b05435c172a2c4a82afbcdd587d23",
    )


def test_scalar_mul_p256() raises:
    ref curve = p256_curve()
    _check_scalar_mul(
        curve,
        "7b91dbda458a35463e7e8af7f27cbd3665458abcf577b23a654ec83284b197b9",
        "04bc69d456c35d7786333b8d46473665c644595907bd893288fe3ae7ebede46351ae53287bd08b2d8838c1841465a167e422298565b74c4995a838f7bb5ec357d4",
        "04ef483d3be3c7dee5983f32ff3a612291e69294c104c092a00979a13ad4f1f63e03791a3ac6d08abcfc2ec6bbae8416be21a62c860a1d323185c263b22a8995be",
    )
    _check_scalar_mul(
        curve,
        "a5e9db28babf51fab73dac4a78c22fe3fbbb76818a85bd1367a806637f4b8517",
        "040354fc73df0188550bbe38f417fc3b791289e99aa1dd3238d4deaf8fe3722659b6b379d64535d5a76a7a5cffc8b32aa8a019fa8b3960262529b96cdbb3ef7687",
        "04b5c4c688a5a89766edd9617c01ed330c3a29a99df1e1b2a24fa0afe4b4dc83c13876d43bb83fe99fcc78701dfabef33e89c0b61459d9bf7ba1f462ceda8ea896",
    )
    _check_scalar_mul(
        curve,
        "7fe32a1c471ecf1af3881b2fbc50610cc79f7addfceebac4a661f33b16278003",
        "0444bcd0ece7f3673fe8a52df1f29d59bca1b0b4e3c83b6fb1b73fe39f526b937628bef3f2baad71e6089715f9499ba86a388e75cd078205f3ddc2c9294fd7e70e",
        "041f7c56043f99a91e1ee7ff8ff3c5a3283156f991e31de118a71919250c2013a1335fbd21b98b01b5c1a0a36ae991a219282a456fef1794722835ed6f53fb27bf",
    )
    _check_scalar_mul(
        curve,
        "c066bcca945e14e6ff0004943dd16b983eead1cb721ffdb7905bec738d9de01b",
        "0452470ebee9382190db6bfd9d0cecceea46b2fc3811eaf6f0c635a7212b14c17826ada1b51c2220614b173dbfab3cec93f5f4c8db98f528c926f6087ad4c5e392",
        "04ea10f460b1d5eef4377fc016e973fcc74ca421f3ba0d7e845d33cd50e5e546ceff64e5ad326b243c9fa418d00e2489bf034afa8498a0478a213f1af87beddf26",
    )
    _check_scalar_mul(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
        "infinity",
    )
    _check_scalar_mul(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
    )
    _check_scalar_mul(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c51463d6872570f238ff5d9e7ac7427cffeb419ef81cecfbfa311bdaf77771d873ad62",
    )
    _check_scalar_mul(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
        "infinity",
    )
    _check_scalar_mul(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "04687a22ec11f3bd03ea53563fab6f8ea8f3c34f5446956c8206168fdf86c514632978da8e0dc700a3618538bd830014be6107e3140405cee42508888e278c529d",
        "0496345342c4e12100b19c98f8a4dea17be4d1aaa78f52ff1fc0106cb8665253f5e4198f02e3e6c7795411cde471634e8681561ef7fce224ea8dee0ddd692e3559",
    )


def test_double_scalar_mul_p256() raises:
    ref curve = p256_curve()
    _check_double_scalar(
        curve,
        "bb943c3dd0b2555c0dafbec49b55ecd09081e74075ffb40ea47431de61daac7b",
        "b296ba69895693f96cb120e806b6c03d8b076a3a0d5d66fdd54910958d01a797",
        "043158e0e3f7478791076d69ade084fb54f89be2f9b72fcd802ec15b5d95c4deb11be619c22fcd6fbf9f4bd091d90c671fc9679325b7a7b62013cf68de12456d0b",
        "0446697ea375a47f29ead756b35b7d75e17799bcd83625f0683621fd6e9db9ef242618b940e64671436b79633fae3bc8d5e33b10e0c5fb6398084af905c89ea8b2",
    )
    _check_double_scalar(
        curve,
        "95deb0885b27efa2ef3869bb858f5850913e52ee6bf69d88892cb9eac8663cf7",
        "b624347a19a32003b4ef7693e55034781af2efb7023d0222481c61ca7dd27bf5",
        "0435db92b3375fdd9a909459a24e13588010608540a168cbd62022493359114109454d911c081c087b24b38c4d4248d720fbc865112745dac9f41fec0934f93e60",
        "04df5ef2d1178c911afddef19e604e44484f052e5bf05033150d26adc405f1329f0fa721b01b2cc6b8809451651eb8ef3ea30ef1437b7d80dcd80d6e103ebc4046",
    )
    _check_double_scalar(
        curve,
        "c6941c666de845858f84dfb79f04e548d26cef77b53e35b1c77aef5b921428fe",
        "5525bb456af414e3775082e5d7052aebdfa3beb98fbfbfc7277f386edc96b083",
        "04acb01ebfac0dba21031dea251ef743534b92fbfa1f9edb8f7215246e8a238d5bac21fe36473e45df5b0e36e881d0c03c4004c73e2738dd07a15ad86bee99832d",
        "04b628291b0abc07bc64bb63f7031be0719b7c1c7a27cd83f478f7d9d4a4e499f89000de2c83a17c28fa12f9cc1e8f5a732c3852508e4c2dc67f0ddb34a7ca8da2",
    )
    _check_double_scalar(
        curve,
        "0b2273c7435ec3aa9a96dd4f4fe6e4930365d56fc55916a13f83e96a0a7d1cb8",
        "4b80d12164ac77d48602f25e32907a3dee105ec3184aeb26aaecc14ff756fd44",
        "045d51af7a567c62d8c1f6b8fd077cf48fba37e090a15e9d495ab319201b64e8f079aede31493ace1a56ca3167914b46771cbd028199b8796225f8065c21e56740",
        "0404ac2f83293600a95c6c31c66c26a429a92feee07ad5cddd280fc80e351744c5e1139cb8ab458b05ef90f4c48147f8e6097f7a406e66a3cb14ae4016bc4a7dfd",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "044813a01966570e44cb0c661b09e1aeb51c770f4a41fbc91250baf0a86e6f52cd61eb20961a39f1932cf20bd7b47311325598f4cfd038a539e1abf6160aa8951a",
    )
    _check_double_scalar(
        curve,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "044813a01966570e44cb0c661b09e1aeb51c770f4a41fbc91250baf0a86e6f52cd9e14df68e5c60e6dd30df4284b8ceecdaa670b312fc75ac61e5409e9f5576ae5",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "0000000000000000000000000000000000000000000000000000000000000005",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "04741dd5bda817d95e4626537320e5d55179983028b2f82c99d500c5ee8624e3c40770b46a9c385fdc567383554887b1548eeb912c35ba5ca71995ff22cd4481d3",
    )
    _check_double_scalar(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "04aeec1a95be3248db56b238cf740cbacbacd96b24da00864c881734e7500145fb5d40296b18060c91e51d1c3c19b6b2932b16d6b43826ca18faba3572834494c0",
        "041bd4e24b0e7266bee90681c477b648e905543e606da4d5ba88d1aabda1617ef373f41a744d62cf6b490a21e5cae8943bcf650a32bf4a8ff11f4157322b928a94",
    )
    _check_double_scalar(
        curve,
        "2ce81065694ef1e74a51f05c0874911a10ea58908daf64ed023d1db7e5b774cd",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        "047bc2375cc73d705838a08c5c216b97be85f0a902476cd763ebcd33cd520c3a72d2efa5b4eca898473560090688a93258952c958c0cdc128252449a2e527f11fb",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "2ce81065694ef1e74a51f05c0874911a10ea58908daf64ed023d1db7e5b774cd",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "047bc2375cc73d705838a08c5c216b97be85f0a902476cd763ebcd33cd520c3a72d2efa5b4eca898473560090688a93258952c958c0cdc128252449a2e527f11fb",
        "04f7bc21d5b0356bd6c235498fb100ccd5a0da02951b39c3633ce3e98736d8b94f1d595b3e8d7b253a0d48d17f34b9635eeb3d918f0e5c7ef1b81bfff242cbd450",
    )
    _check_double_scalar(
        curve,
        "d317ef9996b10e19b5ae0fa3f78b6ee5abfca21d19683997f17cad0b16abb084",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "047bc2375cc73d705838a08c5c216b97be85f0a902476cd763ebcd33cd520c3a72d2efa5b4eca898473560090688a93258952c958c0cdc128252449a2e527f11fb",
        "infinity",
    )


def test_precomputed_constants_p384() raises:
    _check_constants(
        p384_curve(),
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    )


def test_group_law_p384() raises:
    _check_group_law(p384_curve())


def test_base_point_multiples_p384() raises:
    ref curve = p384_curve()
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "infinity",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
        "0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
        "04077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831c995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1",
    )
    _check_multiple(
        curve,
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f",
        "04b3d13fc8b32b01058cc15c11d813525522a94156fff01c205b21f9f7da7c4e9ca849557a10b6383b4b88701a9606860b152919e7df9162a61b049b2536164b1beebac4a11d749af484d1114373dfbfd9838d24f8b284af50985d588d33f7bd62",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010",
        "04d5d89c3b5282369c5fbd88e2b231511a6b80dff0e5152cf6a464fa9428a8583bac8ebc773d157811a462b892401dafcfd815229de12906d241816d5e9a9448f1d41d4fc40e2a3bdb9caba57e440a7abad1210cb8f49bf2236822b755ebab3673",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
        "044099952208b4889600a5ebbcb13e1a32692befb0733b41e6dcc614e42e5805f817012a991af1f486caf3a9add9ffcc035ecf94777833059839474594af603598163ad3f8008ad0cd9b797d277f2388b304da4d2faa9680ecfa650ef5e23b09a0",
    )
    _check_multiple(
        curve,
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff",
        "04127988c63c9328dd60dfd83b205a3ae1123e7f8f89e7d9e726c1f58ea69039a6e24efc663a13fde1af118ef7617501fffa5a1db9013191fad4311e5ebe5c4d37cd63c1ee5337ecec8baa7efe5774e95701476776ac4a3fe80eac6612282529a9",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000",
        "04079dc566510cc718ff348797e2cfe67c2fce93bf5f6f39bf74c1ac3d8cbae3ef92dd9cdedfa0f56d06ba5918d74d9642a64da09a5d9087bc89a8437e5c806f88626377708484b5f136275538892459a929f49d50cc51c42fa0ecd5d0c16bb523",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000",
        "04f532389a060cbd1bd6e98b0d37ca7abc4360390918141b1a4b58808b3f8686a92c3e0c91558717db39c1b328d8ee21c9b9d2852cc3b38e696f04caa2de3a82babd22cfb2a2124163bc40ce5abe64360331ea31b1085a4e9a7a7e183923d86ecd",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff",
        "04baac2a11737aa82e4813b41d785143251494915bf86ecc5daff1c5630b161411a8dbbcaca70d49bc9e422112899321785d1519d1e04d5f69424327ecd2a1bd5e51426088eaf88612b78d90015896f7ee563c325940abad953b2ca660ff65802f",
    )
    _check_multiple(
        curve,
        "000000000000000000000000000000000000000000000001000000000000000000000001000000000000000000000001",
        "04dc916c17960e090efafce26e0381ef13bf88de7f4862b95425651d105052dd32451c707a371a2ca5300ae2e60e758344266e8a40d69eca0ab3d92ea4701c295252d154b80ba04a3540896478cc16069795c01ff19b42441bed17cc44026b0889",
    )
    _check_multiple(
        curve,
        "000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000",
        "04b2d1055817cbaa12211905035f4972d7097da395a23096863d8b29dbd08848c2f33a450ad156f761e4bfc2c04905ca71354cd872c3c6cbd2237c0dba3cfd056bf82be8f52e6236c09b475d744ecf1a68e87ab07c6924666fddcebb55753ee324",
    )
    _check_multiple(
        curve,
        "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "04e3e25cdb160208b6474e2b34d72bf586bba14f72c3f97f515a405d1429196e6673161b78ad80afe664ee504d4b161ab73770b64d5442695959fb89da7eb3a7cafcba079d32031df6213049c1cc509e3f9120caf8dd9109115f403859ac337acc",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971",
        "0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61717f0e05a4e4c312484017200292458b4d8a278a43933bc16fb1afa0da954bd9a002bc15b2c61dd29eafe190f56bf17f",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "infinity",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    )
    _check_multiple(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "048e32381850a570e53d52786a71e833a22cf810c0c2d8f8414ed61004d6a8ae364a3ac516938f22508fce11b165b6bf3bd262873a4c3cf596bc850e06f232d7ee92dbe041e3a5fa88b5aa8beb0d30d55beb832bd2be40e2fbd58b6a6d63971efd",
    )
    _check_multiple(
        curve,
        "c3e5b05ec3932c3b0697319bb1c15cdc47028082cef9b3ffca8feb00ac4258b0cb1ff192b59a6c3d924cbed331089ade",
        "0436e046c0084321ba26a2b874e44ee584ecd6df811597106f7043d9539b4a957e5a4f053a94d1340a8cb82bbc8637a6970f1054cc3ccb43b5af8544b60d5451e91bd8bdceb48c650e4976fe2f3bdb080addd13af6a6dffe5a32163387da408ac7",
    )
    _check_multiple(
        curve,
        "5954f3ee7e1d425be0f50abc5d0455a7f397a6ad779b945da8b9a5a69b1ab054c850a260fff8360936e594c2a5876b30",
        "04f94ba4658f1468fa2598b96238f72b45f6d5938aafc749b242cfc25ba55641b4e0deff79bc3708bcb05c7d64b772046ac73118cf689049525842af92cea3d5997a33ab3ed2b9a8b0d0d9335c30d6984ce40d0d53108b75cda347da5f4c3cad9b",
    )
    _check_multiple(
        curve,
        "2c9e6c1ed3b3be38423fa733c70332080639de814cff7fa64e972fe44ebdffb5af804c9d2e2fbd1feb704d76309893c7",
        "04adccfe2f26bd60a2f6b8674fc8e44dd341a7114191779ddf0fd8b9e647112970869904694a61c7f7360277272bc7981636426c64dc7e7f27c3305b9b565e367fe4e1014cac62f397c4e160bfc14d94895718af5b4ba6f2a6bd78389c99c544ab",
    )
    _check_multiple(
        curve,
        "9008b3ea80351205750bf4e8a26298b6d753ec069db4a053994a28da893bcd9de94bf557d10d819b41cefcc018f01bf7",
        "048f05cad154de09edca1386d8f3a4c07d87efef4167cd790ec5702e75cc40eed9261a4898a215a086c31c1813802eb320500c4b54a3f0dddefbaf2a20d355c690ef8e26dd167b96ed9a422460a8c314118ca7f295e892e2e438d8c1f0416506e2",
    )
    _check_multiple(
        curve,
        "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "04386e767ea5cb716c9cd620ff7342129c892a6fccefe612140c80bff59e943468019dda16e5079b0c1d9001d23a624b6dd088d0c3826394194787403e8a7d07e5e22f7e9c0b8e80fa1faff5d28b4bb597b267f0b87023ca61fc8454bddefd2e0e",
    )
    _check_multiple(
        curve,
        "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        "0409a93ebb5fdc62a052e62b46ff7f04966dcb36283993a6615eb5cd25601ad235d5b0f51b370271673f7c5cc0fa7820160383c296a10f4e743edca47662407309194fdd3af1085fc15adc43d2602bf7cbf5fc61b1b969a554cf5bc0101fba3962",
    )
    _check_multiple(
        curve,
        "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888",
        "0438bcb3028cb1210b18a4324eb6f1a626ac13812d60332b284e57ba9e6fe8347cd0a6b896975654a79e0b04472331c72ee20c3a8d01cba254d2597d40a9101df30d1618e3b6d4292a0f62e1704f3300fbecadd9478a1553b7902a39f5812ca239",
    )


def test_scalar_mul_p384() raises:
    ref curve = p384_curve()
    _check_scalar_mul(
        curve,
        "65979d4508895eacfb6f86aa789c4c61e54036d78346219e3cfb05cf65575131644fc76cb5fd7238df80d8ca55090cf6",
        "04363e7f3814e40ebe3ef083b968a994740c1615c8b0416d2ed4f5081a0b3d1fefff475249e15189822af8a0c622aa29918a26df69c6f7fb4f670904d4787f20ecd18f22434faa1d8cf381a0b34295898e1b3b8e9e1c168530def4f0c58f003a86",
        "046001c095659d64f480867ce1a34155e6a1fe6cdc1a947bce69efba73f0c687886d3e5769264d4b35260d72d357bb34834dddde009f2194d32b1e994ec86817a43565276fd3df5b7aa3b5f43c838dcf7a1f67aebdbbfd9351a6cd134721634388",
    )
    _check_scalar_mul(
        curve,
        "fdeb009226c8b08849a325285fccd3637413ad5dd2a7c97bd55bc8cf24ebbbd74cd157faaa8fd030286fb5cee0b1b258",
        "04a7412ed3176a18fe00aa5e4b9400edefbf0fcc2b795355ce21a522113fe8abe91f2803f8babd88f5471251894db9b9caeb77ab61e1285f18b22be11c79e54af828f624386024b7c662c3ed2c1d03802b85f017930e592e1f157dd0f9d9b984f1",
        "048ddd5a85d824decba717ef70252714bc0715b2ea5c517d5425ed2052ac473ab0b727b736adba358ec310c3fdb6945087874b9ca2169ec9328495ddb312f60a120ab7a86850a57d58759635d789a2c992969b0c5c78e86c65bfd7c29877aef302",
    )
    _check_scalar_mul(
        curve,
        "10d3f11036afe1e867aa00a24ebb35ef1805d691d2fc423522e34fe8067730fb5f8d8c889b8c463e72803467c155f682",
        "046210670d1973ce6951fae33f8df60b70aab8047d8fd395037180adb51ed7a67732f92332e4c759710162bef0fa866752a036e26fb6bd91ae8ebfa2d6c31ca0c12ea1a41087418ea820af56cc18396441fc00674c3f7538aa63985f06c0e13677",
        "04b39e30471853cf2f0adb67c734d5a56acc90d1ecfc46a3dc25cfee88bfb78ddb88f9f329f7fdfb1ef3cf8f860cea62be78bf37521f11b967620641e2de59f8bdf89439abc9c552e8f3c08a7c553ad5bdf37f762e17505c5807c53c23e201d327",
    )
    _check_scalar_mul(
        curve,
        "17040439da4a8d07f72aa1974b4fcb6863f7a6f55ca3772416447c1105632ef906668565e8a23e6af26d322cb262c034",
        "04841b9b4d5578007673319dfa46fa0208cf76c05cafe6fb9d66b7e91d3e566ad64f72d76862ae254613166509886610a2763d109a5f26f32cb1070601316ebe6ae6da101e822da6072e88d09cd1fe4be5cc8ae14340836310f6555ed198aceb5f",
        "042463f132fd9d91d66f2f238dc8082d1b97b580e3b8f85b3f0bf5f16c8b61d5e74b2b3add2817ea09256fe897ff5a9a5fb3b69b7337e1c760ed5908014471fe26f185f4324a4b93f4a00de6480b49523dcfbdb63568bccd9e02baa792ca9dd174",
    )
    _check_scalar_mul(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
        "infinity",
    )
    _check_scalar_mul(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
    )
    _check_scalar_mul(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7b7b2b5dadce281cd353b167755ddccb4a10d31c317a4f157daf8f9a806f38ca5beccd599530b274132f90464bc734383",
    )
    _check_scalar_mul(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
        "infinity",
    )
    _check_scalar_mul(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "04aea5310e70b84746121b53cb8dd4019e33d20b77fd60702aba1c9e198685750a03084433f329eb14fd36238fde69e5f7484d4a25231d7e32cac4e988aa22334b5ef2ce3ce85b0ea825070657f90c735941332a65acf4d8becd06fb9c438cbc7c",
        "04b6151dd0d80edc209ea6f592556169e1ebc9303587ff9fa74c26e31a5865b0c981bc2eb64f0c40e47267bfefb173411cea2b88e22e96a7e4471df29e795b7dbd306083ef3dc03f9b521c0003b6608bf310fd97478c0b982ed688d9a3ab0a65e0",
    )


def test_double_scalar_mul_p384() raises:
    ref curve = p384_curve()
    _check_double_scalar(
        curve,
        "bbbc08bf0097cec53574690afb8f821649bc690bb4f155258ce9bacb5d779a4705095891f274f18cbe12a8721d9811bf",
        "2ff3da9d412203f190606a66f53c231b5f9d348783e64ac4890884f6e5ecbff1a34e9e405e1dd4a417646e37a22c116f",
        "042178bf6f50b93b70efdceddb515da838c2f4b0ba8c444bbd5e6354bf1233bdf8bca1cb66a02bd4c2cc89fc1d9fdab2388feb983eeff8d15673f6b7cee17d478e17e99067c4ff4abe2f3e99169acf2f0bf9ece9240d8e0104bad48c3fc17ddbc4",
        "048d5c6020f851535ae2374027cbcb82d22ca2899d127803540c6d4ba13fbc10c2436163e55efa57a7d93dcc3036d25da41b5e15ba0ef862f37d7d6a63dd8db65dd5ba546ad6a10f7ee7b2974771155600966ece55e79b056b510d21f0656cf2da",
    )
    _check_double_scalar(
        curve,
        "c50ee3a1a84653220439050af65ca8250e87e61c0a0c8f3292b2fc0e34ffac91b8053d0dd586d55543529d237400b7c7",
        "5b98273ffcc5b37db8b69c719f711c99f8e6052bd1a8a7ac4801c0e0b0c144f3f1a59e361201647aaa79f23508c228cb",
        "041230169247f205260f0df004ddf24d6e81cb155754a6b7f3b31d04edb35926285f0a347401cecf05a9281db552e03a7db3b76ef5fcc288c3c4ba3a66c4a0caa40c2bf07cabd65292c10bfa5afd38962ffe7d0c2b0d857d6dc75cf7a6a4c7b499",
        "04b5827ee4de7d5d30a3f8aa0950b8040b1871e7da2180d8bbdea466271e7d51b678265ea48bd6536cad3eeb8a1e7fe2760e3622531f4b1bc3a2bb348107d3b3de4402367bbb34f161975ff71f1edc4068c1c6467b978a10033dddfc3890c50606",
    )
    _check_double_scalar(
        curve,
        "e485371551ea5c66e7c8d79dba447f042a527aaabb71ca92d4c92b93de160680e9bd54c9c495dcb3fd186af859d2ac81",
        "4a193baf916c72ead32bcf058f1ec63da45bc1596f2babdaa8ca486cc5550d5afd760ff67c4e121595c703052c11033f",
        "040854442d5cefb9660a64dcb45a7e929562185f1b116a5023075bddf90704498581f9684cee5c1f5f1e1666cdf242835ada38a3c42c0f8d841022c30cbbad98aac1ff8e55d755e5c3a434edfa6a5433f2586173a4c73d6c7de1346d50078a4b0d",
        "04b13395952d1bee172d128117ad89033f1298d271e26c8c86659e2c8b3f066b775f8453cdb8bdc83854eccb582657d770d505682fe6a17d66e9d5f90c54a063d8239a7f54d817be1a0f28fcdfcf66cab7074b975161264dd42031521f9718e65b",
    )
    _check_double_scalar(
        curve,
        "8f767bf9740beec401465e37b8986e80152ec9e8e62fcc2915faa6a1589472a65806c4145bc746fc46d056a211276269",
        "6f3d7a59ea1028c557fbfe3a5d2222b24f645ca9017a9cd63c0e205ca26e886e0c24e937f7bfe07c1b73c8ca368a44a9",
        "041dbcede961de9ad5af5152e2b990c7f7737c0c8e66a14989d5603f225c34b4b01dbd94607177892af0c98700c9a6868fba2b963c1dba970f8d786d062ba27b80792eaf01db965a9f67c445d4488f0a3c959377164b50caa26fae300a7182f2a1",
        "048dca26e0257017bdb77d457cff150d7c7047bd6f43c81d4cdc3286b5f375567fc1479cbfd4c67d79cfd7cfd767cb92f3dfad35033fbe833962df5be359fc5bae7cad9f1fd4c363b73ddbcec49d35e5573551de67481f8b0f4e178452e91b2780",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "042d83a7be986423d5f9c27baefb2decd10b66604a74843c9738ad3575a3e8dfe955f6c1fb102e6a10938a53943de5823d41622482ddfd3a6e82232a1bbaa0d39e5662a5c1a5eed124576a6ba57d30fbccf1d85a137e096cf79725b65f20d726a3",
    )
    _check_double_scalar(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "042d83a7be986423d5f9c27baefb2decd10b66604a74843c9738ad3575a3e8dfe955f6c1fb102e6a10938a53943de5823dbe9ddb7d2202c5917ddcd5e4455f2c61a99d5a3e5a112edba895945a82cf04320e27a5eb81f6930868da49a1df28d95c",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        "0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007",
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        "04952a7a349bd49289ab3ac421dcf683d08c2ed5e41f6d0e21648af2691a481406da4a5e22da817cb466da2ea77d2a7022a0320faf84b5bc0563052deae6f66f2e09fb8036ce18a0ebb9028b096196b50d031aa64589743e229ef6bacce21bd16e",
    )
    _check_double_scalar(
        curve,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "04168e44fd349aca77e38680107a4e6417c1aed7252888938ff8cfc7f132c9ca6f0c183a4dc8cf97a6a10322dd487f692ac16acd2fa776d08aac97d29b25338b0dfa04068ce164b56fcc227c073ac87c97489ea91a8ff52a4fb4494c995ef7137c",
        "047ed39ecb8150c3a4bf19a69c440ebb08a375f4944231de2b7c1312f9e9b4a69c49deaa1e62eb806b509042e61f100cce9a008b2b4629907160b0288b98ffe11cdba49b57fa89e84c4158387c5607a5942f2dc31a40c2697396830a71e00d6a7b",
    )
    _check_double_scalar(
        curve,
        "aa1fa229c60def8e9f204162aba1be95d53719c79e23c5e1999a13ddd2b96374f883af8a85a337820166d25d147ce8b7",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        "04abd6a82fcf95651f645ad95f3bb4231d9513d1c46ade0a1b98fd2345db70913c92b0e2e5a2ce4faa219fedc8415f09293a7c894d3fba11c063821f0c7e3e5adef285e53bafc31ab8dfcd5c409c1abfff7850a2dfb7ebee0e9dc00560aef01c2a",
        "infinity",
    )
    _check_double_scalar(
        curve,
        "aa1fa229c60def8e9f204162aba1be95d53719c79e23c5e1999a13ddd2b96374f883af8a85a337820166d25d147ce8b7",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04abd6a82fcf95651f645ad95f3bb4231d9513d1c46ade0a1b98fd2345db70913c92b0e2e5a2ce4faa219fedc8415f09293a7c894d3fba11c063821f0c7e3e5adef285e53bafc31ab8dfcd5c409c1abfff7850a2dfb7ebee0e9dc00560aef01c2a",
        "04dbaa2749d95e7e577cef9eccba9cdfe16a8b31d258dc69861713859e0365aa60842cfacda17d78fd0b19096969148079ed9a150afeb411a843a74a0478a6efcde6d51e98576e4c8913a02e8e6057e212fdef693b26561dae08a50092455f1101",
    )
    _check_double_scalar(
        curve,
        "55e05dd639f2107160dfbe9d545e416a2ac8e63861dc3a1e2dc939a4217dca6a5f965e27c30d6ff8eb85470db84840bc",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        "04abd6a82fcf95651f645ad95f3bb4231d9513d1c46ade0a1b98fd2345db70913c92b0e2e5a2ce4faa219fedc8415f09293a7c894d3fba11c063821f0c7e3e5adef285e53bafc31ab8dfcd5c409c1abfff7850a2dfb7ebee0e9dc00560aef01c2a",
        "infinity",
    )


def _decodes[n: Int](curve: Curve[n], text: StringSpan) raises -> Bool:
    var zero = Array[UInt64, n](fill=0)
    var point = AffinePoint[n](zero.copy(), zero^)
    var bytes = hex_decode(text)
    return curve.decode_point(Span(bytes), point)


def _scalar_ok[n: Int](curve: Curve[n], text: StringSpan) raises -> Bool:
    var k = Array[UInt64, n](fill=0)
    var bytes = hex_decode(text)
    return curve.decode_scalar(Span(bytes), k)


def test_point_decoding_p256() raises:
    ref curve = p256_curve()
    var g = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    assert_true(_decodes(curve, g))
    var encoded = curve.encode_point(curve.generator)
    assert_equal(hex_encode(Span(encoded)), g)
    # Wrong prefix: compressed, hybrid, infinity.
    assert_false(
        _decodes(
            curve,
            "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
    )
    assert_false(
        _decodes(
            curve,
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
    )
    assert_false(
        _decodes(
            curve,
            "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    )
    assert_false(
        _decodes(
            curve,
            "066b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    )
    assert_false(
        _decodes(
            curve,
            "006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    )
    assert_false(_decodes(curve, "00"))
    assert_false(_decodes(curve, ""))
    # Wrong length.
    assert_false(
        _decodes(
            curve,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51",
        )
    )
    assert_false(
        _decodes(
            curve,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f500",
        )
    )
    # Not on the curve: (0, 0), swapped coordinates, y off by one.
    assert_false(
        _decodes(
            curve,
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
    )
    assert_false(
        _decodes(
            curve,
            "044fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f56b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
    )
    assert_false(
        _decodes(
            curve,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
        )
    )
    # Coordinates not below p, although they are congruent to G.
    assert_false(
        _decodes(
            curve,
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    )
    assert_false(
        _decodes(
            curve,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    )
    # The negated generator is a valid point.
    assert_true(
        _decodes(
            curve,
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
        )
    )


def test_scalar_decoding_p256() raises:
    ref curve = p256_curve()
    assert_true(
        _scalar_ok(
            curve,
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_true(
        _scalar_ok(
            curve,
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "00000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "000000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_false(_scalar_ok(curve, ""))


def test_digest_to_scalar_p256() raises:
    ref curve = p256_curve()
    var d0 = hex_decode("")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d0))),
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    var d1 = hex_decode("01")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d1))),
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    var d2 = hex_decode("0102030405060708090a0b0c0d0e0f1011121314")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d2))),
        "0000000000000000000000000102030405060708090a0b0c0d0e0f1011121314",
    )
    var d3 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d3))),
        "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae",
    )
    var d4 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d4))),
        "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae",
    )
    var d5 = hex_decode(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d5))),
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    var d6 = hex_decode(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d6))),
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    )
    var d7 = hex_decode(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556aabb"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d7))),
        "0000000000000000000000000000000000000000000000000000000000000005",
    )
    var d8 = hex_decode(
        "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828300000000000000000000000000000000"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d8))),
        "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283",
    )
    assert_equal(
        _hex(curve.x_mod_order(curve.generator)),
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    )


def test_point_decoding_p384() raises:
    ref curve = p384_curve()
    var g = "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
    assert_true(_decodes(curve, g))
    var encoded = curve.encode_point(curve.generator)
    assert_equal(hex_encode(Span(encoded)), g)
    # Wrong prefix: compressed, hybrid, infinity.
    assert_false(
        _decodes(
            curve,
            "02aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        )
    )
    assert_false(
        _decodes(
            curve,
            "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        )
    )
    assert_false(
        _decodes(
            curve,
            "02aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    )
    assert_false(
        _decodes(
            curve,
            "06aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    )
    assert_false(
        _decodes(
            curve,
            "00aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    )
    assert_false(_decodes(curve, "00"))
    assert_false(_decodes(curve, ""))
    # Wrong length.
    assert_false(
        _decodes(
            curve,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f00",
        )
    )
    # Not on the curve: (0, 0), swapped coordinates, y off by one.
    assert_false(
        _decodes(
            curve,
            "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
    )
    assert_false(
        _decodes(
            curve,
            "043617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5faa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e60",
        )
    )
    # Coordinates not below p, although they are congruent to G.
    assert_false(
        _decodes(
            curve,
            "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    )
    assert_false(
        _decodes(
            curve,
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    )
    # The negated generator is a valid point.
    assert_true(
        _decodes(
            curve,
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0",
        )
    )


def test_scalar_decoding_p384() raises:
    ref curve = p384_curve()
    assert_true(
        _scalar_ok(
            curve,
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_true(
        _scalar_ok(
            curve,
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_false(
        _scalar_ok(
            curve,
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
        )
    )
    assert_false(_scalar_ok(curve, ""))


def test_digest_to_scalar_p384() raises:
    ref curve = p384_curve()
    var d0 = hex_decode("")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d0))),
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    var d1 = hex_decode("01")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d1))),
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    )
    var d2 = hex_decode("0102030405060708090a0b0c0d0e0f1011121314")
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d2))),
        "000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f1011121314",
    )
    var d3 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d3))),
        "000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68c",
    )
    var d4 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d4))),
        "000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68c",
    )
    var d5 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d5))),
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    )
    var d6 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d6))),
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
    )
    var d7 = hex_decode(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52978aabb"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d7))),
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005",
    )
    var d8 = hex_decode(
        "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091929300000000000000000000000000000000"
    )
    assert_equal(
        _hex(curve.digest_to_scalar(Span(d8))),
        "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293",
    )
    assert_equal(
        _hex(curve.x_mod_order(curve.generator)),
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    )


def _check_nonce[
    H: Hash
](
    private_key: StringSpan,
    hashed: StringSpan,
    first: StringSpan,
    second: StringSpan,
) raises:
    var key = hex_decode(private_key)
    var h = hex_decode(hashed)
    var generator = Rfc6979[H](Span(key), Span(h))
    var k1 = generator.generate(len(key))
    assert_equal(hex_encode(Span(k1)), first)
    var k2 = generator.generate(len(key))
    assert_equal(hex_encode(Span(k2)), second)


def test_rfc6979_nonces_p256() raises:
    # RFC 6979 A.2.5: the `k` values. The second candidate of each
    # generator, which the RFC does not list, comes from an independent
    # implementation of section 3.2.
    # SHA-1, "sample".
    _check_nonce[Sha1](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "0000000000000000000000008151325dcdbae9e0ff95f9f9658432dbedfdb209",
        "882905f1227fd620fbf2abf21244f0ba83d0dc3a9103dbbee43a1fb858109db4",
        "408db15631f27185b08ff01830d5ba788f06eb7c2b6cdf4d4307f31d2d3c071f",
    )
    # SHA-256, "sample".
    _check_nonce[Sha256](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        "8e83dc490bc5fc4d5992bd63cd87f254adffcb930f8a8011702a88870f638fdb",
    )
    # SHA-384, "sample".
    _check_nonce[Sha384](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312",
        "09f634b188cefd98e7ec88b1aa9852d734d0bc272f7d2a47decc6ebeb375aad4",
        "6a344c70adaa24d1f758c8fca623efa725f3857e01757e2d99cdc6d73501d5c5",
    )
    # SHA-512, "sample".
    _check_nonce[Sha512](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f4",
        "5fa81c63109badb88c1f367b47da606da28cad69aa22c4fe6ad7df73a7173aa5",
        "93a91fa90cbea561665d37f94431ca1a40a817981ae7181d2194f44a1168e19b",
    )
    # SHA-1, "test".
    _check_nonce[Sha1](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "000000000000000000000000a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "8c9520267c55d6b980df741e56b4adee114d84fbfa2e62137954164028632a2e",
        "e633c928ea65588c78dc4b4688eed0a9eaefdd925055b4d8f48d517611b6cfdc",
    )
    # SHA-256, "test".
    _check_nonce[Sha256](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
        "ed6fc87dcb558274e84d7d3799f12f8f279c07fa5301a7cd33f0ad9866cd8ca0",
    )
    # SHA-384, "test".
    _check_nonce[Sha384](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4",
        "16aeffa357260b04b1dd199693960740066c1a8f3e8edd79070aa914d361b3b8",
        "83092c432d924d545245519fb7ebe88214028dce01328ffd435835340d5f8774",
    )
    # SHA-512, "test".
    _check_nonce[Sha512](
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2",
        "6915d11632aca3c40d5d51c08daf9c555933819548784480e93499000d9f0b7f",
        "0ab4cb1796526c9eef6a74bf8313338d172bb0ee7434b6daeea9df348c29b019",
    )


def _check_rfc6979_p256[
    H: Hash
](message: StringSpan, digest: Span[UInt8, _], signature: StringSpan) raises:
    ref curve = p256_curve()
    var key = hex_decode(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    )
    var public_key = hex_decode(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    )
    var sig = ecdsa_sign[H=H](curve, Span(key), digest)
    assert_equal(hex_encode(Span(sig)), signature, msg=String(message))
    assert_true(ecdsa_verify(curve, Span(public_key), digest, Span(sig)))


def test_rfc6979_signatures_p256() raises:
    # RFC 6979 A.2.5, every hash this library has. Digests shorter and
    # longer than the group order exercise bits2int.
    var m0 = bytes_of("sample")
    var d0 = sha1(Span(m0))
    _check_rfc6979_p256[Sha1](
        "SHA-1 sample",
        Span(d0),
        "61340c88c3aaebeb4f6d667f672ca9759a6ccaa9fa8811313039ee4a35471d326d7f147dac089441bb2e2fe8f7a3fa264b9c475098fdcf6e00d7c996e1b8b7eb",
    )
    var m1 = bytes_of("sample")
    var d1 = sha256(Span(m1))
    _check_rfc6979_p256[Sha256](
        "SHA-256 sample",
        Span(d1),
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    )
    var m2 = bytes_of("sample")
    var d2 = sha384(Span(m2))
    _check_rfc6979_p256[Sha384](
        "SHA-384 sample",
        Span(d2),
        "0eafea039b20e9b42309fb1d89e213057cbf973dc0cfc8f129edddc800ef77194861f0491e6998b9455193e34e7b0d284ddd7149a74b95b9261f13abde940954",
    )
    var m3 = bytes_of("sample")
    var d3 = sha512(Span(m3))
    _check_rfc6979_p256[Sha512](
        "SHA-512 sample",
        Span(d3),
        "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f002362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe",
    )
    var m4 = bytes_of("test")
    var d4 = sha1(Span(m4))
    _check_rfc6979_p256[Sha1](
        "SHA-1 test",
        Span(d4),
        "0cbcc86fd6abd1d99e703e1ec50069ee5c0b4ba4b9ac60e409e8ec5910d81a8901b9d7b73dfaa60d5651ec4591a0136f87653e0fd780c3b1bc872ffdeae479b1",
    )
    var m5 = bytes_of("test")
    var d5 = sha256(Span(m5))
    _check_rfc6979_p256[Sha256](
        "SHA-256 test",
        Span(d5),
        "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    )
    var m6 = bytes_of("test")
    var d6 = sha384(Span(m6))
    _check_rfc6979_p256[Sha384](
        "SHA-384 test",
        Span(d6),
        "83910e8b48bb0c74244ebdf7f07a1c5413d61472bd941ef3920e623fbccebeb68ddbec54cf8cd5874883841d712142a56a8d0f218f5003cb0296b6b509619f2c",
    )
    var m7 = bytes_of("test")
    var d7 = sha512(Span(m7))
    _check_rfc6979_p256[Sha512](
        "SHA-512 test",
        Span(d7),
        "461d93f31b6540894788fd206c07cfa0cc35f46fa3c91816fff1040ad1581a0439af9f15de0db8d97e72719c74820d304ce5226e32dedae67519e840d1194e55",
    )


def test_rfc6979_nonces_p384() raises:
    # RFC 6979 A.2.6: the `k` values. The second candidate of each
    # generator, which the RFC does not list, comes from an independent
    # implementation of section 3.2.
    # SHA-1, "sample".
    _check_nonce[Sha1](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "000000000000000000000000000000000000000000000000000000008151325dcdbae9e0ff95f9f9658432dbedfdb209",
        "4471ef7518bb2c7c20f62eae1c387ad0c5e8e470995db4acf694466e6ab096630f29e5938d25106c3c340045a2db01a7",
        "bdc20464205738bd1129829d876e1a59233b021c2434f5bb6f1bf530d6362de8b36fdd4df7abbaef256143b84636ecef",
    )
    # SHA-256, "sample".
    _check_nonce[Sha256](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "00000000000000000000000000000000af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
        "180ae9f9aec5438a44bc159a1fcb277c7be54fa20e7cf404b490650a8acc414e375572342863c899f9f2edf9747a9b60",
        "241bd74f1c179a78a711d90e71fb198b5f9332adb1a0f11dcbb08fa2030279ef72cced0eaad4c723d20f75de4d69430a",
    )
    # SHA-384, "sample".
    _check_nonce[Sha384](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe",
        "94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9",
        "9d63ce4c96d070a67f7bee49e870b64838c0ac65bb7440cf46017dca69d35d236219aae5e00a9f01f13e7774be1339fc",
    )
    # SHA-512, "sample".
    _check_nonce[Sha512](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f49a739468ab8049bf18eef820cdb1ad6c",
        "92fc3c7183a883e24216d1141f1a8976c5b0dd797dfa597e3d7b32198bd35331a4e966532593a52980d0e3aaa5e10ec3",
        "d9b606bf6d00c9d2525c2dce4e514453140c090d14f79aba1e593ba24141dd738170de8786307664144ea0f49216a1ef",
    )
    # SHA-1, "test".
    _check_nonce[Sha1](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "00000000000000000000000000000000000000000000000000000000a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "66cc2c8f4d303fc962e5ff6a27bd79f84ec812ddae58cf5243b64a4ad8094d47ec3727f3a3c186c15054492e30698497",
        "96325e161ed99e52703ec604266d6ece8bacef48be6465ac43024e27c05015e4353b93b12a95893226c73491c3ee8090",
    )
    # SHA-256, "test".
    _check_nonce[Sha256](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "000000000000000000000000000000009f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "0cfac37587532347dc3389fdc98286bba8c73807285b184c83e62e26c401c0faa48dd070ba79921a3457abff2d630ad7",
        "793e80637606aeaf668767adbf04f742afb42fd2c97f0d7287d0b77c01e779f971737cf821e4e840d51458a776c72fbf",
    )
    # SHA-384, "test".
    _check_nonce[Sha384](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
        "015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea",
        "9cc959b70dd7367bc45ead8352b899ea744e5e94f6524f0cd8c21a548ebc562fc7d5329e4d5f906a0cff9c2157105309",
    )
    # SHA-512, "test".
    _check_nonce[Sha512](
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
        "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b14",
        "3780c4f67cb15518b6acae34c9f83568d2e12e47deab6c50a4e4ee5319d1e8ce0e2cc8a136036dc4b9c00e6888f66b6c",
        "461f5961d27ad17cd4ad2ed2e4480d682c70aee8a0ad73af10c439745ea71b4ee0bbda7b43312b1339f1c90300c506e5",
    )


def _check_rfc6979_p384[
    H: Hash
](message: StringSpan, digest: Span[UInt8, _], signature: StringSpan) raises:
    ref curve = p384_curve()
    var key = hex_decode(
        "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5"
    )
    var public_key = hex_decode(
        "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720"
    )
    var sig = ecdsa_sign[H=H](curve, Span(key), digest)
    assert_equal(hex_encode(Span(sig)), signature, msg=String(message))
    assert_true(ecdsa_verify(curve, Span(public_key), digest, Span(sig)))


def test_rfc6979_signatures_p384() raises:
    # RFC 6979 A.2.6, every hash this library has. Digests shorter and
    # longer than the group order exercise bits2int.
    var m0 = bytes_of("sample")
    var d0 = sha1(Span(m0))
    _check_rfc6979_p384[Sha1](
        "SHA-1 sample",
        Span(d0),
        "ec748d839243d6fbef4fc5c4859a7dffd7f3abddf72014540c16d73309834fa37b9ba002899f6fda3a4a9386790d4eb2a3bcfa947beef4732bf247ac17f71676cb31a847b9ff0cbc9c9ed4c1a5b3facf26f49ca031d4857570ccb5ca4424a443",
    )
    var m1 = bytes_of("sample")
    var d1 = sha256(Span(m1))
    _check_rfc6979_p384[Sha256](
        "SHA-256 sample",
        Span(d1),
        "21b13d1e013c7fa1392d03c5f99af8b30c570c6f98d4ea8e354b63a21d3daa33bde1e888e63355d92fa2b3c36d8fb2cdf3aa443fb107745bf4bd77cb3891674632068a10ca67e3d45db2266fa7d1feebefdc63eccd1ac42ec0cb8668a4fa0ab0",
    )
    var m2 = bytes_of("sample")
    var d2 = sha384(Span(m2))
    _check_rfc6979_p384[Sha384](
        "SHA-384 sample",
        Span(d2),
        "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe4699ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
    )
    var m3 = bytes_of("sample")
    var d3 = sha512(Span(m3))
    _check_rfc6979_p384[Sha512](
        "SHA-512 sample",
        Span(d3),
        "ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5",
    )
    var m4 = bytes_of("test")
    var d4 = sha1(Span(m4))
    _check_rfc6979_p384[Sha1](
        "SHA-1 test",
        Span(d4),
        "4bc35d3a50ef4e30576f58cd96ce6bf638025ee624004a1f7789a8b8e43d0678acd9d29876daf46638645f7f404b11c7d5a6326c494ed3ff614703878961c0fde7b2c278f9a65fd8c4b7186201a2991695ba1c84541327e966fa7b50f7382282",
    )
    var m5 = bytes_of("test")
    var d5 = sha256(Span(m5))
    _check_rfc6979_p384[Sha256](
        "SHA-256 test",
        Span(d5),
        "6d6defac9ab64dabafe36c6bf510352a4cc27001263638e5b16d9bb51d451559f918eedaf2293be5b475cc8f0188636b2d46f3becbcc523d5f1a1256bf0c9b024d879ba9e838144c8ba6baeb4b53b47d51ab373f9845c0514eefb14024787265",
    )
    var m6 = bytes_of("test")
    var d6 = sha384(Span(m6))
    _check_rfc6979_p384[Sha384](
        "SHA-384 test",
        Span(d6),
        "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023dbddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5",
    )
    var m7 = bytes_of("test")
    var d7 = sha512(Span(m7))
    _check_rfc6979_p384[Sha512](
        "SHA-512 test",
        Span(d7),
        "a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
