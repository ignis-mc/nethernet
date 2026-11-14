"""NIST P-256 (secp256r1): key generation, ECDH and ECDSA with SHA-256."""

from std.builtin.globals import global_constant

from .ec import (
    Curve,
    ec_private_key_from_bytes,
    ec_public_key,
    ecdh,
    ecdsa_sign,
    ecdsa_verify,
)
from .mont import Modulus
from .sha256 import Sha256

comptime P256_SCALAR_LEN = 32
"""The byte length of a P-256 private scalar and of a shared secret."""
comptime P256_POINT_LEN = 65
"""The byte length of an uncompressed SEC 1 point, `0x04 || X || Y`."""
comptime P256_SIGNATURE_LEN = 64
"""The byte length of a raw signature, `r || s`."""


def _make_curve() -> Curve[4]:
    # FIPS 186-4 D.1.2.3. Little-endian 64-bit limbs; every value except the
    # two moduli is in Montgomery form (times 2^256). The derived
    # constants are checked against `Curve`'s deriving constructor in the
    # tests.
    var p: Array[UInt64, 4] = [
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]
    var p_one: Array[UInt64, 4] = [
        0x0000000000000001,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF,
        0x00000000FFFFFFFE,
    ]
    var p_rr: Array[UInt64, 4] = [
        0x0000000000000003,
        0xFFFFFFFBFFFFFFFF,
        0xFFFFFFFFFFFFFFFE,
        0x00000004FFFFFFFD,
    ]
    var order: Array[UInt64, 4] = [
        0xF3B9CAC2FC632551,
        0xBCE6FAADA7179E84,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
    ]
    var order_one: Array[UInt64, 4] = [
        0x0C46353D039CDAAF,
        0x4319055258E8617B,
        0x0000000000000000,
        0x00000000FFFFFFFF,
    ]
    var order_rr: Array[UInt64, 4] = [
        0x83244C95BE79EEA2,
        0x4699799C49BD6FA6,
        0x2845B2392B6BEC59,
        0x66E12D94F3D95620,
    ]
    var b: Array[UInt64, 4] = [
        0xD89CDF6229C4BDDF,
        0xACF005CD78843090,
        0xE5A220ABF7212ED6,
        0xDC30061D04874834,
    ]
    var gx: Array[UInt64, 4] = [
        0x79E730D418A9143C,
        0x75BA95FC5FEDB601,
        0x79FB732B77622510,
        0x18905F76A53755C6,
    ]
    var gy: Array[UInt64, 4] = [
        0xDDF25357CE95560A,
        0x8B4AB8E4BA19E45C,
        0xD2E88688DD21F325,
        0x8571FF1825885D85,
    ]
    # Comb entries 1 to 15, each x then y.
    var comb: Array[UInt64, 120] = [
        0x79E730D418A9143C,
        0x75BA95FC5FEDB601,
        0x79FB732B77622510,
        0x18905F76A53755C6,
        0xDDF25357CE95560A,
        0x8B4AB8E4BA19E45C,
        0xD2E88688DD21F325,
        0x8571FF1825885D85,
        0x4F922FC516A0D2BB,
        0x0D5CC16C1A623499,
        0x9241CF3A57C62C8B,
        0x2F5E6961FD1B667F,
        0x5C15C70BF5A01797,
        0x3D20B44D60956192,
        0x04911B37071FDB52,
        0xF648F9168D6F0F7B,
        0x9E566847E137BBBC,
        0xE434469E8A6A0BEC,
        0xB1C4276179D73463,
        0x5ABE0285133D0015,
        0x92AA837CC04C7DAB,
        0x573D9F4C43260C07,
        0x0C93156278E6CC37,
        0x94BB725B6B6F7383,
        0x62A8C244BFE20925,
        0x91C19AC38FDCE867,
        0x5A96A5D5DD387063,
        0x61D587D421D324F6,
        0xE87673A2A37173EA,
        0x2384800853778B65,
        0x10F8441E05BAB43E,
        0xFA11FE124621EFBE,
        0x1C891F2B2CB19FFD,
        0x01BA8D5BB1923C23,
        0xB6D03D678AC5CA8E,
        0x586EB04C1F13BEDC,
        0x0C35C6E527E8ED09,
        0x1E81A33C1819EDE2,
        0x278FD6C056C652FA,
        0x19D5AC0870864F11,
        0x62577734D2B533D5,
        0x673B8AF6A1BDDDC0,
        0x577E7C9AA79EC293,
        0xBB6DE651C3B266B1,
        0xE7E9303AB65259B3,
        0xD6A0AFD3D03A7480,
        0xC5AC83D19B3CFC27,
        0x60B4619A5D18B99B,
        0xBD6A38E11AE5AA1C,
        0xB8B7652B49E73658,
        0x0B130014EE5F87ED,
        0x9D0F27B2AEEBFFCD,
        0xCA9246317A730A55,
        0x9C955B2FDDBBC83A,
        0x07C1DFE0AC019A71,
        0x244A566D356EC48D,
        0x56F8410EF4F8B16A,
        0x97241AFEC47B266A,
        0x0A406B8E6D9C87C1,
        0x803F3E02CD42AB1B,
        0x7F0309A804DBEC69,
        0xA83B85F73BBAD05F,
        0xC6097273AD8E197F,
        0xC097440E5067ADC1,
        0x846A56F2C379AB34,
        0xA8EE068B841DF8D1,
        0x20314459176C68EF,
        0xF1AF32D5915F1F30,
        0x99C375315D75BD50,
        0x837CFFBAF72F67BC,
        0x0613A41848D7723F,
        0x23D0F130E2D41C8B,
        0xED93E225D5BE5A2B,
        0x6FE799835934F3C6,
        0x4314092622626FFC,
        0x50BBB4D97990216A,
        0x378191C6E57EC63E,
        0x65422C40181DCDB2,
        0x41A8099B0236E0F6,
        0x2B10011801FE49C3,
        0xFC68B5C59B391593,
        0xC385F5A2598270FC,
        0x7144F3AAD19ADCBB,
        0xDD55899983FBAE0C,
        0x93B88B8E74B82FF4,
        0xD2E03C4071E734C9,
        0x9A7A9EAF43C0322A,
        0xE6E4C551149D6041,
        0x5FE14BFE80EC21FE,
        0xF6CE116AC255BE82,
        0x98BC5A072F4A5D67,
        0xFAD27148DB7E63AF,
        0x90C0B6AC29AB05B3,
        0x37A9A83C4E251AE6,
        0x0A7DC875C2AADE7D,
        0x77387DE39F0E1A84,
        0x1E9ECC49A56C0DD7,
        0xA5CFFCD846086C74,
        0x8F7A1408F505AECE,
        0xB37B85C0BEF0C47E,
        0x3596B6E4CC0E6A8F,
        0xFD6D4BBF6B388F23,
        0xABA453FAC39CEF4E,
        0x9C135AC8F9F628D5,
        0x0A1C729495C8F8BE,
        0x2961C4803BF362BF,
        0x9E418403DF63D4AC,
        0xC109F9CB91ECE900,
        0xC2D095D058945705,
        0xB9083D96DDEB85C0,
        0x84692B8D7A40449B,
        0x9BC3344F2EEE1EE1,
        0x0D5AE35642913074,
        0x55491B2748A542B1,
        0x469CA665B310732A,
        0x29591D525F1A4CC1,
        0xE76F5B6BB84F983F,
        0xBE7EEF419F5F84E1,
        0x1200D49680BAA189,
        0x6376551F18EF332C,
    ]
    return Curve[4](
        field=Modulus[4](
            modulus=p, m0_inv=0x0000000000000001, one=p_one, rr=p_rr
        ),
        scalar=Modulus[4](
            modulus=order, m0_inv=0xCCD1C8AAEE00BC4F, one=order_one, rr=order_rr
        ),
        b=b,
        gx=gx,
        gy=gy,
        comb=comb,
    )


comptime _CURVE = _make_curve()


def p256_curve() -> ref[ImmStaticOrigin] Curve[4]:
    """Returns the P-256 domain parameters."""
    return global_constant[_CURVE]()


def p256_private_key_from_bytes(
    seed: Span[UInt8, _]
) raises -> Array[UInt8, 32]:
    """Derives a P-256 private scalar from uniformly random bytes.

    Interprets the seed as a big-endian integer, reduces it modulo `n - 1`
    and adds one, which gives a scalar in `[1, n - 1]` whose distribution is
    within `2^-64` of uniform. Constant-time in the seed value.
    """
    return ec_private_key_from_bytes(p256_curve(), seed)


def p256_public_key(private_key: Span[UInt8, _]) raises -> Array[UInt8, 65]:
    """Computes the P-256 public key of a private scalar in constant time."""
    return ec_public_key(p256_curve(), private_key)


def p256_ecdh(
    private_key: Span[UInt8, _], peer_public_key: Span[UInt8, _]
) raises -> Array[UInt8, 32]:
    """Computes a P-256 Diffie-Hellman shared secret.

    The scalar multiplication is constant-time. The peer key is fully
    validated first: length, `0x04` prefix, coordinates below `p`, and the
    curve equation.
    """
    return ecdh(p256_curve(), private_key, peer_public_key)


def p256_sign(
    private_key: Span[UInt8, _], digest: Span[UInt8, _]
) raises -> Array[UInt8, 64]:
    """Signs a message digest with ECDSA over P-256.

    The nonce is derived deterministically as in RFC 6979 with HMAC-SHA-256,
    so no randomness is needed. Constant-time in the private key and the
    nonce; see `nethernet.crypto.ec.ecdsa_sign()`.
    """
    return ecdsa_sign[H=Sha256](p256_curve(), private_key, digest)


def p256_verify(
    public_key: Span[UInt8, _],
    digest: Span[UInt8, _],
    signature: Span[UInt8, _],
) -> Bool:
    """Verifies an ECDSA signature over P-256.

    Variable-time: every input is public. Never raises.
    """
    return ecdsa_verify(p256_curve(), public_key, digest, signature)
