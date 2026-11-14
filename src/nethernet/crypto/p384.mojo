"""NIST P-384 (secp384r1): key generation, ECDH and ECDSA with SHA-384."""

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
from .sha512 import Sha384

comptime P384_SCALAR_LEN = 48
"""The byte length of a P-384 private scalar and of a shared secret."""
comptime P384_POINT_LEN = 97
"""The byte length of an uncompressed SEC 1 point, `0x04 || X || Y`."""
comptime P384_SIGNATURE_LEN = 96
"""The byte length of a raw signature, `r || s`."""


def _make_curve() -> Curve[6]:
    # FIPS 186-4 D.1.2.4. Little-endian 64-bit limbs; every value except the
    # two moduli is in Montgomery form (times 2^384). The derived
    # constants are checked against `Curve`'s deriving constructor in the
    # tests.
    var p: Array[UInt64, 6] = [
        0x00000000FFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]
    var p_one: Array[UInt64, 6] = [
        0xFFFFFFFF00000001,
        0x00000000FFFFFFFF,
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]
    var p_rr: Array[UInt64, 6] = [
        0xFFFFFFFE00000001,
        0x0000000200000000,
        0xFFFFFFFE00000000,
        0x0000000200000000,
        0x0000000000000001,
        0x0000000000000000,
    ]
    var order: Array[UInt64, 6] = [
        0xECEC196ACCC52973,
        0x581A0DB248B0A77A,
        0xC7634D81F4372DDF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]
    var order_one: Array[UInt64, 6] = [
        0x1313E695333AD68D,
        0xA7E5F24DB74F5885,
        0x389CB27E0BC8D220,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]
    var order_rr: Array[UInt64, 6] = [
        0x2D319B2419B409A9,
        0xFF3D81E5DF1AA419,
        0xBC3E483AFCB82947,
        0xD40D49174AAB1CC5,
        0x3FB05B7A28266895,
        0x0C84EE012B39BF21,
    ]
    var b: Array[UInt64, 6] = [
        0x081188719D412DCC,
        0xF729ADD87A4C32EC,
        0x77F2209B1920022E,
        0xE3374BEE94938AE2,
        0xB62B21F41F022094,
        0xCD08114B604FBFF9,
    ]
    var gx: Array[UInt64, 6] = [
        0x3DD0756649C0B528,
        0x20E378E2A0D6CE38,
        0x879C3AFC541B4D6E,
        0x6454868459A30EFF,
        0x812FF723614EDE2B,
        0x4D3AADC2299E1513,
    ]
    var gy: Array[UInt64, 6] = [
        0x23043DAD4B03A4FE,
        0xA1BFA8BF7BB4A9AC,
        0x8BADE7562E83B050,
        0xC6C3521968F4FFD9,
        0xDD8002263969A840,
        0x2B78ABC25A15C5E9,
    ]
    # Comb entries 1 to 15, each x then y.
    var comb: Array[UInt64, 180] = [
        0x3DD0756649C0B528,
        0x20E378E2A0D6CE38,
        0x879C3AFC541B4D6E,
        0x6454868459A30EFF,
        0x812FF723614EDE2B,
        0x4D3AADC2299E1513,
        0x23043DAD4B03A4FE,
        0xA1BFA8BF7BB4A9AC,
        0x8BADE7562E83B050,
        0xC6C3521968F4FFD9,
        0xDD8002263969A840,
        0x2B78ABC25A15C5E9,
        0x24480C57F26FEEF9,
        0xC31A26943A0E1240,
        0x735002C3273E2BC7,
        0x8C42E9C53EF1ED4C,
        0x028BABF67F4948E8,
        0x6A502F438A978632,
        0xF5F13A46B74536FE,
        0x1D218BABD8A9F0EB,
        0x30F36BCC37232768,
        0xC5317B31576E8C18,
        0xEF1D57A69BBCB766,
        0x917C4930B3E3D4DC,
        0x11426E2EE349DDD0,
        0x9F117EF99B2FC250,
        0xFF36B480EC0174A6,
        0x4F4BDE7618458466,
        0x2F2EDB6D05806049,
        0x8ADC75D119DFCA92,
        0xA619D097B7D5A7CE,
        0x874275E5A34411E9,
        0x5403E0470DA4B4EF,
        0x2EBAAFD977901D8F,
        0x5E63EBCEA747170F,
        0x12A369447F9D8036,
        0x378205DE2F9FBE67,
        0xC4AFCB837F728E44,
        0xDBCEC06C682E00F1,
        0xF2A145C3114D5423,
        0xA01D98747A52463E,
        0xFC0935B17D717B0A,
        0x9653BC4FD4D01F95,
        0x9AA83EA89560AD34,
        0xF77943DCAF8E3F3F,
        0x70774A10E86FE16E,
        0x6B62E6F1BF9FFDCF,
        0x8A72F39E588745C9,
        0x73ADE4DA2341C342,
        0xDD326E54EA704422,
        0x336C7D983741CEF3,
        0x1EAFA00D59E61549,
        0xCD3ED892BD9A3EFD,
        0x03FAF26CC5C6C7E4,
        0x087E2FCF3045F8AC,
        0x14A65532174F1E73,
        0x2CF84F28FE0AF9A7,
        0xDDFD7A842CDC935B,
        0x4C0F117B6929C895,
        0x356572D64C8BCFCC,
        0xFAB086073F3B236F,
        0x19E9D41D81E221DA,
        0xF3F6571E3927B428,
        0x4348A9337550F1F6,
        0x7167B996A85E62F0,
        0x62D437597F5452BF,
        0xD85FEB9EF2955926,
        0x440A561F6DF78353,
        0x389668EC9CA36B59,
        0x052BF1A1A22DA016,
        0xBDFBFF72F6093254,
        0x94E50F28E22209F3,
        0x90B2E5B33062E8AF,
        0xA8572375E8A3D369,
        0x3FE1B00B201DB7B1,
        0xE926DEF0EE651AA2,
        0x6542C9BEB9B10AD7,
        0x098E309BA2FCBE74,
        0x779DEEB3FFF1D63F,
        0x23D0E80A20BFD374,
        0x8452BB3B8768F797,
        0xCF75BB4D1F952856,
        0x8FE6B40029EA3FAA,
        0x12BD3E4081373A53,
        0x070D34E116973CF4,
        0x20AEE08B7E4F34F7,
        0x269AF9B95EB8AD29,
        0xDDE0A036A6A45DDA,
        0xA18B528E63DF41E0,
        0x03CC71B2A260DF2A,
        0x24A6770AA06B1DD7,
        0x5BFA9C119D2675D3,
        0x73C1E2A196844432,
        0x3660558D131A6CF0,
        0xB0289C832EE79454,
        0xA6AEFB01C6D8DDCD,
        0xBA1464B401AB5245,
        0x9B8D0B6DC48D93FF,
        0x939867DC93AD272C,
        0xBEBE085EAE9FDC77,
        0x73AE5103894EA8BD,
        0x740FC89A39AC22E1,
        0x5E28B0A328E23B23,
        0x2352722EE13104D0,
        0xF4667A18B0A2640D,
        0xAC74A72E49BB37C3,
        0x79F734F0E81E183A,
        0xBFFE5B6C3FD9C0EB,
        0x03CF292200623F3B,
        0x095C71115F29EBFF,
        0x42D7224780AA6823,
        0x044C7BA17458C0B0,
        0xCA62F7EF0959EC20,
        0x40AE2AB7F8CA929F,
        0xB8C5377AA927B102,
        0x398A86A0DC031771,
        0x04908F9DC216A406,
        0xB423A73A918D3300,
        0x634B0FF1E0B94739,
        0xE29DE7252D69F697,
        0x744D14008435AF04,
        0x5F255B1DFEC192DA,
        0x1F17DC12336DC542,
        0x5C90C2A7636A68A8,
        0x960C9EB77704CA1E,
        0x9DE8CF1E6FB3D65A,
        0xC60FEE0D511D3D06,
        0x466E2313F9EB52C7,
        0x743C0F5F206B0914,
        0x42F55BAC2191AA4D,
        0xCEFC7C8FFFEBDBC2,
        0xD4FA6081E6E8ED1C,
        0x867DB63998683186,
        0xFB5CF424DDCC4EA9,
        0xCC9A7FFED4F0E7BD,
        0x7C57F71C7A779F7E,
        0x90774079D6B25EF2,
        0x90EAE903B4081680,
        0xDF2AAE5E0EE1FCEB,
        0x3FF1DA24E86C1A1F,
        0x80F587D6CA193EDF,
        0xA5695523DC9B9D6A,
        0x7B84090085920303,
        0x1EFA4DFCBA6DBDEF,
        0xFBD838F9E0540015,
        0x2C323946C39077DC,
        0x8B1FB9E6AD619124,
        0x9612440C0CA62EA8,
        0x9AD9B52C2DBE00FF,
        0xF52ABAA1AE197643,
        0xD0E898942CAC32AD,
        0xDFB79E4262A98F91,
        0x65452ECF276F55CB,
        0xDB1AC0D27AD23E12,
        0xF68C5F6ADE4986F0,
        0x389AC37B82CE327D,
        0xCD96866DB8A9E8C9,
        0xA11963B85BB8091E,
        0xC7F90D53045B3CD2,
        0x755A72B580F36504,
        0x46F8B39921D3751C,
        0x4BFFDC9153C193DE,
        0xCD15C049B89554E7,
        0x353C6754F7A26BE6,
        0x79602370BD41D970,
        0xDE16470B12B176C0,
        0x56BA117540C8809D,
        0xE2DB35C3E435FB1E,
        0xD71E4AAB6328E33F,
        0x5486782BAF8136D1,
        0x07A4995F86D57231,
        0xF1F0A5BD1651A968,
        0xA5DC5B2476803B6D,
        0x5C587CBC42DDA935,
        0x2B6CDB32BAE8B4C0,
        0x66D1598BB1331138,
        0x4A23B2D25D7E9614,
        0x93E402A674A8C05D,
        0x45AC94E6DA7CE82E,
        0xEB9F8281E463D465,
    ]
    return Curve[6](
        field=Modulus[6](
            modulus=p, m0_inv=0x0000000100000001, one=p_one, rr=p_rr
        ),
        scalar=Modulus[6](
            modulus=order, m0_inv=0x6ED46089E88FDC45, one=order_one, rr=order_rr
        ),
        b=b,
        gx=gx,
        gy=gy,
        comb=comb,
    )


comptime _CURVE = _make_curve()


def p384_curve() -> ref[ImmStaticOrigin] Curve[6]:
    """Returns the P-384 domain parameters."""
    return global_constant[_CURVE]()


def p384_private_key_from_bytes(
    seed: Span[UInt8, _]
) raises -> Array[UInt8, 48]:
    """Derives a P-384 private scalar from uniformly random bytes.

    Interprets the seed as a big-endian integer, reduces it modulo `n - 1`
    and adds one, which gives a scalar in `[1, n - 1]` whose distribution is
    within `2^-64` of uniform. Constant-time in the seed value.
    """
    return ec_private_key_from_bytes(p384_curve(), seed)


def p384_public_key(private_key: Span[UInt8, _]) raises -> Array[UInt8, 97]:
    """Computes the P-384 public key of a private scalar in constant time."""
    return ec_public_key(p384_curve(), private_key)


def p384_ecdh(
    private_key: Span[UInt8, _], peer_public_key: Span[UInt8, _]
) raises -> Array[UInt8, 48]:
    """Computes a P-384 Diffie-Hellman shared secret.

    The scalar multiplication is constant-time. The peer key is fully
    validated first: length, `0x04` prefix, coordinates below `p`, and the
    curve equation.
    """
    return ecdh(p384_curve(), private_key, peer_public_key)


def p384_sign(
    private_key: Span[UInt8, _], digest: Span[UInt8, _]
) raises -> Array[UInt8, 96]:
    """Signs a message digest with ECDSA over P-384.

    The nonce is derived deterministically as in RFC 6979 with HMAC-SHA-384,
    so no randomness is needed. Constant-time in the private key and the
    nonce; see `nethernet.crypto.ec.ecdsa_sign()`.
    """
    return ecdsa_sign[H=Sha384](p384_curve(), private_key, digest)


def p384_verify(
    public_key: Span[UInt8, _],
    digest: Span[UInt8, _],
    signature: Span[UInt8, _],
) -> Bool:
    """Verifies an ECDSA signature over P-384.

    Variable-time: every input is public. Never raises.
    """
    return ecdsa_verify(p384_curve(), public_key, digest, signature)
