"""SHA-384 and SHA-512 as specified in FIPS 180-4."""

from std.builtin.globals import global_constant

from .hash import Hash


def _round_constants() -> Array[UInt64, 80]:
    var k: Array[UInt64, 80] = [
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    ]
    return k^


comptime _K = _round_constants()


@inline(.always)
def _rotr(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))


struct _Sha512Core(Copyable):
    """The compression state shared by SHA-384 and SHA-512."""

    var state: Array[UInt64, 8]
    var block: Array[UInt8, 128]
    var block_len: Int
    var total_len: UInt64

    def __init__(out self, state: Array[UInt64, 8]):
        self.state = state.copy()
        self.block = Array[UInt8, 128](fill=0)
        self.block_len = 0
        self.total_len = 0

    def compress(mut self):
        ref k = global_constant[_K]()
        var w = Array[UInt64, 80](fill=0)
        for i in range(16):
            var v = UInt64(0)
            for j in range(8):
                v = (v << 8) | UInt64(self.block[8 * i + j])
            w[i] = v
        for i in range(16, 80):
            var s0 = (
                _rotr(w[i - 15], 1) ^ _rotr(w[i - 15], 8) ^ (w[i - 15] >> 7)
            )
            var s1 = _rotr(w[i - 2], 19) ^ _rotr(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        var a = self.state[0]
        var b = self.state[1]
        var c = self.state[2]
        var d = self.state[3]
        var e = self.state[4]
        var f = self.state[5]
        var g = self.state[6]
        var h = self.state[7]
        for i in range(80):
            var big_s1 = _rotr(e, 14) ^ _rotr(e, 18) ^ _rotr(e, 41)
            var ch = (e & f) ^ (~e & g)
            var t1 = h + big_s1 + ch + k[i] + w[i]
            var big_s0 = _rotr(a, 28) ^ _rotr(a, 34) ^ _rotr(a, 39)
            var maj = (a & b) ^ (a & c) ^ (b & c)
            var t2 = big_s0 + maj
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        self.state[0] += a
        self.state[1] += b
        self.state[2] += c
        self.state[3] += d
        self.state[4] += e
        self.state[5] += f
        self.state[6] += g
        self.state[7] += h

    def update(mut self, data: Span[UInt8, _]):
        self.total_len += UInt64(len(data))
        for b in data:
            self.block[self.block_len] = b
            self.block_len += 1
            if self.block_len == 128:
                self.compress()
                self.block_len = 0

    def finish(mut self):
        # Messages longer than 2^61 bytes are out of scope, so the high 64
        # bits of the 128-bit length field stay zero.
        var bit_len = self.total_len * 8
        self.block[self.block_len] = 0x80
        self.block_len += 1
        if self.block_len > 112:
            while self.block_len < 128:
                self.block[self.block_len] = 0
                self.block_len += 1
            self.compress()
            self.block_len = 0
        while self.block_len < 120:
            self.block[self.block_len] = 0
            self.block_len += 1
        for i in range(8):
            self.block[120 + i] = UInt8((bit_len >> UInt64(56 - 8 * i)) & 0xFF)
        self.compress()

    def word_byte(self, index: Int) -> UInt8:
        var word = self.state[index // 8]
        return UInt8((word >> UInt64(56 - 8 * (index % 8))) & 0xFF)


struct Sha512(Hash):
    """A streaming SHA-512 hasher."""

    comptime BLOCK_SIZE = 128
    """The internal block size in bytes."""
    comptime DIGEST_SIZE = 64
    """The digest size in bytes."""

    var _core: _Sha512Core

    def __init__(out self):
        """Creates a hasher with the SHA-512 initial state."""
        self._core = _Sha512Core(
            [
                0x6A09E667F3BCC908,
                0xBB67AE8584CAA73B,
                0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1,
                0x510E527FADE682D1,
                0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B,
                0x5BE0CD19137E2179,
            ]
        )

    def update(mut self, data: Span[UInt8, _]):
        """Absorbs more input."""
        self._core.update(data)

    def finish(mut self) -> Array[UInt8, 64]:
        """Pads the input and produces the digest.

        The hasher must not be used again afterwards.
        """
        self._core.finish()
        var out = Array[UInt8, 64](fill=0)
        for i in range(64):
            out[i] = self._core.word_byte(i)
        return out^


struct Sha384(Hash):
    """A streaming SHA-384 hasher."""

    comptime BLOCK_SIZE = 128
    """The internal block size in bytes."""
    comptime DIGEST_SIZE = 48
    """The digest size in bytes."""

    var _core: _Sha512Core

    def __init__(out self):
        """Creates a hasher with the SHA-384 initial state."""
        self._core = _Sha512Core(
            [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7,
                0x47B5481DBEFA4FA4,
            ]
        )

    def update(mut self, data: Span[UInt8, _]):
        """Absorbs more input."""
        self._core.update(data)

    def finish(mut self) -> Array[UInt8, 48]:
        """Pads the input and produces the digest.

        The hasher must not be used again afterwards.
        """
        self._core.finish()
        var out = Array[UInt8, 48](fill=0)
        for i in range(48):
            out[i] = self._core.word_byte(i)
        return out^


def sha512(data: Span[UInt8, _]) -> Array[UInt8, 64]:
    """Computes the SHA-512 digest of `data`."""
    var h = Sha512()
    h.update(data)
    return h.finish()


def sha384(data: Span[UInt8, _]) -> Array[UInt8, 48]:
    """Computes the SHA-384 digest of `data`."""
    var h = Sha384()
    h.update(data)
    return h.finish()
