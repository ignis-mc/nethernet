"""SHA-256 as specified in FIPS 180-4."""

from std.builtin.globals import global_constant

from .hash import Hash


def _round_constants() -> Array[UInt32, 64]:
    var k: Array[UInt32, 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]
    return k^


comptime _K = _round_constants()


@inline(.always)
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))


struct Sha256(Hash):
    """A streaming SHA-256 hasher."""

    comptime BLOCK_SIZE = 64
    comptime DIGEST_SIZE = 32

    var _state: Array[UInt32, 8]
    var _block: Array[UInt8, 64]
    var _block_len: Int
    var _total_len: UInt64

    def __init__(out self):
        """Creates a hasher with the SHA-256 initial state."""
        self._state = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ]
        self._block = Array[UInt8, 64](fill=0)
        self._block_len = 0
        self._total_len = 0

    def _compress(mut self):
        ref k = global_constant[_K]()
        var w = Array[UInt32, 64](fill=0)
        for i in range(16):
            w[i] = (
                (UInt32(self._block[4 * i]) << 24)
                | (UInt32(self._block[4 * i + 1]) << 16)
                | (UInt32(self._block[4 * i + 2]) << 8)
                | UInt32(self._block[4 * i + 3])
            )
        for i in range(16, 64):
            var s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            var s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] + s0 + w[i - 7] + s1
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        var e = self._state[4]
        var f = self._state[5]
        var g = self._state[6]
        var h = self._state[7]
        for i in range(64):
            var big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            var ch = (e & f) ^ (~e & g)
            var t1 = h + big_s1 + ch + k[i] + w[i]
            var big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
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
        self._state[0] += a
        self._state[1] += b
        self._state[2] += c
        self._state[3] += d
        self._state[4] += e
        self._state[5] += f
        self._state[6] += g
        self._state[7] += h

    def update(mut self, data: Span[UInt8, _]):
        """Absorbs more input.

        Args:
            data: The bytes to hash.
        """
        self._total_len += UInt64(len(data))
        for b in data:
            self._block[self._block_len] = b
            self._block_len += 1
            if self._block_len == 64:
                self._compress()
                self._block_len = 0

    def finish(mut self) -> Array[UInt8, 32]:
        """Pads the input and produces the digest.

        The hasher must not be used again afterwards.

        Returns:
            The 32-byte digest.
        """
        var bit_len = self._total_len * 8
        self._block[self._block_len] = 0x80
        self._block_len += 1
        if self._block_len > 56:
            while self._block_len < 64:
                self._block[self._block_len] = 0
                self._block_len += 1
            self._compress()
            self._block_len = 0
        while self._block_len < 56:
            self._block[self._block_len] = 0
            self._block_len += 1
        for i in range(8):
            self._block[56 + i] = UInt8((bit_len >> UInt64(56 - 8 * i)) & 0xFF)
        self._compress()
        var out = Array[UInt8, 32](fill=0)
        for i in range(8):
            out[4 * i] = UInt8(self._state[i] >> 24)
            out[4 * i + 1] = UInt8((self._state[i] >> 16) & 0xFF)
            out[4 * i + 2] = UInt8((self._state[i] >> 8) & 0xFF)
            out[4 * i + 3] = UInt8(self._state[i] & 0xFF)
        return out^


def sha256(data: Span[UInt8, _]) -> Array[UInt8, 32]:
    """Computes the SHA-256 digest of `data`.

    Args:
        data: The bytes to hash.

    Returns:
        The 32-byte digest.
    """
    var h = Sha256()
    h.update(data)
    return h.finish()
