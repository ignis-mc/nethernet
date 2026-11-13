"""SHA-1 as specified in FIPS 180-4.

SHA-1 is broken for collision resistance. It is here only because STUN
MESSAGE-INTEGRITY (RFC 8489) is HMAC-SHA1.
"""

from .hash import Hash


@inline(.always)
def _rotl(x: UInt32, n: UInt32) -> UInt32:
    return (x << n) | (x >> (32 - n))


struct Sha1(Hash):
    """A streaming SHA-1 hasher."""

    comptime BLOCK_SIZE = 64
    """The internal block size in bytes."""
    comptime DIGEST_SIZE = 20
    """The digest size in bytes."""

    var _state: Array[UInt32, 5]
    var _block: Array[UInt8, 64]
    var _block_len: Int
    var _total_len: UInt64

    def __init__(out self):
        """Creates a hasher with the SHA-1 initial state."""
        self._state = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
        self._block = Array[UInt8, 64](fill=0)
        self._block_len = 0
        self._total_len = 0

    def _compress(mut self):
        var w = Array[UInt32, 80](fill=0)
        for i in range(16):
            w[i] = (
                (UInt32(self._block[4 * i]) << 24)
                | (UInt32(self._block[4 * i + 1]) << 16)
                | (UInt32(self._block[4 * i + 2]) << 8)
                | UInt32(self._block[4 * i + 3])
            )
        for i in range(16, 80):
            w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        var e = self._state[4]
        for i in range(80):
            var f: UInt32
            var k: UInt32
            if i < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            var t = _rotl(a, 5) + f + e + k + w[i]
            e = d
            d = c
            c = _rotl(b, 30)
            b = a
            a = t
        self._state[0] += a
        self._state[1] += b
        self._state[2] += c
        self._state[3] += d
        self._state[4] += e

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

    def finish(mut self) -> Array[UInt8, 20]:
        """Pads the input and produces the digest.

        The hasher must not be used again afterwards.

        Returns:
            The 20-byte digest.
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
        var out = Array[UInt8, 20](fill=0)
        for i in range(5):
            out[4 * i] = UInt8(self._state[i] >> 24)
            out[4 * i + 1] = UInt8((self._state[i] >> 16) & 0xFF)
            out[4 * i + 2] = UInt8((self._state[i] >> 8) & 0xFF)
            out[4 * i + 3] = UInt8(self._state[i] & 0xFF)
        return out^


def sha1(data: Span[UInt8, _]) -> Array[UInt8, 20]:
    """Computes the SHA-1 digest of `data`.

    Args:
        data: The bytes to hash.

    Returns:
        The 20-byte digest.
    """
    var h = Sha1()
    h.update(data)
    return h.finish()
