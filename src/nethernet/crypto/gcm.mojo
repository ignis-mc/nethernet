"""AES-GCM authenticated encryption as specified in NIST SP 800-38D.

Only 96-bit nonces and 128-bit tags are supported, which is what TLS and DTLS
use. A nonce must never repeat under the same key.

The portable GHASH is constant-time: the carry-less multiplication is built
from 64-bit integer multiplications of operands with spaced-out bits (the
`ghash_ctmul64` technique of BearSSL, Thomas Pornin, MIT licence). It has no
lookup tables and no secret-dependent branches, and relies on the CPU's
integer multiplier running in constant time, as it does on x86-64 and
AArch64. Counter mode runs on `Aes`, which is constant-time as well, and tags
are compared with `constant_time_eq` before any plaintext is produced.

When the compilation target is x86-64 with PCLMULQDQ (`GCM_HARDWARE`),
`AesGcm(key)` multiplies with that instruction instead, and its block cipher
uses AES-NI when `AES_HARDWARE` is true. `AesGcm.portable(key)` always selects
the portable code, which is compiled on every target.
"""

from std.bit import byte_swap
from std.sys.info import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from .aes import Aes, _load_le64
from .ct import constant_time_eq

comptime GCM_NONCE_LEN = 12
comptime GCM_TAG_LEN = 16

# True when the PCLMULQDQ GHASH is compiled in. `_has_feature` is the stdlib's
# own (private) target-feature query; 1.2 has no public predicate for PCLMUL.
comptime GCM_HARDWARE = (
    CompilationTarget.is_x86() and CompilationTarget._has_feature["pclmul"]()
)

# SP 800-38D limits a message to 2**39 - 256 bits so the counter cannot wrap.
comptime _MAX_MESSAGE_LEN = (1 << 36) - 32

comptime _V = SIMD[DType.uint64, 2]


@inline(.always)
def _bmul64(x: UInt64, y: UInt64) -> UInt64:
    # Low 64 bits of the carry-less product. Each operand is split into four
    # words holding every fourth bit, so the carries of the integer products
    # land in the holes and are masked away.
    var x0 = x & 0x1111111111111111
    var x1 = x & 0x2222222222222222
    var x2 = x & 0x4444444444444444
    var x3 = x & 0x8888888888888888
    var y0 = y & 0x1111111111111111
    var y1 = y & 0x2222222222222222
    var y2 = y & 0x4444444444444444
    var y3 = y & 0x8888888888888888
    var z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
    var z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
    var z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
    var z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
    return (
        (z0 & 0x1111111111111111)
        | (z1 & 0x2222222222222222)
        | (z2 & 0x4444444444444444)
        | (z3 & 0x8888888888888888)
    )


@inline(.always)
def _rev64(x: UInt64) -> UInt64:
    var v = x
    v = ((v & 0x5555555555555555) << 1) | ((v >> 1) & 0x5555555555555555)
    v = ((v & 0x3333333333333333) << 2) | ((v >> 2) & 0x3333333333333333)
    v = ((v & 0x0F0F0F0F0F0F0F0F) << 4) | ((v >> 4) & 0x0F0F0F0F0F0F0F0F)
    v = ((v & 0x00FF00FF00FF00FF) << 8) | ((v >> 8) & 0x00FF00FF00FF00FF)
    v = ((v & 0x0000FFFF0000FFFF) << 16) | ((v >> 16) & 0x0000FFFF0000FFFF)
    return (v << 32) | (v >> 32)


@inline(.always)
def _clmul(a: UInt64, b: UInt64) -> _V:
    # Full 64x64 carry-less product as (low, high). The intrinsic may only
    # appear in code compiled for a target that has the instruction.
    comptime if GCM_HARDWARE:
        return llvm_intrinsic["llvm.x86.pclmulqdq", _V, has_side_effect=False](
            _V(a, 0), _V(b, 0), Int8(0)
        )
    else:
        return _V(_bmul64(a, b), _rev64(_bmul64(_rev64(a), _rev64(b))) >> 1)


@inline(.always)
def _be64(data: Span[UInt8, _], offset: Int) -> UInt64:
    # Unchecked: the caller guarantees `offset + 8 <= len(data)`.
    return byte_swap(_load_le64(data, offset))


struct _Ghash(Copyable):
    # GHASH with the hash key split into halves; `_y1` holds the first eight
    # bytes of the running value and `_y0` the last eight, both big-endian.
    var _h0: UInt64
    var _h1: UInt64
    var _h2: UInt64
    var _h0r: UInt64
    var _h1r: UInt64
    var _h2r: UInt64
    var _y0: UInt64
    var _y1: UInt64
    var _hw: Bool

    def __init__(out self, h: Array[UInt8, 16], hw: Bool):
        self._h1 = _be64(Span(h), 0)
        self._h0 = _be64(Span(h), 8)
        self._h2 = self._h0 ^ self._h1
        self._h0r = _rev64(self._h0)
        self._h1r = _rev64(self._h1)
        self._h2r = self._h0r ^ self._h1r
        self._y0 = 0
        self._y1 = 0
        self._hw = hw

    @inline(.always)
    def _reduce(mut self, z0: UInt64, z1: UInt64, z2: UInt64, z3: UInt64):
        # GHASH bits are reflected, so the 127-bit product moves up one bit
        # before folding with x^128 = x^7 + x^2 + x + 1.
        var v3 = (z3 << 1) | (z2 >> 63)
        var v2 = (z2 << 1) | (z1 >> 63)
        var v1 = (z1 << 1) | (z0 >> 63)
        var v0 = z0 << 1
        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)
        self._y0 = v2
        self._y1 = v3

    @inline(.always)
    def _mul_soft(mut self):
        # Karatsuba over the halves; the high half of each product comes from
        # multiplying the bit-reversed operands.
        var y0 = self._y0
        var y1 = self._y1
        var y0r = _rev64(y0)
        var y1r = _rev64(y1)
        var z0 = _bmul64(y0, self._h0)
        var z1 = _bmul64(y1, self._h1)
        var z2 = _bmul64(y0 ^ y1, self._h2)
        var z0h = _bmul64(y0r, self._h0r)
        var z1h = _bmul64(y1r, self._h1r)
        var z2h = _bmul64(y0r ^ y1r, self._h2r)
        z2 ^= z0 ^ z1
        z2h ^= z0h ^ z1h
        z0h = _rev64(z0h) >> 1
        z1h = _rev64(z1h) >> 1
        z2h = _rev64(z2h) >> 1
        self._reduce(z0, z0h ^ z2, z1 ^ z2h, z1h)

    @inline(.always)
    def _mul_hw(mut self):
        var y0 = self._y0
        var y1 = self._y1
        var p0 = _clmul(y0, self._h0)
        var p1 = _clmul(y1, self._h1)
        var p2 = _clmul(y0 ^ y1, self._h2) ^ p0 ^ p1
        self._reduce(p0[0], p0[1] ^ p2[0], p1[0] ^ p2[1], p1[1])

    @inline(.always)
    def _mul(mut self):
        # Multiplies the running value by the hash key.
        comptime if GCM_HARDWARE:
            if self._hw:
                self._mul_hw()
                return
        self._mul_soft()

    def _update_padded(mut self, data: Span[UInt8, _]):
        # Absorbs `data`, zero-padded to a whole number of blocks.
        var total = len(data)
        var off = 0
        while off + 16 <= total:
            self._y1 ^= _be64(data, off)
            self._y0 ^= _be64(data, off + 8)
            self._mul()
            off += 16
        if off < total:
            var last = Array[UInt8, 16](fill=0)
            for i in range(total - off):
                last[i] = data[off + i]
            self._y1 ^= _be64(Span(last), 0)
            self._y0 ^= _be64(Span(last), 8)
            self._mul()

    def _finish(mut self, aad_len: Int, text_len: Int) -> Array[UInt8, 16]:
        # Absorbs the bit lengths and returns the GHASH value.
        self._y1 ^= UInt64(aad_len) << 3
        self._y0 ^= UInt64(text_len) << 3
        self._mul()
        var out = Array[UInt8, 16](fill=0)
        for i in range(8):
            out[i] = UInt8((self._y1 >> UInt64(56 - 8 * i)) & 0xFF)
            out[8 + i] = UInt8((self._y0 >> UInt64(56 - 8 * i)) & 0xFF)
        return out^


struct AesGcm(Copyable):
    """An AES-GCM key for sealing and opening messages.

    The value holds expanded key material; treat it as a secret.
    """

    var _aes: Aes
    var _ghash: _Ghash

    def __init__(out self, key: Span[UInt8, _]) raises:
        """Expands a key.

        Args:
            key: The 16, 24 or 32 byte AES key.

        Raises:
            Error: If the key has any other length.
        """
        self._aes = Aes(key)
        var zero = Array[UInt8, 16](fill=0)
        self._ghash = _Ghash(self._aes.encrypt_block(zero), GCM_HARDWARE)

    @staticmethod
    def portable(key: Span[UInt8, _]) raises -> Self:
        """Expands a key for use with the portable implementation only.

        The result behaves exactly like `AesGcm(key)` but never uses AES-NI or
        PCLMULQDQ, even when the target has them.

        Args:
            key: The 16, 24 or 32 byte AES key.

        Returns:
            The key.

        Raises:
            Error: If the key has any other length.
        """
        var gcm = Self(key)
        gcm._aes = Aes.portable(key)
        var zero = Array[UInt8, 16](fill=0)
        gcm._ghash = _Ghash(gcm._aes.encrypt_block(zero), False)
        return gcm^

    def _tag(
        self,
        nonce: Span[UInt8, _],
        aad: Span[UInt8, _],
        ciphertext: Span[UInt8, _],
    ) -> Array[UInt8, 16]:
        var ghash = self._ghash.copy()
        ghash._update_padded(aad)
        ghash._update_padded(ciphertext)
        var tag = ghash._finish(len(aad), len(ciphertext))
        # J0 = nonce || 0x00000001 for a 96-bit nonce.
        var j0 = Array[UInt8, 16](fill=0)
        for i in range(GCM_NONCE_LEN):
            j0[i] = nonce[i]
        j0[15] = 1
        var mask = self._aes.encrypt_block(j0)
        for i in range(GCM_TAG_LEN):
            tag[i] ^= mask[i]
        return tag^

    def seal(
        self,
        nonce: Span[UInt8, _],
        aad: Span[UInt8, _],
        plaintext: Span[UInt8, _],
        mut out: List[UInt8],
    ) raises:
        """Encrypts and authenticates a message.

        Args:
            nonce: The 12-byte nonce, unique for this key.
            aad: Additional data to authenticate but not encrypt.
            plaintext: The message.
            out: Receives the ciphertext, which is as long as `plaintext`,
                followed by the 16-byte tag. Existing contents are kept.

        Raises:
            Error: If the nonce is not 12 bytes or the message is too long.
        """
        if len(nonce) != GCM_NONCE_LEN:
            raise Error("gcm: nonce must be 12 bytes")
        var n = len(plaintext)
        if n > _MAX_MESSAGE_LEN:
            raise Error("gcm: message too long")
        var base = len(out)
        out.resize(base + n + GCM_TAG_LEN, 0)
        self._aes._ctr32_xor(nonce, 2, plaintext, Span(out)[base : base + n])
        var tag = self._tag(nonce, aad, Span(out)[base : base + n])
        for i in range(GCM_TAG_LEN):
            out[base + n + i] = tag[i]

    def open(
        self,
        nonce: Span[UInt8, _],
        aad: Span[UInt8, _],
        sealed: Span[UInt8, _],
        mut out: List[UInt8],
    ) raises:
        """Verifies and decrypts a sealed message.

        The tag is checked in constant time before any plaintext is produced.
        When this raises, `out` is left unchanged.

        Args:
            nonce: The 12-byte nonce used to seal the message.
            aad: The additional data that was authenticated with it.
            sealed: The ciphertext followed by the 16-byte tag.
            out: Receives the plaintext. Existing contents are kept.

        Raises:
            Error: If the nonce is not 12 bytes or the message is too long, or
                "gcm: authentication failed" if `sealed` is shorter than a
                tag or the tag does not match.
        """
        if len(nonce) != GCM_NONCE_LEN:
            raise Error("gcm: nonce must be 12 bytes")
        if len(sealed) < GCM_TAG_LEN:
            raise Error("gcm: authentication failed")
        var n = len(sealed) - GCM_TAG_LEN
        if n > _MAX_MESSAGE_LEN:
            raise Error("gcm: message too long")
        var expected = self._tag(nonce, aad, sealed[0:n])
        if not constant_time_eq(Span(expected), sealed[n : n + GCM_TAG_LEN]):
            raise Error("gcm: authentication failed")
        var base = len(out)
        out.resize(base + n, 0)
        self._aes._ctr32_xor(nonce, 2, sealed[0:n], Span(out)[base : base + n])
