"""AES block cipher as specified in FIPS 197.

The portable implementation is bitsliced and constant-time. It has no lookup
tables at all, so nothing is indexed by secret data, and no secret-dependent
branches; that includes the key schedule. It follows the `aes_ct64` design of
BearSSL (Thomas Pornin, MIT licence): the S-box is the Boyar-Peralta boolean
circuit and a 64-bit word carries one bit of every byte of four blocks. The
counter-mode helper used by GCM runs the same circuit on SIMD lanes to
encrypt eight or sixteen blocks per pass.

When the compilation target is x86-64 with AES-NI (`AES_HARDWARE`), `Aes(key)`
uses the AES instructions for block operations instead, which are
constant-time by construction. `Aes.portable(key)` always selects the
bitsliced code, which is compiled on every target.
"""

from std.bit import byte_swap
from std.sys.info import CompilationTarget, Endian
from std.sys.intrinsics import llvm_intrinsic

comptime AES_BLOCK_LEN = 16

# True when the AES-NI path is compiled in. `_has_feature` is the stdlib's
# own (private) target-feature query; 1.2 has no public predicate for AES-NI.
comptime AES_HARDWARE = (
    CompilationTarget.is_x86() and CompilationTarget._has_feature["aes"]()
)

# Widest bitsliced counter-mode pass, in 64-bit lanes of four blocks each.
comptime _CTR_LANES = 4 if CompilationTarget.has_avx2() else 2

comptime _V = SIMD[DType.uint64, 2]


@inline(.always)
def _sbox[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    # Boyar-Peralta circuit; x0 is the high bit, x7 the low bit.
    var x0 = q[7]
    var x1 = q[6]
    var x2 = q[5]
    var x3 = q[4]
    var x4 = q[3]
    var x5 = q[2]
    var x6 = q[1]
    var x7 = q[0]

    # Top linear transformation.
    var y14 = x3 ^ x5
    var y13 = x0 ^ x6
    var y9 = x0 ^ x3
    var y8 = x0 ^ x5
    var t0 = x1 ^ x2
    var y1 = t0 ^ x7
    var y4 = y1 ^ x3
    var y12 = y13 ^ y14
    var y2 = y1 ^ x0
    var y5 = y1 ^ x6
    var y3 = y5 ^ y8
    var t1 = x4 ^ y12
    var y15 = t1 ^ x5
    var y20 = t1 ^ x1
    var y6 = y15 ^ x7
    var y10 = y15 ^ t0
    var y11 = y20 ^ y9
    var y7 = x7 ^ y11
    var y17 = y10 ^ y11
    var y19 = y10 ^ y8
    var y16 = t0 ^ y11
    var y21 = y13 ^ y16
    var y18 = x0 ^ y16

    # Non-linear section.
    var t2 = y12 & y15
    var t3 = y3 & y6
    var t4 = t3 ^ t2
    var t5 = y4 & x7
    var t6 = t5 ^ t2
    var t7 = y13 & y16
    var t8 = y5 & y1
    var t9 = t8 ^ t7
    var t10 = y2 & y7
    var t11 = t10 ^ t7
    var t12 = y9 & y11
    var t13 = y14 & y17
    var t14 = t13 ^ t12
    var t15 = y8 & y10
    var t16 = t15 ^ t12
    var t17 = t4 ^ t14
    var t18 = t6 ^ t16
    var t19 = t9 ^ t14
    var t20 = t11 ^ t16
    var t21 = t17 ^ y20
    var t22 = t18 ^ y19
    var t23 = t19 ^ y21
    var t24 = t20 ^ y18

    var t25 = t21 ^ t22
    var t26 = t21 & t23
    var t27 = t24 ^ t26
    var t28 = t25 & t27
    var t29 = t28 ^ t22
    var t30 = t23 ^ t24
    var t31 = t22 ^ t26
    var t32 = t31 & t30
    var t33 = t32 ^ t24
    var t34 = t23 ^ t33
    var t35 = t27 ^ t33
    var t36 = t24 & t35
    var t37 = t36 ^ t34
    var t38 = t27 ^ t36
    var t39 = t29 & t38
    var t40 = t25 ^ t39

    var t41 = t40 ^ t37
    var t42 = t29 ^ t33
    var t43 = t29 ^ t40
    var t44 = t33 ^ t37
    var t45 = t42 ^ t41
    var z0 = t44 & y15
    var z1 = t37 & y6
    var z2 = t33 & x7
    var z3 = t43 & y16
    var z4 = t40 & y1
    var z5 = t29 & y7
    var z6 = t42 & y11
    var z7 = t45 & y17
    var z8 = t41 & y10
    var z9 = t44 & y12
    var z10 = t37 & y3
    var z11 = t33 & y4
    var z12 = t43 & y13
    var z13 = t40 & y5
    var z14 = t29 & y2
    var z15 = t42 & y9
    var z16 = t45 & y14
    var z17 = t41 & y8

    # Bottom linear transformation.
    var t46 = z15 ^ z16
    var t47 = z10 ^ z11
    var t48 = z5 ^ z13
    var t49 = z9 ^ z10
    var t50 = z2 ^ z12
    var t51 = z2 ^ z5
    var t52 = z7 ^ z8
    var t53 = z0 ^ z3
    var t54 = z6 ^ z7
    var t55 = z16 ^ z17
    var t56 = z12 ^ t48
    var t57 = t50 ^ t53
    var t58 = z4 ^ t46
    var t59 = z3 ^ t54
    var t60 = t46 ^ t57
    var t61 = z14 ^ t57
    var t62 = t52 ^ t58
    var t63 = t49 ^ t58
    var t64 = z4 ^ t59
    var t65 = t61 ^ t62
    var t66 = z1 ^ t63
    var s0 = t59 ^ t63
    var s6 = t56 ^ ~t62
    var s7 = t48 ^ ~t60
    var t67 = t64 ^ t65
    var s3 = t53 ^ t66
    var s4 = t51 ^ t66
    var s5 = t47 ^ t65
    var s1 = t64 ^ ~s3
    var s2 = t55 ^ ~t67

    q[7] = s0
    q[6] = s1
    q[5] = s2
    q[4] = s3
    q[3] = s4
    q[2] = s5
    q[1] = s6
    q[0] = s7


@inline(.always)
def _inv_sbox_affine[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    var q0 = ~q[0]
    var q1 = ~q[1]
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = ~q[5]
    var q6 = ~q[6]
    var q7 = q[7]
    q[7] = q1 ^ q4 ^ q6
    q[6] = q0 ^ q3 ^ q5
    q[5] = q7 ^ q2 ^ q4
    q[4] = q6 ^ q1 ^ q3
    q[3] = q5 ^ q0 ^ q2
    q[2] = q4 ^ q7 ^ q1
    q[1] = q3 ^ q6 ^ q0
    q[0] = q2 ^ q5 ^ q7


@inline(.always)
def _inv_sbox[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    # The inverse S-box is the forward one between two affine layers.
    _inv_sbox_affine(q)
    _sbox(q)
    _inv_sbox_affine(q)


@inline(.always)
def _swap_bits[
    n: Int
](
    mut q: Array[SIMD[DType.uint64, n], 8],
    i: Int,
    j: Int,
    low: UInt64,
    shift: UInt64,
):
    comptime W = SIMD[DType.uint64, n]
    var cl = W(low)
    var ch = ~cl
    var s = W(shift)
    var a = q[i]
    var b = q[j]
    q[i] = (a & cl) | ((b & cl) << s)
    q[j] = ((a & ch) >> s) | (b & ch)


@inline(.always)
def _ortho[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    # Converts between "one word per block half" and "one word per bit
    # position" layouts. The permutation is an involution.
    _swap_bits(q, 0, 1, 0x5555555555555555, 1)
    _swap_bits(q, 2, 3, 0x5555555555555555, 1)
    _swap_bits(q, 4, 5, 0x5555555555555555, 1)
    _swap_bits(q, 6, 7, 0x5555555555555555, 1)

    _swap_bits(q, 0, 2, 0x3333333333333333, 2)
    _swap_bits(q, 1, 3, 0x3333333333333333, 2)
    _swap_bits(q, 4, 6, 0x3333333333333333, 2)
    _swap_bits(q, 5, 7, 0x3333333333333333, 2)

    _swap_bits(q, 0, 4, 0x0F0F0F0F0F0F0F0F, 4)
    _swap_bits(q, 1, 5, 0x0F0F0F0F0F0F0F0F, 4)
    _swap_bits(q, 2, 6, 0x0F0F0F0F0F0F0F0F, 4)
    _swap_bits(q, 3, 7, 0x0F0F0F0F0F0F0F0F, 4)


@inline(.always)
def _spread(w: UInt32) -> UInt64:
    # Moves byte k of `w` to bits 16k..16k+7.
    var x = UInt64(w)
    x = (x | (x << 16)) & 0x0000FFFF0000FFFF
    x = (x | (x << 8)) & 0x00FF00FF00FF00FF
    return x


@inline(.always)
def _unspread(x: UInt64) -> UInt32:
    var y = x & 0x00FF00FF00FF00FF
    y = (y | (y >> 8)) & 0x0000FFFF0000FFFF
    return UInt32((y | (y >> 16)) & 0xFFFFFFFF)


@inline(.always)
def _add_round_key[
    n: Int
](mut q: Array[SIMD[DType.uint64, n], 8], sk: Array[UInt64, 120], round: Int,):
    for i in range(8):
        q[i] ^= SIMD[DType.uint64, n](sk[8 * round + i])


@inline(.always)
def _shift_rows[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    for i in range(8):
        var x = q[i]
        q[i] = (
            (x & 0x000000000000FFFF)
            | ((x & 0x00000000FFF00000) >> 4)
            | ((x & 0x00000000000F0000) << 12)
            | ((x & 0x0000FF0000000000) >> 8)
            | ((x & 0x000000FF00000000) << 8)
            | ((x & 0xF000000000000000) >> 12)
            | ((x & 0x0FFF000000000000) << 4)
        )


@inline(.always)
def _inv_shift_rows[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    for i in range(8):
        var x = q[i]
        q[i] = (
            (x & 0x000000000000FFFF)
            | ((x & 0x000000000FFF0000) << 4)
            | ((x & 0x00000000F0000000) >> 12)
            | ((x & 0x000000FF00000000) << 8)
            | ((x & 0x0000FF0000000000) >> 8)
            | ((x & 0x000F000000000000) << 12)
            | ((x & 0xFFF0000000000000) >> 4)
        )


@inline(.always)
def _rot16[n: Int](x: SIMD[DType.uint64, n]) -> SIMD[DType.uint64, n]:
    return (x >> 16) | (x << 48)


@inline(.always)
def _rot32[n: Int](x: SIMD[DType.uint64, n]) -> SIMD[DType.uint64, n]:
    return (x << 32) | (x >> 32)


@inline(.always)
def _mix_columns[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    var q0 = q[0]
    var q1 = q[1]
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = q[5]
    var q6 = q[6]
    var q7 = q[7]
    var r0 = _rot16(q0)
    var r1 = _rot16(q1)
    var r2 = _rot16(q2)
    var r3 = _rot16(q3)
    var r4 = _rot16(q4)
    var r5 = _rot16(q5)
    var r6 = _rot16(q6)
    var r7 = _rot16(q7)

    q[0] = q7 ^ r7 ^ r0 ^ _rot32(q0 ^ r0)
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ _rot32(q1 ^ r1)
    q[2] = q1 ^ r1 ^ r2 ^ _rot32(q2 ^ r2)
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ _rot32(q3 ^ r3)
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ _rot32(q4 ^ r4)
    q[5] = q4 ^ r4 ^ r5 ^ _rot32(q5 ^ r5)
    q[6] = q5 ^ r5 ^ r6 ^ _rot32(q6 ^ r6)
    q[7] = q6 ^ r6 ^ r7 ^ _rot32(q7 ^ r7)


@inline(.always)
def _inv_mix_columns[n: Int](mut q: Array[SIMD[DType.uint64, n], 8]):
    var q0 = q[0]
    var q1 = q[1]
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = q[5]
    var q6 = q[6]
    var q7 = q[7]
    var r0 = _rot16(q0)
    var r1 = _rot16(q1)
    var r2 = _rot16(q2)
    var r3 = _rot16(q3)
    var r4 = _rot16(q4)
    var r5 = _rot16(q5)
    var r6 = _rot16(q6)
    var r7 = _rot16(q7)

    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ _rot32(q0 ^ q5 ^ q6 ^ r0 ^ r5)
    q[1] = (
        q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ _rot32(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6)
    )
    q[2] = (
        q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ _rot32(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7)
    )
    q[3] = (
        q0
        ^ q1
        ^ q2
        ^ q5
        ^ q6
        ^ r0
        ^ r2
        ^ r3
        ^ r5
        ^ _rot32(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7)
    )
    q[4] = (
        q1
        ^ q2
        ^ q3
        ^ q5
        ^ r1
        ^ r3
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ _rot32(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6)
    )
    q[5] = (
        q2
        ^ q3
        ^ q4
        ^ q6
        ^ r2
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ _rot32(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7)
    )
    q[6] = (
        q3
        ^ q4
        ^ q5
        ^ q7
        ^ r3
        ^ r5
        ^ r6
        ^ r7
        ^ _rot32(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7)
    )
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ _rot32(q4 ^ q5 ^ q7 ^ r4 ^ r7)


def _bitslice_encrypt[
    n: Int
](rounds: Int, sk: Array[UInt64, 120], mut q: Array[SIMD[DType.uint64, n], 8],):
    _add_round_key(q, sk, 0)
    for u in range(1, rounds):
        _sbox(q)
        _shift_rows(q)
        _mix_columns(q)
        _add_round_key(q, sk, u)
    _sbox(q)
    _shift_rows(q)
    _add_round_key(q, sk, rounds)


def _bitslice_decrypt[
    n: Int
](rounds: Int, sk: Array[UInt64, 120], mut q: Array[SIMD[DType.uint64, n], 8],):
    _add_round_key(q, sk, rounds)
    for i in range(1, rounds):
        _inv_shift_rows(q)
        _inv_sbox(q)
        _add_round_key(q, sk, rounds - i)
        _inv_mix_columns(q)
    _inv_shift_rows(q)
    _inv_sbox(q)
    _add_round_key(q, sk, 0)


def _sub_word(x: UInt32) -> UInt32:
    var q = Array[UInt64, 8](fill=0)
    q[0] = UInt64(x)
    _ortho[1](q)
    _sbox[1](q)
    _ortho[1](q)
    return UInt32(q[0] & 0xFFFFFFFF)


@inline(.always)
def _le32(data: Span[UInt8, _], offset: Int) -> UInt32:
    return (
        UInt32(data[offset])
        | (UInt32(data[offset + 1]) << 8)
        | (UInt32(data[offset + 2]) << 16)
        | (UInt32(data[offset + 3]) << 24)
    )


@inline(.always)
def _load_le64(data: Span[UInt8, _], offset: Int) -> UInt64:
    # Unchecked: the caller guarantees `offset + 8 <= len(data)`.
    var v = (
        data.unsafe_ptr()
        .unsafe_offset(offset)
        .unsafe_bitcast[UInt64]()
        .unsafe_load[alignment=1]()
    )
    comptime if Endian.native() == .big:
        v = byte_swap(v)
    return v


@inline(.always)
def _store_le64(dst: Span[mut=True, UInt8, _], offset: Int, value: UInt64):
    # Unchecked: the caller guarantees `offset + 8 <= len(dst)`.
    var v = value
    comptime if Endian.native() == .big:
        v = byte_swap(v)
    dst.unsafe_ptr().unsafe_offset(offset).unsafe_bitcast[
        UInt64
    ]().unsafe_store[alignment=1](0, v)


@inline(.always)
def _xor_words[
    count: Int
](
    src: Span[UInt8, _],
    dst: Span[mut=True, UInt8, _],
    offset: Int,
    length: Int,
    ks: Array[UInt64, count],
):
    # dst[offset:offset + length] = src[...] ^ keystream, where the keystream
    # bytes are the little-endian bytes of `ks`.
    var words = length >> 3
    for k in range(words):
        _store_le64(
            dst, offset + 8 * k, _load_le64(src, offset + 8 * k) ^ ks[k]
        )
    for i in range(8 * words, length):
        dst[offset + i] = src[offset + i] ^ UInt8(
            (ks[words] >> UInt64(8 * (i & 7))) & 0xFF
        )


# The AES-NI intrinsics may only appear in code compiled for a target that has
# the instructions, so each wrapper has a placeholder body for other targets.
# Those bodies are never called: every use sits behind `AES_HARDWARE`.
@inline(.always)
def _aesenc(state: _V, key: _V) -> _V:
    comptime if AES_HARDWARE:
        return llvm_intrinsic[
            "llvm.x86.aesni.aesenc", _V, has_side_effect=False
        ](state, key)
    else:
        return state ^ key


@inline(.always)
def _aesenclast(state: _V, key: _V) -> _V:
    comptime if AES_HARDWARE:
        return llvm_intrinsic[
            "llvm.x86.aesni.aesenclast", _V, has_side_effect=False
        ](state, key)
    else:
        return state ^ key


@inline(.always)
def _aesdec(state: _V, key: _V) -> _V:
    comptime if AES_HARDWARE:
        return llvm_intrinsic[
            "llvm.x86.aesni.aesdec", _V, has_side_effect=False
        ](state, key)
    else:
        return state ^ key


@inline(.always)
def _aesdeclast(state: _V, key: _V) -> _V:
    comptime if AES_HARDWARE:
        return llvm_intrinsic[
            "llvm.x86.aesni.aesdeclast", _V, has_side_effect=False
        ](state, key)
    else:
        return state ^ key


@inline(.always)
def _aesimc(key: _V) -> _V:
    comptime if AES_HARDWARE:
        return llvm_intrinsic[
            "llvm.x86.aesni.aesimc", _V, has_side_effect=False
        ](key)
    else:
        return key


@inline(.always)
def _load_block(block: Array[UInt8, 16]) -> _V:
    return _V(_load_le64(Span(block), 0), _load_le64(Span(block), 8))


@inline(.always)
def _store_block(v: _V) -> Array[UInt8, 16]:
    var out = Array[UInt8, 16](fill=0)
    _store_le64(Span(out), 0, v[0])
    _store_le64(Span(out), 8, v[1])
    return out^


@inline(.always)
def _block_in(mut q: Array[UInt64, 8], block: Array[UInt8, 16]):
    # Places one block in slot 0 of the four-block bitslice input layout.
    var lo = _load_le64(Span(block), 0)
    var hi = _load_le64(Span(block), 8)
    q[0] = _spread(UInt32(lo & 0xFFFFFFFF)) | (
        _spread(UInt32(hi & 0xFFFFFFFF)) << 8
    )
    q[4] = _spread(UInt32(lo >> 32)) | (_spread(UInt32(hi >> 32)) << 8)


@inline(.always)
def _block_out(q: Array[UInt64, 8]) -> Array[UInt8, 16]:
    var out = Array[UInt8, 16](fill=0)
    _store_le64(
        Span(out), 0, UInt64(_unspread(q[0])) | (UInt64(_unspread(q[4])) << 32)
    )
    _store_le64(
        Span(out),
        8,
        UInt64(_unspread(q[0] >> 8)) | (UInt64(_unspread(q[4] >> 8)) << 32),
    )
    return out^


struct Aes(Copyable):
    """An AES-128, AES-192 or AES-256 key schedule.

    The value holds expanded key material; treat it as a secret.
    """

    var _rounds: Int
    # Round keys as 128-bit little-endian values, for the AES-NI path.
    var _rk: Array[SIMD[DType.uint64, 2], 15]
    # The same round keys in bitsliced form, eight words per round.
    var _sk: Array[UInt64, 120]
    var _hw: Bool

    def __init__(out self, key: Span[UInt8, _]) raises:
        """Expands a key.

        Args:
            key: The 16, 24 or 32 byte key.

        Raises:
            Error: If the key has any other length.
        """
        var key_len = len(key)
        if key_len != 16 and key_len != 24 and key_len != 32:
            raise Error("aes: key must be 16, 24 or 32 bytes")
        var nk = key_len // 4
        self._rounds = nk + 6
        self._rk = Array[_V, 15](fill=_V(0))
        self._sk = Array[UInt64, 120](fill=0)
        self._hw = AES_HARDWARE

        # FIPS 197 key expansion on little-endian words. SubWord goes through
        # the bitsliced S-box, so the schedule is constant-time as well.
        var w = Array[UInt32, 60](fill=0)
        for i in range(nk):
            w[i] = _le32(key, 4 * i)
        var tmp = w[nk - 1]
        var rcon = UInt32(1)
        var j = 0
        for i in range(nk, (self._rounds + 1) * 4):
            if j == 0:
                tmp = _sub_word((tmp << 24) | (tmp >> 8)) ^ rcon
                rcon = ((rcon << 1) ^ ((rcon >> 7) * 0x1B)) & 0xFF
            elif nk > 6 and j == 4:
                tmp = _sub_word(tmp)
            tmp ^= w[i - nk]
            w[i] = tmp
            j += 1
            if j == nk:
                j = 0

        for r in range(self._rounds + 1):
            self._rk[r] = _V(
                UInt64(w[4 * r]) | (UInt64(w[4 * r + 1]) << 32),
                UInt64(w[4 * r + 2]) | (UInt64(w[4 * r + 3]) << 32),
            )
            var lo = _spread(w[4 * r]) | (_spread(w[4 * r + 2]) << 8)
            var hi = _spread(w[4 * r + 1]) | (_spread(w[4 * r + 3]) << 8)
            var q = Array[UInt64, 8](fill=0)
            for i in range(4):
                q[i] = lo
                q[i + 4] = hi
            _ortho[1](q)
            for i in range(8):
                self._sk[8 * r + i] = q[i]

    @staticmethod
    def portable(key: Span[UInt8, _]) raises -> Self:
        """Expands a key for use with the bitsliced implementation only.

        The result behaves exactly like `Aes(key)` but never uses the AES-NI
        path, even when `AES_HARDWARE` is true.

        Args:
            key: The 16, 24 or 32 byte key.

        Returns:
            The key schedule.

        Raises:
            Error: If the key has any other length.
        """
        var aes = Self(key)
        aes._hw = False
        return aes^

    def _round_key_word(self, index: Int) -> UInt32:
        # Word `w[index]` of the FIPS 197 key expansion, for tests.
        var half = self._rk[index >> 2][(index >> 1) & 1]
        return byte_swap(
            UInt32((half >> UInt64(32 * (index & 1))) & 0xFFFFFFFF)
        )

    @inline(.always)
    def _hw_encrypt(self, block: _V) -> _V:
        var s = block ^ self._rk[0]
        for r in range(1, self._rounds):
            s = _aesenc(s, self._rk[r])
        return _aesenclast(s, self._rk[self._rounds])

    @inline(.always)
    def _hw_decrypt(self, block: _V) -> _V:
        var s = block ^ self._rk[self._rounds]
        for i in range(1, self._rounds):
            s = _aesdec(s, _aesimc(self._rk[self._rounds - i]))
        return _aesdeclast(s, self._rk[0])

    def encrypt_block(self, block: Array[UInt8, 16]) -> Array[UInt8, 16]:
        """Encrypts one block.

        Args:
            block: The plaintext block.

        Returns:
            The ciphertext block.
        """
        comptime if AES_HARDWARE:
            if self._hw:
                return _store_block(self._hw_encrypt(_load_block(block)))
        var q = Array[UInt64, 8](fill=0)
        _block_in(q, block)
        _ortho[1](q)
        _bitslice_encrypt[1](self._rounds, self._sk, q)
        _ortho[1](q)
        return _block_out(q)

    def decrypt_block(self, block: Array[UInt8, 16]) -> Array[UInt8, 16]:
        """Decrypts one block.

        Args:
            block: The ciphertext block.

        Returns:
            The plaintext block.
        """
        comptime if AES_HARDWARE:
            if self._hw:
                return _store_block(self._hw_decrypt(_load_block(block)))
        var q = Array[UInt64, 8](fill=0)
        _block_in(q, block)
        _ortho[1](q)
        _bitslice_decrypt[1](self._rounds, self._sk, q)
        _ortho[1](q)
        return _block_out(q)

    def _ctr32_xor(
        self,
        nonce: Span[UInt8, _],
        counter: UInt32,
        src: Span[UInt8, _],
        dst: Span[mut=True, UInt8, _],
    ):
        # XORs `src` into `dst` with the keystream E(nonce || be32(counter)),
        # E(nonce || be32(counter + 1)), ... `nonce` is 12 bytes and `dst` is
        # as long as `src`. The counter wraps modulo 2**32 as in GCM.
        comptime if AES_HARDWARE:
            if self._hw:
                self._ctr32_xor_hw(nonce, counter, src, dst)
                return
        self._ctr32_xor_soft(nonce, counter, src, dst)

    def _ctr32_xor_hw(
        self,
        nonce: Span[UInt8, _],
        counter: UInt32,
        src: Span[UInt8, _],
        dst: Span[mut=True, UInt8, _],
    ):
        var lo = UInt64(_le32(nonce, 0)) | (UInt64(_le32(nonce, 4)) << 32)
        var hi = UInt64(_le32(nonce, 8))
        var cc = counter
        var total = len(src)
        var off = 0
        # Four blocks at a time keeps the AES units busy; the rounds of one
        # block form a serial dependency chain.
        while total - off >= 64:
            var k = self._rk[0]
            var b0 = _V(lo, hi | (UInt64(byte_swap(cc)) << 32)) ^ k
            var b1 = _V(lo, hi | (UInt64(byte_swap(cc + 1)) << 32)) ^ k
            var b2 = _V(lo, hi | (UInt64(byte_swap(cc + 2)) << 32)) ^ k
            var b3 = _V(lo, hi | (UInt64(byte_swap(cc + 3)) << 32)) ^ k
            for r in range(1, self._rounds):
                k = self._rk[r]
                b0 = _aesenc(b0, k)
                b1 = _aesenc(b1, k)
                b2 = _aesenc(b2, k)
                b3 = _aesenc(b3, k)
            k = self._rk[self._rounds]
            b0 = _aesenclast(b0, k)
            b1 = _aesenclast(b1, k)
            b2 = _aesenclast(b2, k)
            b3 = _aesenclast(b3, k)
            var ks: Array[UInt64, 8] = [
                b0[0],
                b0[1],
                b1[0],
                b1[1],
                b2[0],
                b2[1],
                b3[0],
                b3[1],
            ]
            _xor_words(src, dst, off, 64, ks)
            cc += 4
            off += 64
        while off < total:
            var b = self._hw_encrypt(_V(lo, hi | (UInt64(byte_swap(cc)) << 32)))
            cc += 1
            var m = min(16, total - off)
            var ks: Array[UInt64, 2] = [b[0], b[1]]
            _xor_words(src, dst, off, m, ks)
            off += m

    def _ctr32_xor_soft(
        self,
        nonce: Span[UInt8, _],
        counter: UInt32,
        src: Span[UInt8, _],
        dst: Span[mut=True, UInt8, _],
    ):
        # Uses the widest pass first and narrower ones for what is left, so a
        # short tail does not pay for a wide pass.
        var total = len(src)
        var off = 0
        comptime if _CTR_LANES >= 4:
            while total - off > 128:
                self._ctr32_pass[4](nonce, counter, src, dst, off)
                off += 256
        while total - off > 64:
            self._ctr32_pass[2](nonce, counter, src, dst, off)
            off += 128
        while off < total:
            self._ctr32_pass[1](nonce, counter, src, dst, off)
            off += 64

    def _ctr32_pass[
        n: Int
    ](
        self,
        nonce: Span[UInt8, _],
        counter: UInt32,
        src: Span[UInt8, _],
        dst: Span[mut=True, UInt8, _],
        offset: Int,
    ):
        # Encrypts up to `4 * n` counter blocks at once and XORs them over
        # the bytes from `offset`, which must be a multiple of 16. `counter`
        # belongs to offset 0.
        comptime W = SIMD[DType.uint64, n]
        # Words 0 and 2 of every counter block come from the nonce alone.
        var q_even = _spread(_le32(nonce, 0)) | (_spread(_le32(nonce, 8)) << 8)
        var q_odd = _spread(_le32(nonce, 4))
        var cc = counter + UInt32((offset >> 4) & 0xFFFFFFFF)
        var q = Array[W, 8](fill=W(0))
        for lane in range(n):
            for i in range(4):
                q[i][lane] = q_even
                q[i + 4][lane] = q_odd | (_spread(byte_swap(cc)) << 8)
                cc += 1
        _ortho(q)
        _bitslice_encrypt(self._rounds, self._sk, q)
        _ortho(q)
        var ks = Array[UInt64, 8 * n](fill=0)
        for lane in range(n):
            for i in range(4):
                var a = q[i][lane]
                var b = q[i + 4][lane]
                ks[8 * lane + 2 * i] = UInt64(_unspread(a)) | (
                    UInt64(_unspread(b)) << 32
                )
                ks[8 * lane + 2 * i + 1] = UInt64(_unspread(a >> 8)) | (
                    UInt64(_unspread(b >> 8)) << 32
                )
        _xor_words(src, dst, offset, min(64 * n, len(src) - offset), ks)
