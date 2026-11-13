"""Fixed-width Montgomery modular arithmetic over 64-bit limbs.

Numbers are `Array[UInt64, n]` values holding `n` little-endian limbs, where
`n` is a compile-time parameter (4 for 256-bit moduli, 6 for 384-bit ones).
A `Modulus[n]` carries an odd modulus `m` and the constants for arithmetic
with the Montgomery radix `R = 2^(64 n)`.

Every function in this module runs in time that depends only on `n` and on
the lengths of byte spans, never on the values of its numeric arguments,
except where a docstring says "variable-time". The code uses no
value-dependent branches or indices; masks and 128-bit carries replace them.

Every selection mask passes through `_value_barrier()`, an empty piece of
inline assembly that hides from the optimiser that the mask is all ones or
zero. Without it LLVM turns a masked table scan back into a compare and
branch. The price is that the arithmetic cannot run in the compile-time
interpreter; build `comptime` constants with the `Modulus` constructor that
takes precomputed values.
"""

from std.sys import inlined_assembly

comptime _LOW = UInt128(0xFFFF_FFFF_FFFF_FFFF)


@inline(.always)
def _value_barrier(x: UInt64) -> UInt64:
    # Returns x through a register the optimiser cannot see into.
    return inlined_assembly[
        "", UInt64, constraints="=r,0", has_side_effect=False
    ](x)


@inline(.always)
def _mask_from_bit(bit: UInt64) -> UInt64:
    # 1 -> all ones, 0 -> zero.
    return _value_barrier(UInt64(0) - bit)


@inline(.always)
def _nonzero_bit(x: UInt64) -> UInt64:
    # 1 if x != 0, else 0, without a comparison.
    return (x | (UInt64(0) - x)) >> 63


@inline(.always)
def _mask_if_zero(x: UInt64) -> UInt64:
    # All ones if x == 0, else zero.
    return _value_barrier(_nonzero_bit(x) - 1)


@inline(.always)
def ct_word_eq(a: UInt64, b: UInt64) -> UInt64:
    """Compares two words for equality in constant time.

    Args:
        a: The first word.
        b: The second word.

    Returns:
        A mask with all bits set if `a == b`, and zero otherwise.
    """
    return _mask_if_zero(a ^ b)


def ct_is_zero[n: Int](a: Array[UInt64, n]) -> UInt64:
    """Tests a number for zero in constant time.

    Parameters:
        n: The limb count.

    Args:
        a: The number to test.

    Returns:
        A mask with all bits set if `a` is zero, and zero otherwise.
    """
    var acc = UInt64(0)
    for i in range(n):
        acc |= a[i]
    return _mask_if_zero(acc)


def ct_eq[n: Int](a: Array[UInt64, n], b: Array[UInt64, n]) -> UInt64:
    """Compares two numbers for equality in constant time.

    Parameters:
        n: The limb count.

    Args:
        a: The first number.
        b: The second number.

    Returns:
        A mask with all bits set if `a == b`, and zero otherwise.
    """
    var acc = UInt64(0)
    for i in range(n):
        acc |= a[i] ^ b[i]
    return _mask_if_zero(acc)


def ct_lt[n: Int](a: Array[UInt64, n], b: Array[UInt64, n]) -> UInt64:
    """Compares two numbers as unsigned integers in constant time.

    Parameters:
        n: The limb count.

    Args:
        a: The first number.
        b: The second number.

    Returns:
        A mask with all bits set if `a < b`, and zero otherwise.
    """
    var borrow = UInt64(0)
    for i in range(n):
        var d = UInt128(a[i]) - UInt128(b[i]) - UInt128(borrow)
        borrow = UInt64(d >> 64) & 1
    return _mask_from_bit(borrow)


@inline(.always)
def ct_select[
    n: Int
](mask: UInt64, a: Array[UInt64, n], b: Array[UInt64, n]) -> Array[UInt64, n]:
    """Chooses between two numbers in constant time.

    Parameters:
        n: The limb count.

    Args:
        mask: All ones to choose `a`, zero to choose `b`. Other values are
            not allowed.
        a: The number returned when `mask` is all ones.
        b: The number returned when `mask` is zero.

    Returns:
        A copy of the chosen number.
    """
    var out = Array[UInt64, n](fill=0)
    var m = _value_barrier(mask)
    for i in range(n):
        out[i] = b[i] ^ (m & (a[i] ^ b[i]))
    return out^


def ct_swap[
    n: Int
](mask: UInt64, mut a: Array[UInt64, n], mut b: Array[UInt64, n]):
    """Exchanges two numbers in constant time when asked to.

    Parameters:
        n: The limb count.

    Args:
        mask: All ones to swap, zero to leave both unchanged. Other values
            are not allowed.
        a: The first number.
        b: The second number.
    """
    var m = _value_barrier(mask)
    for i in range(n):
        var t = m & (a[i] ^ b[i])
        a[i] ^= t
        b[i] ^= t


def limbs_from_be_bytes[n: Int](data: Span[UInt8, _]) -> Array[UInt64, n]:
    """Decodes a big-endian unsigned integer into limbs.

    Spans shorter than `8 * n` bytes are treated as if padded with leading
    zeros. Of longer spans only the last `8 * n` bytes are used.

    Parameters:
        n: The limb count.

    Args:
        data: The big-endian bytes.

    Returns:
        The integer, modulo `2^(64 n)`, as little-endian limbs.
    """
    var out = Array[UInt64, n](fill=0)
    var count = len(data)
    if count > 8 * n:
        count = 8 * n
    for k in range(count):
        # Byte k counted from the least significant end.
        var byte = UInt64(data[len(data) - 1 - k])
        out[k >> 3] |= byte << UInt64(8 * (k & 7))
    return out^


def limbs_to_be_bytes[n: Int](a: Array[UInt64, n]) -> Array[UInt8, 8 * n]:
    """Encodes limbs as a fixed-width big-endian unsigned integer.

    Parameters:
        n: The limb count.

    Args:
        a: The number to encode.

    Returns:
        The `8 * n` big-endian bytes of `a`.
    """
    var out = Array[UInt8, 8 * n](fill=0)
    for k in range(8 * n):
        out[8 * n - 1 - k] = UInt8((a[k >> 3] >> UInt64(8 * (k & 7))) & 0xFF)
    return out^


def limbs_reduce_be_bytes[
    n: Int
](data: Span[UInt8, _], modulus: Array[UInt64, n]) -> Array[UInt64, n]:
    """Reduces a big-endian unsigned integer of any length modulo `modulus`.

    The modulus may be even. The reduction shifts in one bit at a time, so
    the running time depends only on `len(data)` and `n`.

    Parameters:
        n: The limb count.

    Args:
        data: The big-endian bytes of the integer to reduce.
        modulus: The modulus, which must not be zero.

    Returns:
        The integer modulo `modulus`.
    """
    var acc = Array[UInt64, n](fill=0)
    var diff = Array[UInt64, n](fill=0)
    for index in range(len(data)):
        var byte = UInt64(data[index])
        for shift in range(8):
            # acc = 2 * acc + bit, which is below 2 * modulus.
            var carry = (byte >> UInt64(7 - shift)) & 1
            for i in range(n):
                var limb = acc[i]
                acc[i] = (limb << 1) | carry
                carry = limb >> 63
            var borrow = UInt64(0)
            for i in range(n):
                var d = UInt128(acc[i]) - UInt128(modulus[i]) - UInt128(borrow)
                diff[i] = UInt64(d & _LOW)
                borrow = UInt64(d >> 64) & 1
            # Keep the difference unless it underflowed with no carry out.
            var keep = _mask_from_bit(borrow & (carry ^ 1))
            for i in range(n):
                acc[i] = diff[i] ^ (keep & (acc[i] ^ diff[i]))
    return acc^


def _minus_two[n: Int](modulus: Array[UInt64, n]) -> Array[UInt64, n]:
    var out = Array[UInt64, n](fill=0)
    var borrow = UInt64(2)
    for i in range(n):
        var d = UInt128(modulus[i]) - UInt128(borrow)
        out[i] = UInt64(d & _LOW)
        borrow = UInt64(d >> 64) & 1
    return out^


struct Modulus[n: Int](Copyable):
    """An odd modulus with the constants for Montgomery arithmetic.

    Values passed to `add()`, `sub()`, `neg()`, `mul()`, `square()`, `pow()`
    and `inv()` must already be reduced, that is, lie in `[0, m)`. A value
    `a` is in Montgomery form when it is stored as `a * R mod m` with
    `R = 2^(64 n)`; `mul()` then maps two Montgomery-form values to the
    Montgomery form of their product.

    Parameters:
        n: The limb count.
    """

    var m: Array[UInt64, Self.n]
    """The modulus."""
    var m0_inv: UInt64
    """The value `-m^-1 mod 2^64`."""
    var one: Array[UInt64, Self.n]
    """The value `R mod m`: one in Montgomery form."""
    var rr: Array[UInt64, Self.n]
    """The value `R^2 mod m`, used to convert into Montgomery form."""
    var m_minus_2: Array[UInt64, Self.n]
    """The exponent `m - 2`, used by `inv()`."""

    def __init__(out self, modulus: Array[UInt64, Self.n]):
        """Derives the Montgomery constants of a modulus.

        Args:
            modulus: The modulus as little-endian limbs. It must be odd and
                at least 3.

        Constraints:
            Runs at run time only; the compile-time interpreter rejects
            the inline assembly behind the constant-time masks. For
            `comptime` constants use the constructor that takes
            precomputed values.
        """
        self.m = modulus.copy()
        # Newton iteration doubles the number of correct low bits each round.
        var inv = UInt64(1)
        for _ in range(6):
            inv = inv * (UInt64(2) - modulus[0] * inv)
        self.m0_inv = UInt64(0) - inv
        self.one = Array[UInt64, Self.n](fill=0)
        self.rr = Array[UInt64, Self.n](fill=0)
        self.m_minus_2 = _minus_two(modulus)
        # R mod m and R^2 mod m by repeated modular doubling of 1.
        var acc = Array[UInt64, Self.n](fill=0)
        acc[0] = 1
        for _ in range(64 * Self.n):
            acc = self.add(acc, acc)
        self.one = acc.copy()
        for _ in range(64 * Self.n):
            acc = self.add(acc, acc)
        self.rr = acc.copy()

    def __init__(
        out self,
        *,
        modulus: Array[UInt64, Self.n],
        m0_inv: UInt64,
        one: Array[UInt64, Self.n],
        rr: Array[UInt64, Self.n],
    ):
        """Wraps precomputed Montgomery constants without checking them.

        Args:
            modulus: The modulus as little-endian limbs; odd and at least 3.
            m0_inv: The value `-modulus^-1 mod 2^64`.
            one: The value `2^(64 n) mod modulus`.
            rr: The value `2^(128 n) mod modulus`.
        """
        self.m = modulus.copy()
        self.m0_inv = m0_inv
        self.one = one.copy()
        self.rr = rr.copy()
        self.m_minus_2 = _minus_two(modulus)

    @inline(.always)
    def add(
        self, a: Array[UInt64, Self.n], b: Array[UInt64, Self.n]
    ) -> Array[UInt64, Self.n]:
        """Adds two reduced values modulo `m` in constant time.

        Args:
            a: The first addend, in `[0, m)`.
            b: The second addend, in `[0, m)`.

        Returns:
            The sum `a + b mod m`.
        """
        var sum = Array[UInt64, Self.n](fill=0)
        var carry = UInt64(0)
        comptime for i in range(Self.n):
            var s = UInt128(a[i]) + UInt128(b[i]) + UInt128(carry)
            sum[i] = UInt64(s & _LOW)
            carry = UInt64(s >> 64)
        return self._reduce_once(sum, carry)

    @inline(.always)
    def _reduce_once(
        self, t: Array[UInt64, Self.n], top: UInt64
    ) -> Array[UInt64, Self.n]:
        # Maps top * 2^(64 n) + t, known to be below 2 m, into [0, m).
        var out = Array[UInt64, Self.n](fill=0)
        var borrow = UInt64(0)
        comptime for i in range(Self.n):
            var d = UInt128(t[i]) - UInt128(self.m[i]) - UInt128(borrow)
            out[i] = UInt64(d & _LOW)
            borrow = UInt64(d >> 64) & 1
        # The subtraction underflowed for real only if there was no top bit.
        var keep = _mask_from_bit(borrow & (top ^ 1))
        comptime for i in range(Self.n):
            out[i] ^= keep & (out[i] ^ t[i])
        return out^

    @inline(.always)
    def sub(
        self, a: Array[UInt64, Self.n], b: Array[UInt64, Self.n]
    ) -> Array[UInt64, Self.n]:
        """Subtracts two reduced values modulo `m` in constant time.

        Args:
            a: The minuend, in `[0, m)`.
            b: The subtrahend, in `[0, m)`.

        Returns:
            The difference `a - b mod m`.
        """
        var out = Array[UInt64, Self.n](fill=0)
        var borrow = UInt64(0)
        comptime for i in range(Self.n):
            var d = UInt128(a[i]) - UInt128(b[i]) - UInt128(borrow)
            out[i] = UInt64(d & _LOW)
            borrow = UInt64(d >> 64) & 1
        var mask = _mask_from_bit(borrow)
        var carry = UInt64(0)
        comptime for i in range(Self.n):
            var s = UInt128(out[i]) + UInt128(self.m[i] & mask) + UInt128(carry)
            out[i] = UInt64(s & _LOW)
            carry = UInt64(s >> 64)
        return out^

    def neg(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Negates a reduced value modulo `m` in constant time.

        Args:
            a: The value to negate, in `[0, m)`.

        Returns:
            The value `-a mod m`.
        """
        var zero = Array[UInt64, Self.n](fill=0)
        return self.sub(zero, a)

    def reduce_once(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Reduces a value below `2 m` with one constant-time subtraction.

        Args:
            a: The value to reduce, in `[0, 2 m)`.

        Returns:
            The value `a mod m`.
        """
        return self._reduce_once(a, 0)

    @inline(.always)
    def mul(
        self, a: Array[UInt64, Self.n], b: Array[UInt64, Self.n]
    ) -> Array[UInt64, Self.n]:
        """Computes the Montgomery product in constant time.

        Args:
            a: The first factor, in `[0, m)`.
            b: The second factor, in `[0, m)`.

        Returns:
            The value `a * b * R^-1 mod m`. If both factors are in
            Montgomery form, this is the Montgomery form of their product.
        """
        # Coarsely integrated operand scanning; t has one extra limb and
        # `top` holds the overflow above it.
        var t = Array[UInt64, Self.n](fill=0)
        var top = UInt64(0)
        comptime for i in range(Self.n):
            var bi = UInt128(b[i])
            var carry = UInt64(0)
            comptime for j in range(Self.n):
                var p = UInt128(a[j]) * bi + UInt128(t[j]) + UInt128(carry)
                t[j] = UInt64(p & _LOW)
                carry = UInt64(p >> 64)
            var s = UInt128(top) + UInt128(carry)
            var hi = UInt64(s & _LOW)
            var hi2 = UInt64(s >> 64)
            var q = UInt128(t[0] * self.m0_inv)
            var p0 = q * UInt128(self.m[0]) + UInt128(t[0])
            carry = UInt64(p0 >> 64)
            comptime for j in range(1, Self.n):
                var p = q * UInt128(self.m[j]) + UInt128(t[j]) + UInt128(carry)
                t[j - 1] = UInt64(p & _LOW)
                carry = UInt64(p >> 64)
            var s2 = UInt128(hi) + UInt128(carry)
            t[Self.n - 1] = UInt64(s2 & _LOW)
            top = hi2 + UInt64(s2 >> 64)
        return self._reduce_once(t, top)

    @inline(.always)
    def square(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Computes the Montgomery square in constant time.

        Args:
            a: The value to square, in `[0, m)`.

        Returns:
            The value `a * a * R^-1 mod m`.
        """
        return self.mul(a, a)

    def to_mont(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Converts a reduced value into Montgomery form in constant time.

        Args:
            a: The value to convert, in `[0, m)`.

        Returns:
            The value `a * R mod m`.
        """
        return self.mul(a, self.rr)

    def from_mont(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Converts a value out of Montgomery form in constant time.

        Args:
            a: The Montgomery-form value, in `[0, m)`.

        Returns:
            The value `a * R^-1 mod m`, in `[0, m)`.
        """
        var unit = Array[UInt64, Self.n](fill=0)
        unit[0] = 1
        return self.mul(a, unit)

    def pow(
        self, a: Array[UInt64, Self.n], exponent: Array[UInt64, Self.n]
    ) -> Array[UInt64, Self.n]:
        """Raises a Montgomery-form value to a public power.

        Constant-time in `a`, but variable-time in `exponent`: the sequence
        of multiplications and the table indices follow the exponent bits.
        Only pass exponents that are public.

        Args:
            a: The base in Montgomery form, in `[0, m)`.
            exponent: The public exponent.

        Returns:
            The Montgomery form of the base raised to `exponent`.
        """
        # Fixed 4-bit windows over powers a^0 .. a^15.
        var table = List[Array[UInt64, Self.n]](capacity=16)
        table.append(self.one.copy())
        table.append(a.copy())
        for i in range(2, 16):
            table.append(self.mul(table[i - 1], a))
        var acc = self.one.copy()
        for w in range(16 * Self.n):
            var index = 16 * Self.n - 1 - w
            for _ in range(4):
                acc = self.square(acc)
            var limb = exponent[index >> 4]
            var digit = Int((limb >> UInt64(4 * (index & 15))) & 0xF)
            if digit != 0:
                acc = self.mul(acc, table[digit])
        return acc^

    def inv(self, a: Array[UInt64, Self.n]) -> Array[UInt64, Self.n]:
        """Inverts a Montgomery-form value modulo a prime `m`.

        Uses Fermat's little theorem, `a^(m-2)`. The exponent is the public
        constant `m - 2`, so the running time does not depend on `a`.

        Args:
            a: The value to invert, in Montgomery form, in `[0, m)`.

        Returns:
            The Montgomery form of the inverse, or zero if `a` is zero. The
            result is meaningless unless `m` is prime.
        """
        return self.pow(a, self.m_minus_2)
