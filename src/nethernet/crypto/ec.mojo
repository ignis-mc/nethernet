"""Short-Weierstrass elliptic curves with `a = -3`: ECDH and ECDSA.

The group law uses homogeneous projective coordinates and the complete
addition formulas of Renes, Costello and Batina, "Complete addition formulas
for prime order elliptic curves" (EUROCRYPT 2016), Algorithms 4 to 6. They
have no exceptional cases on curves of prime order, so the same straight-line
code handles doubling, adding the point at infinity and adding inverses.

Constant-time contract. Field and scalar arithmetic, the group law,
`Curve.scalar_mul()`, `Curve.scalar_base_mul()`, `ec_private_key_from_bytes()`,
`ec_public_key()`, `ecdh()` and `ecdsa_sign()` have no secret-dependent
branches or table indices: tables are read with full masked scans, and the
masks come from `mont`, which hides them from the optimiser. The exceptions
are stated where they occur: checks that end in an error or a retry branch
on whether a value is valid, never on the value itself. `ecdsa_verify()`,
`Curve.double_scalar_mul_vartime()`, `Curve.decode_point()` and
`Curve.is_on_curve()` are variable-time because they only see public data.
Secret intermediates are not wiped from the stack.
"""

from .ct import zeroize
from .hash import Hash
from .hmac import Hmac
from .mont import (
    Modulus,
    ct_eq,
    ct_is_zero,
    ct_lt,
    ct_select,
    ct_word_eq,
    limbs_from_be_bytes,
    limbs_reduce_be_bytes,
    limbs_to_be_bytes,
)


@fieldwise_init
struct AffinePoint[n: Int](Copyable):
    """A finite curve point `(x, y)` with coordinates in Montgomery form."""

    var x: Array[UInt64, Self.n]
    """The x-coordinate, in Montgomery form."""
    var y: Array[UInt64, Self.n]
    """The y-coordinate, in Montgomery form."""


@fieldwise_init
struct ProjectivePoint[n: Int](Copyable):
    """A curve point `(X : Y : Z)` in homogeneous projective coordinates.

    The affine point is `(X / Z, Y / Z)`; the point at infinity has `Z = 0`.
    Coordinates are in Montgomery form.
    """

    var x: Array[UInt64, Self.n]
    """The X-coordinate, in Montgomery form."""
    var y: Array[UInt64, Self.n]
    """The Y-coordinate, in Montgomery form."""
    var z: Array[UInt64, Self.n]
    """The Z-coordinate, in Montgomery form."""


struct Curve[n: Int](Copyable):
    """A prime-order curve `y^2 = x^3 - 3 x + b` over a prime field.

    Both the field prime and the group order must have exactly `64 * n` bits
    (true for P-256 with `n = 4` and P-384 with `n = 6`); several reductions
    rely on that.
    """

    var field: Modulus[Self.n]
    """Arithmetic modulo the field prime `p`."""
    var scalar: Modulus[Self.n]
    """Arithmetic modulo the group order."""
    var b: Array[UInt64, Self.n]
    """The curve coefficient `b`, in Montgomery form."""
    var generator: AffinePoint[Self.n]
    """The base point `G`."""
    var order_minus_one: Array[UInt64, Self.n]
    """The group order minus one, as a plain integer."""
    var comb: Array[UInt64, 30 * Self.n]
    """The fixed-base comb table used by `scalar_base_mul()`.

    Entry `u` for `u` in `[1, 15]` is the affine point
    `sum(2^(16 n i) G for each set bit i of u)`, stored at limb offset
    `2 n (u - 1)` as `x` then `y`, in Montgomery form.
    """

    def __init__(
        out self,
        p: Array[UInt64, Self.n],
        order: Array[UInt64, Self.n],
        b: Array[UInt64, Self.n],
        gx: Array[UInt64, Self.n],
        gy: Array[UInt64, Self.n],
    ):
        """Derives a curve description from its domain parameters.

        All arguments are plain integers as little-endian 64-bit limbs.
        """
        self.field = Modulus[Self.n](p)
        self.scalar = Modulus[Self.n](order)
        self.b = self.field.to_mont(b)
        self.generator = AffinePoint[Self.n](
            self.field.to_mont(gx), self.field.to_mont(gy)
        )
        self.order_minus_one = _minus_one(order)
        self.comb = Array[UInt64, 30 * Self.n](fill=0)
        # powers[i] = 2^(16 n i) G.
        var powers = List[ProjectivePoint[Self.n]](capacity=4)
        powers.append(self.to_projective(self.generator))
        for i in range(1, 4):
            var next = powers[i - 1].copy()
            for _ in range(16 * Self.n):
                next = self.double(next)
            powers.append(next^)
        for u in range(1, 16):
            var sum = self.infinity()
            for i in range(4):
                if (u >> i) & 1 == 1:
                    sum = self.add(sum, powers[i])
            var entry = self.to_affine(sum)
            for i in range(Self.n):
                self.comb[2 * Self.n * (u - 1) + i] = entry.x[i]
                self.comb[2 * Self.n * (u - 1) + Self.n + i] = entry.y[i]

    def __init__(
        out self,
        *,
        field: Modulus[Self.n],
        scalar: Modulus[Self.n],
        b: Array[UInt64, Self.n],
        gx: Array[UInt64, Self.n],
        gy: Array[UInt64, Self.n],
        comb: Array[UInt64, 30 * Self.n],
    ):
        """Wraps precomputed curve constants without checking them.

        The values must equal what the deriving constructor computes.
        """
        self.field = field.copy()
        self.scalar = scalar.copy()
        self.b = b.copy()
        self.generator = AffinePoint[Self.n](gx.copy(), gy.copy())
        self.order_minus_one = _minus_one(scalar.m)
        self.comb = comb.copy()

    def infinity(self) -> ProjectivePoint[Self.n]:
        """Returns the point at infinity, the group identity."""
        var zero = Array[UInt64, Self.n](fill=0)
        return ProjectivePoint[Self.n](
            zero.copy(), self.field.one.copy(), zero^
        )

    def to_projective(self, p: AffinePoint[Self.n]) -> ProjectivePoint[Self.n]:
        """Lifts an affine point to projective coordinates."""
        return ProjectivePoint[Self.n](
            p.x.copy(), p.y.copy(), self.field.one.copy()
        )

    def is_infinity(self, p: ProjectivePoint[Self.n]) -> UInt64:
        """Tests for the point at infinity in constant time."""
        return ct_is_zero(p.z)

    def to_affine(self, p: ProjectivePoint[Self.n]) -> AffinePoint[Self.n]:
        """Normalises a projective point in constant time.

        Costs one field inversion.
        """
        ref f = self.field
        var z_inv = f.inv(p.z)
        return AffinePoint[Self.n](f.mul(p.x, z_inv), f.mul(p.y, z_inv))

    def is_on_curve(
        self, x: Array[UInt64, Self.n], y: Array[UInt64, Self.n]
    ) -> Bool:
        """Checks the curve equation `y^2 = x^3 - 3 x + b`.

        Variable-time only in its one-bit result.
        """
        ref f = self.field
        var lhs = f.square(y)
        var x3 = f.mul(f.square(x), x)
        var three_x = f.add(f.add(x, x), x)
        var rhs = f.add(f.sub(x3, three_x), self.b)
        return ct_eq(lhs, rhs) != 0

    def add(
        self, p: ProjectivePoint[Self.n], q: ProjectivePoint[Self.n]
    ) -> ProjectivePoint[Self.n]:
        """Adds two points in constant time.

        Complete: valid for every pair of curve points, including equal
        points, inverses and the point at infinity (RCB16 Algorithm 4).
        """
        ref f = self.field
        var t0 = f.mul(p.x, q.x)
        var t1 = f.mul(p.y, q.y)
        var t2 = f.mul(p.z, q.z)
        var t3 = f.add(p.x, p.y)
        var t4 = f.add(q.x, q.y)
        t3 = f.mul(t3, t4)
        t4 = f.add(t0, t1)
        t3 = f.sub(t3, t4)
        t4 = f.add(p.y, p.z)
        var x3 = f.add(q.y, q.z)
        t4 = f.mul(t4, x3)
        x3 = f.add(t1, t2)
        t4 = f.sub(t4, x3)
        x3 = f.add(p.x, p.z)
        var y3 = f.add(q.x, q.z)
        x3 = f.mul(x3, y3)
        y3 = f.add(t0, t2)
        y3 = f.sub(x3, y3)
        var z3 = f.mul(self.b, t2)
        x3 = f.sub(y3, z3)
        z3 = f.add(x3, x3)
        x3 = f.add(x3, z3)
        z3 = f.sub(t1, x3)
        x3 = f.add(t1, x3)
        y3 = f.mul(self.b, y3)
        t1 = f.add(t2, t2)
        t2 = f.add(t1, t2)
        y3 = f.sub(y3, t2)
        y3 = f.sub(y3, t0)
        t1 = f.add(y3, y3)
        y3 = f.add(t1, y3)
        t1 = f.add(t0, t0)
        t0 = f.add(t1, t0)
        t0 = f.sub(t0, t2)
        t1 = f.mul(t4, y3)
        t2 = f.mul(t0, y3)
        y3 = f.mul(x3, z3)
        y3 = f.add(y3, t2)
        x3 = f.mul(t3, x3)
        x3 = f.sub(x3, t1)
        z3 = f.mul(t4, z3)
        t1 = f.mul(t3, t0)
        z3 = f.add(z3, t1)
        return ProjectivePoint[Self.n](x3^, y3^, z3^)

    def add_mixed(
        self, p: ProjectivePoint[Self.n], q: AffinePoint[Self.n]
    ) -> ProjectivePoint[Self.n]:
        """Adds an affine point to a projective point in constant time.

        Complete for every `p`, including the point at infinity and `±q`
        (RCB16 Algorithm 5). The affine operand must be a curve point; the
        `(0, 0)` placeholder gives a meaningless result.
        """
        ref f = self.field
        var t0 = f.mul(p.x, q.x)
        var t1 = f.mul(p.y, q.y)
        var t3 = f.add(q.x, q.y)
        var t4 = f.add(p.x, p.y)
        t3 = f.mul(t3, t4)
        t4 = f.add(t0, t1)
        t3 = f.sub(t3, t4)
        t4 = f.mul(q.y, p.z)
        t4 = f.add(t4, p.y)
        var y3 = f.mul(q.x, p.z)
        y3 = f.add(y3, p.x)
        var z3 = f.mul(self.b, p.z)
        var x3 = f.sub(y3, z3)
        z3 = f.add(x3, x3)
        x3 = f.add(x3, z3)
        z3 = f.sub(t1, x3)
        x3 = f.add(t1, x3)
        y3 = f.mul(self.b, y3)
        t1 = f.add(p.z, p.z)
        var t2 = f.add(t1, p.z)
        y3 = f.sub(y3, t2)
        y3 = f.sub(y3, t0)
        t1 = f.add(y3, y3)
        y3 = f.add(t1, y3)
        t1 = f.add(t0, t0)
        t0 = f.add(t1, t0)
        t0 = f.sub(t0, t2)
        t1 = f.mul(t4, y3)
        t2 = f.mul(t0, y3)
        y3 = f.mul(x3, z3)
        y3 = f.add(y3, t2)
        x3 = f.mul(t3, x3)
        x3 = f.sub(x3, t1)
        z3 = f.mul(t4, z3)
        t1 = f.mul(t3, t0)
        z3 = f.add(z3, t1)
        return ProjectivePoint[Self.n](x3^, y3^, z3^)

    def double(self, p: ProjectivePoint[Self.n]) -> ProjectivePoint[Self.n]:
        """Doubles a point in constant time.

        Complete: valid for every curve point, including the point at
        infinity (RCB16 Algorithm 6).
        """
        ref f = self.field
        var t0 = f.square(p.x)
        var t1 = f.square(p.y)
        var t2 = f.square(p.z)
        var t3 = f.mul(p.x, p.y)
        t3 = f.add(t3, t3)
        var z3 = f.mul(p.x, p.z)
        z3 = f.add(z3, z3)
        var y3 = f.mul(self.b, t2)
        y3 = f.sub(y3, z3)
        var x3 = f.add(y3, y3)
        y3 = f.add(x3, y3)
        x3 = f.sub(t1, y3)
        y3 = f.add(t1, y3)
        y3 = f.mul(x3, y3)
        x3 = f.mul(x3, t3)
        t3 = f.add(t2, t2)
        t2 = f.add(t2, t3)
        z3 = f.mul(self.b, z3)
        z3 = f.sub(z3, t2)
        z3 = f.sub(z3, t0)
        t3 = f.add(z3, z3)
        z3 = f.add(z3, t3)
        t3 = f.add(t0, t0)
        t0 = f.add(t3, t0)
        t0 = f.sub(t0, t2)
        t0 = f.mul(t0, z3)
        y3 = f.add(y3, t0)
        t0 = f.mul(p.y, p.z)
        t0 = f.add(t0, t0)
        z3 = f.mul(t0, z3)
        x3 = f.sub(x3, z3)
        z3 = f.mul(t0, t1)
        z3 = f.add(z3, z3)
        z3 = f.add(z3, z3)
        return ProjectivePoint[Self.n](x3^, y3^, z3^)

    def _multiples(
        self, p: ProjectivePoint[Self.n]
    ) -> List[ProjectivePoint[Self.n]]:
        # [0 p, 1 p, ..., 15 p], built with a fixed sequence of operations.
        var table = List[ProjectivePoint[Self.n]](capacity=16)
        table.append(self.infinity())
        table.append(p.copy())
        for i in range(2, 16):
            if i % 2 == 0:
                table.append(self.double(table[i // 2]))
            else:
                table.append(self.add(table[i - 1], p))
        return table^

    def _select(
        self, table: List[ProjectivePoint[Self.n]], digit: UInt64
    ) -> ProjectivePoint[Self.n]:
        # Reads table[digit] by scanning every entry under a mask.
        var x = Array[UInt64, Self.n](fill=0)
        var y = Array[UInt64, Self.n](fill=0)
        var z = Array[UInt64, Self.n](fill=0)
        for j in range(len(table)):
            var mask = ct_word_eq(UInt64(j), digit)
            for i in range(Self.n):
                x[i] |= table[j].x[i] & mask
                y[i] |= table[j].y[i] & mask
                z[i] |= table[j].z[i] & mask
        return ProjectivePoint[Self.n](x^, y^, z^)

    def scalar_mul(
        self, k: Array[UInt64, Self.n], p: ProjectivePoint[Self.n]
    ) -> ProjectivePoint[Self.n]:
        """Multiplies a point by a secret scalar in constant time.

        Uses fixed 4-bit windows: a table of the sixteen multiples
        `0 p .. 15 p`, read with a full masked scan, and one complete
        addition per window whatever the digit is. The sequence of field
        operations and memory accesses does not depend on `k` or `p`.
        """
        var table = self._multiples(p)
        var top = 16 * Self.n - 1
        var acc = self._select(table, _window(k, top))
        for w in range(1, 16 * Self.n):
            acc = self.double(acc)
            acc = self.double(acc)
            acc = self.double(acc)
            acc = self.double(acc)
            var entry = self._select(table, _window(k, top - w))
            acc = self.add(acc, entry)
        return acc^

    def _comb_digit(self, k: Array[UInt64, Self.n], column: Int) -> UInt64:
        # Bits column, column + 16 n, column + 32 n, column + 48 n of k.
        var digit = UInt64(0)
        for i in range(4):
            var position = 16 * Self.n * i + column
            var bit = (k[position >> 6] >> UInt64(position & 63)) & 1
            digit |= bit << UInt64(i)
        return digit

    def _comb_entry(self, u: Int) -> AffinePoint[Self.n]:
        # Direct, variable-time read of comb entry u in [1, 15].
        var x = Array[UInt64, Self.n](fill=0)
        var y = Array[UInt64, Self.n](fill=0)
        var offset = 2 * Self.n * (u - 1)
        for i in range(Self.n):
            x[i] = self.comb[offset + i]
            y[i] = self.comb[offset + Self.n + i]
        return AffinePoint[Self.n](x^, y^)

    def _comb_select(self, digit: UInt64) -> AffinePoint[Self.n]:
        # Masked scan of the whole comb table; (0, 0) for digit 0.
        var x = Array[UInt64, Self.n](fill=0)
        var y = Array[UInt64, Self.n](fill=0)
        for u in range(1, 16):
            var mask = ct_word_eq(UInt64(u), digit)
            var offset = 2 * Self.n * (u - 1)
            for i in range(Self.n):
                x[i] |= self.comb[offset + i] & mask
                y[i] |= self.comb[offset + Self.n + i] & mask
        return AffinePoint[Self.n](x^, y^)

    def scalar_base_mul(
        self, k: Array[UInt64, Self.n]
    ) -> ProjectivePoint[Self.n]:
        """Multiplies the base point by a secret scalar in constant time.

        Uses a four-row Lim-Lee comb over the precomputed `comb` table:
        `16 n` columns, each one doubling and one complete mixed addition.
        Every column reads the whole table under a mask and always performs
        the addition; a zero digit discards the sum with a constant-time
        select. The sequence of field operations and memory accesses does
        not depend on `k`.
        """
        var acc = self.infinity()
        for step in range(16 * Self.n):
            var column = 16 * Self.n - 1 - step
            acc = self.double(acc)
            var digit = self._comb_digit(k, column)
            var sum = self.add_mixed(acc, self._comb_select(digit))
            var keep = ct_word_eq(digit, 0)
            acc.x = ct_select(keep, acc.x, sum.x)
            acc.y = ct_select(keep, acc.y, sum.y)
            acc.z = ct_select(keep, acc.z, sum.z)
        return acc^

    def double_scalar_mul_vartime(
        self,
        u1: Array[UInt64, Self.n],
        u2: Array[UInt64, Self.n],
        q: ProjectivePoint[Self.n],
    ) -> ProjectivePoint[Self.n]:
        """Computes `u1 G + u2 q` for public inputs.

        Variable-time: Straus interleaving of 4-bit windows for `q` with the
        fixed-base comb for `G`, using direct table indexing and skipping
        work for zero digits. Use it for signature verification only, never
        with a secret scalar.
        """
        var q_table = self._multiples(q)
        var acc = self.infinity()
        var started = False
        for step in range(64 * Self.n):
            var bit = 64 * Self.n - 1 - step
            if started:
                acc = self.double(acc)
            if bit % 4 == 0:
                var d2 = Int(_window(u2, bit // 4))
                if d2 != 0:
                    acc = self.add(acc, q_table[d2])
                    started = True
            if bit < 16 * Self.n:
                var d1 = Int(self._comb_digit(u1, bit))
                if d1 != 0:
                    acc = self.add_mixed(acc, self._comb_entry(d1))
                    started = True
        return acc^

    def decode_scalar(
        self, data: Span[UInt8, _], mut out: Array[UInt64, Self.n]
    ) -> Bool:
        """Decodes a fixed-width big-endian scalar in `[1, order - 1]`.

        The range check itself is branch-free; only its one-bit outcome is
        revealed.
        """
        if len(data) != 8 * Self.n:
            return False
        out = limbs_from_be_bytes[Self.n](data)
        var ok = ~ct_is_zero(out) & ct_lt(out, self.scalar.m)
        return ok != 0

    def decode_point(
        self, data: Span[UInt8, _], mut out: AffinePoint[Self.n]
    ) -> Bool:
        """Decodes and fully validates an uncompressed SEC 1 point.

        Checks the length, the `0x04` prefix, that both coordinates are
        below `p`, and the curve equation. The curve has cofactor one, so a
        point that passes is in the prime-order group. Variable-time: the
        input is public.
        """
        var size = 8 * Self.n
        if len(data) != 2 * size + 1:
            return False
        if data[0] != 0x04:
            return False
        var x = limbs_from_be_bytes[Self.n](data[1 : 1 + size])
        var y = limbs_from_be_bytes[Self.n](data[1 + size : 1 + 2 * size])
        if (ct_lt(x, self.field.m) & ct_lt(y, self.field.m)) == 0:
            return False
        var xm = self.field.to_mont(x)
        var ym = self.field.to_mont(y)
        if not self.is_on_curve(xm, ym):
            return False
        out = AffinePoint[Self.n](xm^, ym^)
        return True

    def encode_point(
        self, p: AffinePoint[Self.n]
    ) -> Array[UInt8, 16 * Self.n + 1]:
        """Encodes an affine point in uncompressed SEC 1 form."""
        var size = 8 * Self.n
        var out = Array[UInt8, 16 * Self.n + 1](fill=0)
        out[0] = 0x04
        var x = limbs_to_be_bytes(self.field.from_mont(p.x))
        var y = limbs_to_be_bytes(self.field.from_mont(p.y))
        for i in range(size):
            out[1 + i] = x[i]
            out[1 + size + i] = y[i]
        return out^

    def digest_to_scalar(self, digest: Span[UInt8, _]) -> Array[UInt64, Self.n]:
        """Converts a message digest to an integer modulo the group order.

        Follows FIPS 186-4 and the `bits2int` of RFC 6979: the leftmost
        `64 * n` bits of the digest, read big-endian, then reduced. Shorter
        digests are used whole.
        """
        var count = len(digest)
        if count > 8 * Self.n:
            count = 8 * Self.n
        var e = limbs_from_be_bytes[Self.n](digest[0:count])
        return self.scalar.reduce_once(e)

    def x_mod_order(self, p: AffinePoint[Self.n]) -> Array[UInt64, Self.n]:
        """Reduces the x-coordinate of a point modulo the group order."""
        return self.scalar.reduce_once(self.field.from_mont(p.x))


def _minus_one[n: Int](order: Array[UInt64, n]) -> Array[UInt64, n]:
    # The order is odd, so clearing the low bit subtracts one.
    var out = order.copy()
    out[0] = order[0] & ~UInt64(1)
    return out^


@inline(.always)
def _window[n: Int](k: Array[UInt64, n], index: Int) -> UInt64:
    # The 4-bit digit of k at nibble position `index` (0 = least significant).
    return (k[index >> 4] >> UInt64(4 * (index & 15))) & 0xF


struct Rfc6979[H: Hash]:
    """The deterministic nonce generator of RFC 6979, section 3.2.

    This is HMAC_DRBG keyed with the private key and the message digest. It
    yields the candidate byte strings `T` of step (h); the caller converts
    each to an integer and asks for another one if it is out of range.
    """

    var _key: Array[UInt8, Self.H.DIGEST_SIZE]
    var _v: Array[UInt8, Self.H.DIGEST_SIZE]
    var _started: Bool

    def __init__(out self, private_key: Span[UInt8, _], hashed: Span[UInt8, _]):
        """Seeds the generator (steps b to g)."""
        self._key = Array[UInt8, Self.H.DIGEST_SIZE](fill=0x00)
        self._v = Array[UInt8, Self.H.DIGEST_SIZE](fill=0x01)
        self._started = False
        var seed = List[UInt8](capacity=len(private_key) + len(hashed))
        for byte in private_key:
            seed.append(byte)
        for byte in hashed:
            seed.append(byte)
        self._rekey(0x00, Span(seed))
        self._rekey(0x01, Span(seed))
        zeroize(seed)

    def _rekey(mut self, separator: UInt8, seed: Span[UInt8, _]):
        # K = HMAC_K(V || separator || seed); V = HMAC_K(V).
        var sep: Array[UInt8, 1] = [separator]
        var mac = Hmac[Self.H](Span(self._key))
        mac.update(Span(self._v))
        mac.update(Span(sep))
        mac.update(seed)
        self._key = mac.finish()
        var mac2 = Hmac[Self.H](Span(self._key))
        mac2.update(Span(self._v))
        self._v = mac2.finish()

    def generate(mut self, count: Int) -> List[UInt8]:
        """Produces the next candidate nonce bytes (step h).

        Every call after the first one first applies the "try again" update
        `K = HMAC_K(V || 0x00)`, `V = HMAC_K(V)`.
        """
        if self._started:
            var empty = List[UInt8]()
            self._rekey(0x00, Span(empty))
        self._started = True
        var out = List[UInt8](capacity=count)
        while len(out) < count:
            var mac = Hmac[Self.H](Span(self._key))
            mac.update(Span(self._v))
            self._v = mac.finish()
            for i in range(Self.H.DIGEST_SIZE):
                if len(out) < count:
                    out.append(self._v[i])
        return out^


def ec_private_key_from_bytes[
    n: Int
](curve: Curve[n], seed: Span[UInt8, _]) raises -> Array[UInt8, 8 * n]:
    """Derives a private scalar from uniformly random bytes.

    Interprets the seed as a big-endian integer `c` and returns
    `(c mod (order - 1)) + 1`, the method of FIPS 186-4 B.4.1. With at least
    64 bits more than the order has, the result is within `2^-64` of uniform
    on `[1, order - 1]`. Constant-time in the seed value.
    """
    if len(seed) < 8 * n + 8:
        raise Error("EC key derivation needs at least 64 extra seed bits")
    var d = limbs_reduce_be_bytes[n](seed, curve.order_minus_one)
    var carry = UInt64(1)
    for i in range(n):
        var s = UInt128(d[i]) + UInt128(carry)
        d[i] = UInt64(s & 0xFFFF_FFFF_FFFF_FFFF)
        carry = UInt64(s >> 64)
    return limbs_to_be_bytes(d)


def ec_public_key[
    n: Int
](curve: Curve[n], private_key: Span[UInt8, _]) raises -> Array[
    UInt8, 16 * n + 1
]:
    """Computes the public key of a private scalar in constant time."""
    var d = Array[UInt64, n](fill=0)
    if not curve.decode_scalar(private_key, d):
        raise Error("invalid EC private key")
    var point = curve.to_affine(curve.scalar_base_mul(d))
    return curve.encode_point(point)


def ecdh[
    n: Int
](
    curve: Curve[n],
    private_key: Span[UInt8, _],
    peer_public_key: Span[UInt8, _],
) raises -> Array[UInt8, 8 * n]:
    """Computes an elliptic-curve Diffie-Hellman shared secret.

    The scalar multiplication is constant-time. The peer key is public and
    is validated in variable time before use.
    """
    var d = Array[UInt64, n](fill=0)
    if not curve.decode_scalar(private_key, d):
        raise Error("invalid EC private key")
    var zero = Array[UInt64, n](fill=0)
    var peer = AffinePoint[n](zero.copy(), zero^)
    if not curve.decode_point(peer_public_key, peer):
        raise Error("invalid EC public key")
    var shared = curve.scalar_mul(d, curve.to_projective(peer))
    if curve.is_infinity(shared) != 0:
        raise Error("ECDH result is the point at infinity")
    var point = curve.to_affine(shared)
    return limbs_to_be_bytes(curve.field.from_mont(point.x))


def ecdsa_sign[
    n: Int, //, H: Hash
](
    curve: Curve[n], private_key: Span[UInt8, _], digest: Span[UInt8, _]
) raises -> Array[UInt8, 16 * n]:
    """Signs a message digest with ECDSA and an RFC 6979 nonce.

    Constant-time in the private key and the nonce: the nonce
    multiplication uses `Curve.scalar_base_mul()` and the nonce is inverted
    with a fixed exponent. The only data-dependent control flow is the
    retry when a nonce candidate is out of range or gives `r = 0` or
    `s = 0`, which happens with negligible probability and reveals nothing
    about the nonce that is finally used.
    """
    var d = Array[UInt64, n](fill=0)
    if not curve.decode_scalar(private_key, d):
        raise Error("invalid EC private key")
    ref order = curve.scalar
    var e = curve.digest_to_scalar(digest)
    var e_bytes = limbs_to_be_bytes(e)
    var nonces = Rfc6979[H](private_key, Span(e_bytes))
    var d_mont = order.to_mont(d)
    var e_mont = order.to_mont(e)
    var out = Array[UInt8, 16 * n](fill=0)
    while True:
        var candidate = nonces.generate(8 * n)
        var k = limbs_from_be_bytes[n](Span(candidate))
        zeroize(candidate)
        if (~ct_is_zero(k) & ct_lt(k, order.m)) == 0:
            continue
        var point = curve.to_affine(curve.scalar_base_mul(k))
        var r = curve.x_mod_order(point)
        if ct_is_zero(r) != 0:
            continue
        var k_inv = order.inv(order.to_mont(k))
        var rd = order.mul(order.to_mont(r), d_mont)
        var s = order.from_mont(order.mul(k_inv, order.add(e_mont, rd)))
        if ct_is_zero(s) != 0:
            continue
        var r_bytes = limbs_to_be_bytes(r)
        var s_bytes = limbs_to_be_bytes(s)
        for i in range(8 * n):
            out[i] = r_bytes[i]
            out[8 * n + i] = s_bytes[i]
        break
    return out^


def ecdsa_verify[
    n: Int
](
    curve: Curve[n],
    public_key: Span[UInt8, _],
    digest: Span[UInt8, _],
    signature: Span[UInt8, _],
) -> Bool:
    """Verifies an ECDSA signature over a message digest.

    Variable-time: every input is public.
    """
    var size = 8 * n
    if len(signature) != 2 * size:
        return False
    var r = Array[UInt64, n](fill=0)
    var s = Array[UInt64, n](fill=0)
    if not curve.decode_scalar(signature[0:size], r):
        return False
    if not curve.decode_scalar(signature[size : 2 * size], s):
        return False
    var zero = Array[UInt64, n](fill=0)
    var q = AffinePoint[n](zero.copy(), zero^)
    if not curve.decode_point(public_key, q):
        return False
    ref order = curve.scalar
    var e = curve.digest_to_scalar(digest)
    var w = order.inv(order.to_mont(s))
    var u1 = order.from_mont(order.mul(order.to_mont(e), w))
    var u2 = order.from_mont(order.mul(order.to_mont(r), w))
    var sum = curve.double_scalar_mul_vartime(u1, u2, curve.to_projective(q))
    if curve.is_infinity(sum) != 0:
        return False
    var v = curve.x_mod_order(curve.to_affine(sum))
    return ct_eq(v, r) != 0
