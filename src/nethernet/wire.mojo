"""Byte-order helpers for parsing and building wire formats.

Parsers read from a `Reader` over a borrowed `Span[UInt8, _]`. Encoders append
to a caller-owned `List[UInt8]` with the `put_*` functions. Multi-byte integers
are big-endian (network order) unless the function name ends in `_le`.
"""


struct Reader[origin: ImmOrigin]:
    """A bounds-checked cursor over a borrowed byte span."""

    var data: Span[UInt8, Self.origin]
    """The bytes being read."""
    var pos: Int
    """The offset of the next unread byte."""

    def __init__(out self, data: Span[UInt8, Self.origin]):
        """Creates a reader positioned at the start of `data`."""
        self.data = data
        self.pos = 0

    def remaining(self) -> Int:
        """Counts the unread bytes."""
        return len(self.data) - self.pos

    def at_end(self) -> Bool:
        """Checks whether every byte has been read."""
        return self.pos >= len(self.data)

    def _need(self, n: Int) raises:
        if n < 0 or self.pos + n > len(self.data):
            raise Error(
                t"short read: need {n} bytes at offset {self.pos} of"
                t" {len(self.data)}"
            )

    def u8(mut self) raises -> UInt8:
        """Reads one byte."""
        self._need(1)
        var v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(mut self) raises -> UInt16:
        """Reads a big-endian 16-bit integer."""
        self._need(2)
        var p = self.pos
        self.pos += 2
        return (UInt16(self.data[p]) << 8) | UInt16(self.data[p + 1])

    def u24(mut self) raises -> UInt32:
        """Reads a big-endian 24-bit integer."""
        self._need(3)
        var p = self.pos
        self.pos += 3
        return (
            (UInt32(self.data[p]) << 16)
            | (UInt32(self.data[p + 1]) << 8)
            | UInt32(self.data[p + 2])
        )

    def u32(mut self) raises -> UInt32:
        """Reads a big-endian 32-bit integer."""
        self._need(4)
        var p = self.pos
        self.pos += 4
        return (
            (UInt32(self.data[p]) << 24)
            | (UInt32(self.data[p + 1]) << 16)
            | (UInt32(self.data[p + 2]) << 8)
            | UInt32(self.data[p + 3])
        )

    def u48(mut self) raises -> UInt64:
        """Reads a big-endian 48-bit integer."""
        var hi = UInt64(self.u16())
        var lo = UInt64(self.u32())
        return (hi << 32) | lo

    def u64(mut self) raises -> UInt64:
        """Reads a big-endian 64-bit integer."""
        var hi = UInt64(self.u32())
        var lo = UInt64(self.u32())
        return (hi << 32) | lo

    def u16_le(mut self) raises -> UInt16:
        """Reads a little-endian 16-bit integer."""
        self._need(2)
        var p = self.pos
        self.pos += 2
        return UInt16(self.data[p]) | (UInt16(self.data[p + 1]) << 8)

    def u32_le(mut self) raises -> UInt32:
        """Reads a little-endian 32-bit integer."""
        var lo = UInt32(self.u16_le())
        var hi = UInt32(self.u16_le())
        return lo | (hi << 16)

    def u64_le(mut self) raises -> UInt64:
        """Reads a little-endian 64-bit integer."""
        var lo = UInt64(self.u32_le())
        var hi = UInt64(self.u32_le())
        return lo | (hi << 32)

    def bytes(mut self, n: Int) raises -> Span[UInt8, Self.origin]:
        """Reads `n` bytes without copying them."""
        self._need(n)
        var s = self.data[self.pos : self.pos + n]
        self.pos += n
        return s

    def skip(mut self, n: Int) raises:
        """Advances the cursor by `n` bytes."""
        self._need(n)
        self.pos += n

    def rest(mut self) -> Span[UInt8, Self.origin]:
        """Reads every remaining byte without copying."""
        var s = self.data[self.pos : len(self.data)]
        self.pos = len(self.data)
        return s


def put_u8(mut out: List[UInt8], v: UInt8):
    """Appends one byte."""
    out.append(v)


def put_u16(mut out: List[UInt8], v: UInt16):
    """Appends a big-endian 16-bit integer."""
    out.append(UInt8(v >> 8))
    out.append(UInt8(v & 0xFF))


def put_u24(mut out: List[UInt8], v: UInt32):
    """Appends the low 24 bits of `v` in big-endian order."""
    out.append(UInt8((v >> 16) & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))


def put_u32(mut out: List[UInt8], v: UInt32):
    """Appends a big-endian 32-bit integer."""
    out.append(UInt8(v >> 24))
    out.append(UInt8((v >> 16) & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))


def put_u48(mut out: List[UInt8], v: UInt64):
    """Appends the low 48 bits of `v` in big-endian order."""
    put_u16(out, UInt16((v >> 32) & 0xFFFF))
    put_u32(out, UInt32(v & 0xFFFF_FFFF))


def put_u64(mut out: List[UInt8], v: UInt64):
    """Appends a big-endian 64-bit integer."""
    put_u32(out, UInt32(v >> 32))
    put_u32(out, UInt32(v & 0xFFFF_FFFF))


def put_u16_le(mut out: List[UInt8], v: UInt16):
    """Appends a little-endian 16-bit integer."""
    out.append(UInt8(v & 0xFF))
    out.append(UInt8(v >> 8))


def put_u32_le(mut out: List[UInt8], v: UInt32):
    """Appends a little-endian 32-bit integer."""
    put_u16_le(out, UInt16(v & 0xFFFF))
    put_u16_le(out, UInt16(v >> 16))


def put_u64_le(mut out: List[UInt8], v: UInt64):
    """Appends a little-endian 64-bit integer."""
    put_u32_le(out, UInt32(v & 0xFFFF_FFFF))
    put_u32_le(out, UInt32(v >> 32))


def put_bytes(mut out: List[UInt8], data: Span[UInt8, _]):
    """Appends a copy of `data`."""
    out.extend(data)


def put_zeros(mut out: List[UInt8], n: Int):
    """Appends `n` zero bytes."""
    for _ in range(n):
        out.append(0)


def set_u16(mut out: List[UInt8], offset: Int, v: UInt16):
    """Overwrites two bytes with a big-endian 16-bit integer."""
    out[offset] = UInt8(v >> 8)
    out[offset + 1] = UInt8(v & 0xFF)


def set_u24(mut out: List[UInt8], offset: Int, v: UInt32):
    """Overwrites three bytes with the low 24 bits of `v`, big-endian."""
    out[offset] = UInt8((v >> 16) & 0xFF)
    out[offset + 1] = UInt8((v >> 8) & 0xFF)
    out[offset + 2] = UInt8(v & 0xFF)


def set_u32(mut out: List[UInt8], offset: Int, v: UInt32):
    """Overwrites four bytes with a big-endian 32-bit integer."""
    out[offset] = UInt8(v >> 24)
    out[offset + 1] = UInt8((v >> 16) & 0xFF)
    out[offset + 2] = UInt8((v >> 8) & 0xFF)
    out[offset + 3] = UInt8(v & 0xFF)


def get_u16(data: Span[UInt8, _], offset: Int) -> UInt16:
    """Decodes a big-endian 16-bit integer at a fixed offset."""
    return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])


def get_u32(data: Span[UInt8, _], offset: Int) -> UInt32:
    """Decodes a big-endian 32-bit integer at a fixed offset."""
    return (
        (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
    )


def bytes_equal(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    """Compares two byte spans for equality.

    This comparison is not constant-time. Use
    `nethernet.crypto.ct.constant_time_eq()` for secrets.
    """
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def hex_encode(data: Span[UInt8, _]) -> String:
    """Encodes bytes as lowercase hexadecimal."""
    var digits = "0123456789abcdef".as_bytes()
    var out = List[UInt8](capacity=len(data) * 2)
    for b in data:
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 0xF)])
    return String(unsafe_from_utf8=Span(out))


def _hex_value(c: UInt8) raises -> UInt8:
    if c >= 0x30 and c <= 0x39:
        return c - 0x30
    if c >= 0x61 and c <= 0x66:
        return c - 0x61 + 10
    if c >= 0x41 and c <= 0x46:
        return c - 0x41 + 10
    raise Error("invalid hex digit")


def hex_decode(text: StringSpan) raises -> List[UInt8]:
    """Decodes a hexadecimal string."""
    return hex_decode_bytes(text.as_bytes())


def hex_decode_bytes(src: Span[UInt8, _]) raises -> List[UInt8]:
    """Decodes hexadecimal digits given as raw ASCII bytes.

    Unlike `hex_decode()`, the input need not be valid UTF-8, so bytes from
    the network can be passed directly.
    """
    if len(src) % 2 != 0:
        raise Error("hex string has odd length")
    var out = List[UInt8](capacity=len(src) // 2)
    for i in range(len(src) // 2):
        out.append((_hex_value(src[2 * i]) << 4) | _hex_value(src[2 * i + 1]))
    return out^


def bytes_of(text: StringSpan) -> List[UInt8]:
    """Copies the UTF-8 bytes of a string into a list."""
    return List[UInt8](text.as_bytes())


def string_of(data: Span[UInt8, _]) -> String:
    """Builds a string from bytes, replacing invalid UTF-8.

    Bytes from the network must never reach `String(unsafe_from_utf8=…)`:
    that constructor aborts on invalid UTF-8 when assertions are enabled and
    creates a malformed string when they are not. Use this where a best
    effort is fine, or `String(from_utf8=…)` to reject invalid input.
    """
    return String(from_utf8_lossy=data)
