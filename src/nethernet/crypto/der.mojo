"""A minimal ASN.1 DER reader and writer.

Covers the definite-length, single-byte-tag subset that X.509 certificates,
SubjectPublicKeyInfo structures and ECDSA signatures use.
"""

from ..wire import Reader, put_bytes

comptime DER_INTEGER = 0x02
"""Tag of an INTEGER."""
comptime DER_BIT_STRING = 0x03
"""Tag of a BIT STRING."""
comptime DER_OCTET_STRING = 0x04
"""Tag of an OCTET STRING."""
comptime DER_OID = 0x06
"""Tag of an OBJECT IDENTIFIER."""
comptime DER_UTF8_STRING = 0x0C
"""Tag of a UTF8String."""
comptime DER_UTC_TIME = 0x17
"""Tag of a UTCTime."""
comptime DER_GENERALIZED_TIME = 0x18
"""Tag of a GeneralizedTime."""
comptime DER_SEQUENCE = 0x30
"""Tag of a constructed SEQUENCE."""
comptime DER_SET = 0x31
"""Tag of a constructed SET."""
comptime DER_CONTEXT_0 = 0xA0
"""Tag of a constructed, context-specific `[0]` element."""


struct DerValue[origin: ImmOrigin]:
    """One decoded TLV: a tag and a view of its content."""

    var tag: UInt8
    """The identifier octet."""
    var content: Span[UInt8, Self.origin]
    """The content octets."""

    def __init__(out self, tag: UInt8, content: Span[UInt8, Self.origin]):
        """Creates a value."""
        self.tag = tag
        self.content = content


def der_next[o: ImmOrigin](mut r: Reader[o]) raises -> DerValue[o]:
    """Reads the next TLV."""
    var tag = r.u8()
    if (tag & 0x1F) == 0x1F:
        raise Error("DER: multi-byte tags are not supported")
    var first = r.u8()
    var length = 0
    if first < 0x80:
        length = Int(first)
    else:
        var n = Int(first & 0x7F)
        if n == 0 or n > 3:
            raise Error("DER: unsupported length encoding")
        for _ in range(n):
            length = (length << 8) | Int(r.u8())
        if length < 0x80 or (n > 1 and length < (1 << (8 * (n - 1)))):
            raise Error("DER: non-minimal length")
    return DerValue[o](tag, r.bytes(length))


def der_expect[
    o: ImmOrigin
](mut r: Reader[o], tag: UInt8) raises -> Span[UInt8, o]:
    """Reads the next TLV and checks its tag."""
    var v = der_next(r)
    if v.tag != tag:
        raise Error(t"DER: expected tag {tag}, found {v.tag}")
    return v.content


def der_put_length(mut out: List[UInt8], length: Int):
    """Appends a DER length."""
    if length < 0x80:
        out.append(UInt8(length))
    elif length < 0x100:
        out.append(0x81)
        out.append(UInt8(length))
    elif length < 0x10000:
        out.append(0x82)
        out.append(UInt8(length >> 8))
        out.append(UInt8(length & 0xFF))
    else:
        out.append(0x83)
        out.append(UInt8((length >> 16) & 0xFF))
        out.append(UInt8((length >> 8) & 0xFF))
        out.append(UInt8(length & 0xFF))


def der_put(mut out: List[UInt8], tag: UInt8, content: Span[UInt8, _]):
    """Appends one TLV."""
    out.append(tag)
    der_put_length(out, len(content))
    put_bytes(out, content)


def der_put_unsigned(mut out: List[UInt8], value: Span[UInt8, _]):
    """Appends a non-negative INTEGER from big-endian magnitude bytes.

    Leading zero bytes are stripped and a zero byte is added when the top bit
    is set, as DER requires.
    """
    var start = 0
    while start < len(value) - 1 and value[start] == 0:
        start += 1
    var content = List[UInt8]()
    if len(value) == 0:
        content.append(0)
    else:
        if (value[start] & 0x80) != 0:
            content.append(0)
        put_bytes(content, value[start : len(value)])
    der_put(out, DER_INTEGER, Span(content))
