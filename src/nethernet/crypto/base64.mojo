"""Base64 (RFC 4648): the standard alphabet with padding and the URL-safe one without."""

comptime _STD: StaticString = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)
comptime _URL: StaticString = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _encode(data: Span[UInt8, _], alphabet: StringSpan, pad: Bool) -> String:
    var table = alphabet.as_bytes()
    var out = List[UInt8](capacity=(len(data) + 2) // 3 * 4)
    var i = 0
    while i + 3 <= len(data):
        var n = (
            (UInt32(data[i]) << 16)
            | (UInt32(data[i + 1]) << 8)
            | UInt32(data[i + 2])
        )
        out.append(table[Int((n >> 18) & 63)])
        out.append(table[Int((n >> 12) & 63)])
        out.append(table[Int((n >> 6) & 63)])
        out.append(table[Int(n & 63)])
        i += 3
    var rest = len(data) - i
    if rest == 1:
        var n = UInt32(data[i]) << 16
        out.append(table[Int((n >> 18) & 63)])
        out.append(table[Int((n >> 12) & 63)])
        if pad:
            out.append(0x3D)
            out.append(0x3D)
    elif rest == 2:
        var n = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8)
        out.append(table[Int((n >> 18) & 63)])
        out.append(table[Int((n >> 12) & 63)])
        out.append(table[Int((n >> 6) & 63)])
        if pad:
            out.append(0x3D)
    return String(unsafe_from_utf8=Span(out))


def _value(c: UInt8, url: Bool) raises -> UInt32:
    if c >= 0x41 and c <= 0x5A:
        return UInt32(c - 0x41)
    if c >= 0x61 and c <= 0x7A:
        return UInt32(c - 0x61) + 26
    if c >= 0x30 and c <= 0x39:
        return UInt32(c - 0x30) + 52
    if url:
        if c == 0x2D:
            return 62
        if c == 0x5F:
            return 63
    else:
        if c == 0x2B:
            return 62
        if c == 0x2F:
            return 63
    raise Error("base64: invalid character")


def _decode(text: StringSpan, url: Bool) raises -> List[UInt8]:
    var src = text.as_bytes()
    var n = len(src)
    # Padding is optional on input for both alphabets.
    while n > 0 and src[n - 1] == 0x3D:
        n -= 1
    if len(src) - n > 2 or n % 4 == 1:
        raise Error("base64: invalid length")
    var out = List[UInt8](capacity=n * 3 // 4)
    var acc = UInt32(0)
    var bits = 0
    for i in range(n):
        acc = (acc << 6) | _value(src[i], url)
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append(UInt8((acc >> UInt32(bits)) & 0xFF))
    if (acc & ((UInt32(1) << UInt32(bits)) - 1)) != 0:
        raise Error("base64: non-zero trailing bits")
    return out^


def base64_encode(data: Span[UInt8, _]) -> String:
    """Encodes bytes with the standard alphabet and `=` padding."""
    return _encode(data, _STD, True)


def base64_decode(text: StringSpan) raises -> List[UInt8]:
    """Decodes standard-alphabet base64, with or without padding."""
    return _decode(text, False)


def base64url_encode(data: Span[UInt8, _]) -> String:
    """Encodes bytes with the URL-safe alphabet and no padding, as JWS does."""
    return _encode(data, _URL, False)


def base64url_decode(text: StringSpan) raises -> List[UInt8]:
    """Decodes URL-safe base64, with or without padding."""
    return _decode(text, True)
