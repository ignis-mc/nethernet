"""A small JSON reader and string quoter.

Just enough for the identity assertions NetherNet embeds in its SDP: split an
object into its members, unquote strings and read integers. Values are kept
as raw text until asked for, so nested objects can be handed on unchanged.
"""

comptime _MAX_DEPTH = 32


def json_quote(text: StringSpan) -> String:
    """Formats a string as a JSON string literal.

    Args:
        text: The string to quote.

    Returns:
        The text in double quotes with the mandatory escapes applied.
    """
    var hex = "0123456789abcdef".as_bytes()
    var out = List[UInt8](capacity=text.byte_length() + 2)
    out.append(0x22)
    for c in text.as_bytes():
        if c == 0x22:
            out.append(0x5C)
            out.append(0x22)
        elif c == 0x5C:
            out.append(0x5C)
            out.append(0x5C)
        elif c == 0x0A:
            out.append(0x5C)
            out.append(0x6E)
        elif c == 0x0D:
            out.append(0x5C)
            out.append(0x72)
        elif c == 0x09:
            out.append(0x5C)
            out.append(0x74)
        elif c < 0x20:
            out.append(0x5C)
            out.append(0x75)
            out.append(0x30)
            out.append(0x30)
            out.append(hex[Int(c >> 4)])
            out.append(hex[Int(c & 0xF)])
        else:
            out.append(c)
    out.append(0x22)
    return String(unsafe_from_utf8=Span(out))


def _is_space(c: UInt8) -> Bool:
    return c == 0x20 or c == 0x09 or c == 0x0A or c == 0x0D


def _skip_space(src: Span[UInt8, _], pos: Int) -> Int:
    var p = pos
    while p < len(src) and _is_space(src[p]):
        p += 1
    return p


def _skip_string(src: Span[UInt8, _], pos: Int) raises -> Int:
    """Returns the index just past the string literal starting at `pos`."""
    var p = pos + 1
    while p < len(src):
        if src[p] == 0x5C:
            p += 2
            continue
        if src[p] == 0x22:
            return p + 1
        if src[p] < 0x20:
            raise Error("JSON: control character in string")
        p += 1
    raise Error("JSON: unterminated string")


def _skip_value(src: Span[UInt8, _], pos: Int, depth: Int) raises -> Int:
    """Returns the index just past the value starting at `pos`."""
    if depth > _MAX_DEPTH:
        raise Error("JSON: nesting too deep")
    if pos >= len(src):
        raise Error("JSON: unexpected end of input")
    var c = src[pos]
    if c == 0x22:
        return _skip_string(src, pos)
    if c == 0x7B or c == 0x5B:
        var close: UInt8 = 0x7D if c == 0x7B else 0x5D
        var p = _skip_space(src, pos + 1)
        if p < len(src) and src[p] == close:
            return p + 1
        while True:
            if c == 0x7B:
                if p >= len(src) or src[p] != 0x22:
                    raise Error("JSON: expected a member name")
                p = _skip_space(src, _skip_string(src, p))
                if p >= len(src) or src[p] != 0x3A:
                    raise Error("JSON: expected ':'")
                p = _skip_space(src, p + 1)
            p = _skip_space(src, _skip_value(src, p, depth + 1))
            if p >= len(src):
                raise Error("JSON: unexpected end of input")
            if src[p] == close:
                return p + 1
            if src[p] != 0x2C:
                raise Error("JSON: expected ',' or a closing bracket")
            p = _skip_space(src, p + 1)
    # A number or a literal: take the run of token characters.
    var p = pos
    while p < len(src):
        var t = src[p]
        var ok = (
            (t >= 0x30 and t <= 0x39)
            or (t >= 0x61 and t <= 0x7A)
            or t == 0x2D
            or t == 0x2B
            or t == 0x2E
            or t == 0x45
        )
        if not ok:
            break
        p += 1
    if p == pos:
        raise Error("JSON: unexpected character")
    return p


def json_parse_object(text: StringSpan) raises -> Dict[String, String]:
    """Splits a JSON object into its members.

    Args:
        text: The JSON text of one object.

    Returns:
        A map from member name to the raw JSON text of its value. A repeated
        name keeps the last value.

    Raises:
        Error: If the text is not a well-formed object.
    """
    var src = text.as_bytes()
    var out = Dict[String, String]()
    var p = _skip_space(src, 0)
    if p >= len(src) or src[p] != 0x7B:
        raise Error("JSON: expected an object")
    p = _skip_space(src, p + 1)
    if p < len(src) and src[p] == 0x7D:
        if _skip_space(src, p + 1) != len(src):
            raise Error("JSON: trailing characters")
        return out^
    while True:
        if p >= len(src) or src[p] != 0x22:
            raise Error("JSON: expected a member name")
        var name_end = _skip_string(src, p)
        var name = json_parse_string(
            StringSpan(unsafe_from_utf8=src[p:name_end])
        )
        p = _skip_space(src, name_end)
        if p >= len(src) or src[p] != 0x3A:
            raise Error("JSON: expected ':'")
        p = _skip_space(src, p + 1)
        var value_end = _skip_value(src, p, 1)
        out[name] = String(unsafe_from_utf8=src[p:value_end])
        p = _skip_space(src, value_end)
        if p >= len(src):
            raise Error("JSON: unexpected end of input")
        if src[p] == 0x7D:
            break
        if src[p] != 0x2C:
            raise Error("JSON: expected ',' or '}'")
        p = _skip_space(src, p + 1)
    if _skip_space(src, p + 1) != len(src):
        raise Error("JSON: trailing characters")
    return out^


def _hex4(src: Span[UInt8, _], pos: Int) raises -> UInt32:
    if pos + 4 > len(src):
        raise Error("JSON: truncated \\u escape")
    var v = UInt32(0)
    for i in range(4):
        var c = src[pos + i]
        var d: UInt32
        if c >= 0x30 and c <= 0x39:
            d = UInt32(c - 0x30)
        elif c >= 0x61 and c <= 0x66:
            d = UInt32(c - 0x61) + 10
        elif c >= 0x41 and c <= 0x46:
            d = UInt32(c - 0x41) + 10
        else:
            raise Error("JSON: invalid \\u escape")
        v = (v << 4) | d
    return v


def _put_utf8(mut out: List[UInt8], cp: UInt32):
    if cp < 0x80:
        out.append(UInt8(cp))
    elif cp < 0x800:
        out.append(UInt8(0xC0 | (cp >> 6)))
        out.append(UInt8(0x80 | (cp & 0x3F)))
    elif cp < 0x10000:
        out.append(UInt8(0xE0 | (cp >> 12)))
        out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (cp & 0x3F)))
    else:
        out.append(UInt8(0xF0 | (cp >> 18)))
        out.append(UInt8(0x80 | ((cp >> 12) & 0x3F)))
        out.append(UInt8(0x80 | ((cp >> 6) & 0x3F)))
        out.append(UInt8(0x80 | (cp & 0x3F)))


def json_parse_string(raw: StringSpan) raises -> String:
    """Decodes a JSON string literal.

    Args:
        raw: The literal including its double quotes; surrounding white space
            is allowed.

    Returns:
        The string with escapes resolved.

    Raises:
        Error: If the text is not one well-formed string literal.
    """
    var src = raw.strip().as_bytes()
    if len(src) < 2 or src[0] != 0x22 or src[len(src) - 1] != 0x22:
        raise Error("JSON: expected a string")
    var out = List[UInt8](capacity=len(src))
    var p = 1
    var end = len(src) - 1
    while p < end:
        var c = src[p]
        if c == 0x22 or c < 0x20:
            raise Error("JSON: invalid character in string")
        if c != 0x5C:
            out.append(c)
            p += 1
            continue
        if p + 1 >= end:
            raise Error("JSON: truncated escape")
        var e = src[p + 1]
        p += 2
        if e == 0x22 or e == 0x5C or e == 0x2F:
            out.append(e)
        elif e == 0x62:
            out.append(0x08)
        elif e == 0x66:
            out.append(0x0C)
        elif e == 0x6E:
            out.append(0x0A)
        elif e == 0x72:
            out.append(0x0D)
        elif e == 0x74:
            out.append(0x09)
        elif e == 0x75:
            var cp = _hex4(src[0:end], p)
            p += 4
            if cp >= 0xD800 and cp <= 0xDBFF:
                # A high surrogate must be followed by an escaped low one.
                if p + 6 > end or src[p] != 0x5C or src[p + 1] != 0x75:
                    raise Error("JSON: unpaired surrogate")
                var low = _hex4(src[0:end], p + 2)
                if low < 0xDC00 or low > 0xDFFF:
                    raise Error("JSON: unpaired surrogate")
                p += 6
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
            elif cp >= 0xDC00 and cp <= 0xDFFF:
                raise Error("JSON: unpaired surrogate")
            _put_utf8(out, cp)
        else:
            raise Error("JSON: invalid escape")
    return String(unsafe_from_utf8=Span(out))


def json_parse_int(raw: StringSpan) raises -> Int:
    """Reads a JSON number as an integer, dropping any fraction.

    Args:
        raw: The number text; surrounding white space is allowed.

    Returns:
        The integer part of the number.

    Raises:
        Error: If the text is not a number, uses an exponent, or is too
            large.
    """
    var src = raw.strip().as_bytes()
    var p = 0
    var negative = False
    if p < len(src) and src[p] == 0x2D:
        negative = True
        p += 1
    if p >= len(src) or src[p] < 0x30 or src[p] > 0x39:
        raise Error("JSON: expected a number")
    var v = 0
    while p < len(src) and src[p] >= 0x30 and src[p] <= 0x39:
        if v > 0x0CCC_CCCC_CCCC_CCCB:
            raise Error("JSON: number too large")
        v = v * 10 + Int(src[p] - 0x30)
        p += 1
    if p < len(src) and src[p] == 0x2E:
        p += 1
        if p >= len(src) or src[p] < 0x30 or src[p] > 0x39:
            raise Error("JSON: malformed number")
        while p < len(src) and src[p] >= 0x30 and src[p] <= 0x39:
            p += 1
    if p != len(src):
        raise Error("JSON: unsupported number format")
    return -v if negative else v
