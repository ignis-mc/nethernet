"""DER encoding of ECDSA signatures, as carried in TLS and X.509.

Converts between the raw fixed-width form `r || s` and

```text
ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
```

Signatures are public, so nothing here is constant-time.
"""


def _put_length(mut out: List[UInt8], length: Int):
    # Definite-form DER length, minimal.
    if length < 0x80:
        out.append(UInt8(length))
    elif length < 0x100:
        out.append(0x81)
        out.append(UInt8(length))
    else:
        out.append(0x82)
        out.append(UInt8((length >> 8) & 0xFF))
        out.append(UInt8(length & 0xFF))


def _integer_content_len(value: Span[UInt8, _]) -> Int:
    # Content length of the minimal non-negative INTEGER holding `value`.
    var start = 0
    while start < len(value) and value[start] == 0:
        start += 1
    if start == len(value):
        return 1
    var size = len(value) - start
    if (value[start] & 0x80) != 0:
        size += 1
    return size


def _integer_len(value: Span[UInt8, _]) -> Int:
    # Total encoded length of the INTEGER: tag, length field and content.
    var content = _integer_content_len(value)
    if content < 0x80:
        return 2 + content
    if content < 0x100:
        return 3 + content
    return 4 + content


def _put_integer(mut out: List[UInt8], value: Span[UInt8, _]):
    out.append(0x02)
    _put_length(out, _integer_content_len(value))
    var start = 0
    while start < len(value) and value[start] == 0:
        start += 1
    if start == len(value):
        out.append(0x00)
        return
    if (value[start] & 0x80) != 0:
        out.append(0x00)
    for i in range(start, len(value)):
        out.append(value[i])


def ecdsa_signature_to_der(raw: Span[UInt8, _]) -> List[UInt8]:
    """Encodes a raw ECDSA signature as a DER `ECDSA-Sig-Value`.

    Each integer gets the minimal encoding: leading zero bytes are dropped
    and a single `0x00` is put back when the top bit would otherwise mark
    the value as negative.
    """
    var half = len(raw) // 2
    var r = raw[0:half]
    var s = raw[half : len(raw)]
    var content = _integer_len(r) + _integer_len(s)
    var out = List[UInt8](capacity=content + 4)
    out.append(0x30)
    _put_length(out, content)
    _put_integer(out, r)
    _put_integer(out, s)
    return out^


def _read_length(der: Span[UInt8, _], mut pos: Int, end: Int) raises -> Int:
    # Reads a definite-form length and rejects every non-minimal encoding.
    if pos >= end:
        raise Error("DER signature is truncated")
    var first = der[pos]
    pos += 1
    if first < 0x80:
        return Int(first)
    if first == 0x81:
        if pos + 1 > end:
            raise Error("DER signature is truncated")
        var value = Int(der[pos])
        pos += 1
        if value < 0x80:
            raise Error("DER length is not minimal")
        return value
    if first == 0x82:
        if pos + 2 > end:
            raise Error("DER signature is truncated")
        var value = (Int(der[pos]) << 8) | Int(der[pos + 1])
        pos += 2
        if value < 0x100:
            raise Error("DER length is not minimal")
        return value
    raise Error("DER length form is not supported")


def _read_integer(
    der: Span[UInt8, _],
    mut pos: Int,
    end: Int,
    scalar_len: Int,
    mut out: List[UInt8],
) raises:
    # Reads one non-negative INTEGER and appends it left-padded.
    if pos >= end or der[pos] != 0x02:
        raise Error("DER signature: expected INTEGER")
    pos += 1
    var length = _read_length(der, pos, end)
    if length == 0 or length > end - pos:
        raise Error("DER signature: bad INTEGER length")
    if (der[pos] & 0x80) != 0:
        raise Error("DER signature: negative INTEGER")
    var start = pos
    if der[pos] == 0x00 and length > 1:
        if (der[pos + 1] & 0x80) == 0:
            raise Error("DER signature: INTEGER is not minimal")
        start += 1
    pos += length
    var size = pos - start
    if size > scalar_len:
        raise Error("DER signature: INTEGER is too large")
    for _ in range(scalar_len - size):
        out.append(0x00)
    for i in range(start, pos):
        out.append(der[i])


def ecdsa_signature_from_der(
    der: Span[UInt8, _], scalar_len: Int
) raises -> List[UInt8]:
    """Decodes a DER `ECDSA-Sig-Value` into a raw ECDSA signature.

    The parser is strict: lengths and integers must be minimally encoded,
    integers must be non-negative, and nothing may follow the sequence or
    its second integer. It does not check that `r` and `s` are in range for
    a curve; signature verification does.
    """
    if scalar_len <= 0:
        raise Error("DER signature: scalar length must be positive")
    var end = len(der)
    if end == 0 or der[0] != 0x30:
        raise Error("DER signature: expected SEQUENCE")
    var pos = 1
    var length = _read_length(der, pos, end)
    if length != end - pos:
        raise Error("DER signature: SEQUENCE length does not match")
    var out = List[UInt8](capacity=2 * scalar_len)
    _read_integer(der, pos, end, scalar_len, out)
    _read_integer(der, pos, end, scalar_len, out)
    if pos != end:
        raise Error("DER signature: trailing bytes in SEQUENCE")
    return out^
