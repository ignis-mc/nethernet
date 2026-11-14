"""CRC-32 (IEEE 802.3) and CRC-32C (Castagnoli) checksums.

STUN FINGERPRINT uses CRC-32; SCTP packets use CRC-32C.
"""

from std.builtin.globals import global_constant


def _make_table(poly: UInt32) -> Array[UInt32, 256]:
    var t = Array[UInt32, 256](fill=0)
    for i in range(256):
        var c = UInt32(i)
        for _ in range(8):
            if (c & 1) != 0:
                c = (c >> 1) ^ poly
            else:
                c = c >> 1
        t[i] = c
    return t^


comptime _CRC32_TABLE = _make_table(0xEDB88320)
comptime _CRC32C_TABLE = _make_table(0x82F63B78)


def crc32_update(crc: UInt32, data: Span[UInt8, _]) -> UInt32:
    """Feeds more bytes into a running CRC-32.

    Start with `0xFFFFFFFF` and invert the final value, or use `crc32()`.
    """
    ref table = global_constant[_CRC32_TABLE]()
    var c = crc
    for b in data:
        c = table[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8)
    return c


def crc32(data: Span[UInt8, _]) -> UInt32:
    """Computes the IEEE CRC-32 of `data`."""
    return ~crc32_update(0xFFFFFFFF, data)


def crc32c_update(crc: UInt32, data: Span[UInt8, _]) -> UInt32:
    """Feeds more bytes into a running CRC-32C.

    Start with `0xFFFFFFFF` and invert the final value, or use `crc32c()`.
    """
    ref table = global_constant[_CRC32C_TABLE]()
    var c = crc
    for b in data:
        c = table[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8)
    return c


def crc32c(data: Span[UInt8, _]) -> UInt32:
    """Computes the CRC-32C (Castagnoli) of `data`."""
    return ~crc32c_update(0xFFFFFFFF, data)
