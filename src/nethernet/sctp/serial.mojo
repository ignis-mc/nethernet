"""Serial number arithmetic (RFC 1982) for TSNs and stream sequence numbers.

Sequence numbers wrap around, so "less than" means "at most half the number
space behind".
"""


def tsn_lt(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` comes before TSN `b`."""
    return a != b and (b - a) < 0x80000000


def tsn_le(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` is `b` or comes before it."""
    return (b - a) < 0x80000000


def tsn_gt(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` comes after TSN `b`."""
    return tsn_lt(b, a)


def tsn_ge(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` is `b` or comes after it."""
    return tsn_le(b, a)


def ssn_lt(a: UInt16, b: UInt16) -> Bool:
    """Checks whether stream sequence number `a` comes before `b`."""
    return a != b and (b - a) < 0x8000


def ssn_le(a: UInt16, b: UInt16) -> Bool:
    """Checks whether stream sequence number `a` is `b` or comes before it."""
    return (b - a) < 0x8000
