"""Serial number arithmetic (RFC 1982) for TSNs and stream sequence numbers.

Sequence numbers wrap around, so "less than" means "at most half the number
space behind".
"""


def tsn_lt(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` comes before TSN `b`.

    Args:
        a: The first TSN.
        b: The second TSN.

    Returns:
        `True` if `a` precedes `b` in serial number order.
    """
    return a != b and (b - a) < 0x80000000


def tsn_le(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` is `b` or comes before it.

    Args:
        a: The first TSN.
        b: The second TSN.

    Returns:
        `True` if `a` equals or precedes `b` in serial number order.
    """
    return (b - a) < 0x80000000


def tsn_gt(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` comes after TSN `b`.

    Args:
        a: The first TSN.
        b: The second TSN.

    Returns:
        `True` if `a` follows `b` in serial number order.
    """
    return tsn_lt(b, a)


def tsn_ge(a: UInt32, b: UInt32) -> Bool:
    """Checks whether TSN `a` is `b` or comes after it.

    Args:
        a: The first TSN.
        b: The second TSN.

    Returns:
        `True` if `a` equals or follows `b` in serial number order.
    """
    return tsn_le(b, a)


def ssn_lt(a: UInt16, b: UInt16) -> Bool:
    """Checks whether stream sequence number `a` comes before `b`.

    Args:
        a: The first sequence number.
        b: The second sequence number.

    Returns:
        `True` if `a` precedes `b` in serial number order.
    """
    return a != b and (b - a) < 0x8000


def ssn_le(a: UInt16, b: UInt16) -> Bool:
    """Checks whether stream sequence number `a` is `b` or comes before it.

    Args:
        a: The first sequence number.
        b: The second sequence number.

    Returns:
        `True` if `a` equals or precedes `b` in serial number order.
    """
    return (b - a) < 0x8000
