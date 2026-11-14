"""Constant-time helpers for handling secrets."""


def constant_time_eq(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    """Compares two byte spans without an early exit.

    The running time depends only on the lengths, not on where the contents
    differ.
    """
    if len(a) != len(b):
        return False
    var diff = UInt8(0)
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def zeroize(mut data: List[UInt8]):
    """Overwrites a buffer with zeros."""
    for i in range(len(data)):
        data[i] = 0
