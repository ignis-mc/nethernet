"""Constant-time helpers for handling secrets."""


def constant_time_eq(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    """Compares two byte spans without an early exit.

    The running time depends only on the lengths, not on where the contents
    differ.

    Args:
        a: The first span.
        b: The second span.

    Returns:
        `True` if both spans have the same length and contents.
    """
    if len(a) != len(b):
        return False
    var diff = UInt8(0)
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def zeroize(mut data: List[UInt8]):
    """Overwrites a buffer with zeros.

    Args:
        data: The buffer to clear.
    """
    for i in range(len(data)):
        data[i] = 0
