"""Cryptographically secure randomness from the kernel."""

from ._sys.linux import Errno, sys_getrandom


def fill_random(buf: Span[mut=True, UInt8, _]) raises Errno:
    """Fills a buffer with random bytes from `getrandom(2)`.

    Args:
        buf: The buffer to fill completely.

    Raises:
        Errno: If the kernel cannot provide randomness.
    """
    var done = 0
    while done < len(buf):
        done += sys_getrandom(buf[done : len(buf)])


def random_bytes(n: Int) raises Errno -> List[UInt8]:
    """Returns `n` random bytes.

    Args:
        n: The number of bytes wanted.

    Returns:
        A list of `n` bytes from the kernel's generator.

    Raises:
        Errno: If the kernel cannot provide randomness.
    """
    var out = List[UInt8](length=n, fill=0)
    fill_random(Span(out))
    return out^


def random_u32() raises Errno -> UInt32:
    """Returns a random 32-bit integer.

    Returns:
        A uniformly random value.

    Raises:
        Errno: If the kernel cannot provide randomness.
    """
    var b = random_bytes(4)
    return (
        (UInt32(b[0]) << 24)
        | (UInt32(b[1]) << 16)
        | (UInt32(b[2]) << 8)
        | UInt32(b[3])
    )


def random_u64() raises Errno -> UInt64:
    """Returns a random 64-bit integer.

    Returns:
        A uniformly random value.

    Raises:
        Errno: If the kernel cannot provide randomness.
    """
    return (UInt64(random_u32()) << 32) | UInt64(random_u32())
