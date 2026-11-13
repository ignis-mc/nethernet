"""Clocks."""

from ._sys.linux import CLOCK_MONOTONIC, CLOCK_REALTIME, sys_clock_ns


def monotonic_ns() -> Int:
    """Reads the monotonic clock.

    Returns:
        Nanoseconds since an arbitrary fixed point; never goes backwards.
    """
    return sys_clock_ns(CLOCK_MONOTONIC)


def monotonic_ms() -> Int:
    """Reads the monotonic clock in milliseconds.

    This is the `now_ms` value the protocol state machines expect.

    Returns:
        Milliseconds since an arbitrary fixed point; never goes backwards.
    """
    return sys_clock_ns(CLOCK_MONOTONIC) // 1_000_000


def unix_time_s() -> Int:
    """Reads the wall clock.

    Returns:
        Seconds since 1970-01-01T00:00:00Z.
    """
    return sys_clock_ns(CLOCK_REALTIME) // 1_000_000_000
