"""Clocks."""

from ._sys.linux import CLOCK_MONOTONIC, CLOCK_REALTIME, sys_clock_ns


def monotonic_ns() -> Int:
    """Reads the monotonic clock."""
    return sys_clock_ns(CLOCK_MONOTONIC)


def monotonic_ms() -> Int:
    """Reads the monotonic clock in milliseconds.

    This is the `now_ms` value the protocol state machines expect.
    """
    return sys_clock_ns(CLOCK_MONOTONIC) // 1_000_000


def unix_time_s() -> Int:
    """Reads the wall clock."""
    return sys_clock_ns(CLOCK_REALTIME) // 1_000_000_000
