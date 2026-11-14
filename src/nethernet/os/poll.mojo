"""Readiness waiting over a small set of descriptors."""

from ._sys.linux import (
    Errno,
    POLLERR,
    POLLHUP,
    POLLIN,
    POLLOUT,
    sys_ppoll,
)


struct PollSet(Movable, Sized):
    """A reusable set of descriptors to wait on with `ppoll(2)`."""

    var _slots: List[Int32]

    def __init__(out self):
        """Creates an empty set."""
        self._slots = List[Int32]()

    def clear(mut self):
        """Removes every descriptor."""
        self._slots.clear()

    def __len__(self) -> Int:
        """Counts the descriptors in the set."""
        return len(self._slots) // 2

    def add(mut self, fd: Int, want_write: Bool = False) -> Int:
        """Adds a descriptor to wait on."""
        var events = Int32(POLLIN)
        if want_write:
            events |= POLLOUT
        self._slots.append(Int32(fd))
        self._slots.append(events)
        return len(self._slots) // 2 - 1

    def wait(mut self, timeout_ms: Int) raises Errno -> Int:
        """Blocks until a descriptor is ready or the timeout passes."""
        for i in range(len(self._slots) // 2):
            self._slots[2 * i + 1] &= 0xFFFF
        return sys_ppoll(Span(self._slots), timeout_ms)

    def _revents(self, index: Int) -> Int32:
        return (self._slots[2 * index + 1] >> 16) & 0xFFFF

    def readable(self, index: Int) -> Bool:
        """Checks whether a descriptor has input (or hung up) after `wait()`."""
        return (self._revents(index) & (POLLIN | POLLHUP | POLLERR)) != 0

    def writable(self, index: Int) -> Bool:
        """Checks whether a descriptor accepts output after `wait()`."""
        return (self._revents(index) & POLLOUT) != 0

    def failed(self, index: Int) -> Bool:
        """Checks whether a descriptor reported an error or hang-up."""
        return (self._revents(index) & (POLLERR | POLLHUP)) != 0


def wait_readable(fd: Int, timeout_ms: Int) raises Errno -> Bool:
    """Waits for one descriptor to become readable."""
    var set = PollSet()
    var index = set.add(fd)
    _ = set.wait(timeout_ms)
    return set.readable(index)
