"""Raw Linux system calls, issued from Mojo with no libc.

The only unsafe primitive is `syscall6()`: one `syscall` (x86-64) or `svc #0`
(aarch64) instruction emitted through `std.sys.inlined_assembly`. Results
follow the kernel convention: a non-negative value on success, `-errno` on
failure.

Lifetime rule: a pointer converted to `Int` no longer carries its origin, so
the compiler may end the owner's lifetime before the system call runs and
drop the stores into it. Every wrapper here therefore borrows its buffers
(`Span`, `mut` arguments) so the caller keeps them alive across the call, and
locals are touched again (`_ = x`) after the call.
"""

from std.bit import byte_swap
from std.sys import inlined_assembly
from std.sys.info import CompilationTarget


@inline(.always)
def syscall6(
    nr: Int, a0: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int
) -> Int:
    """Executes one Linux system call.

    Args:
        nr: The system call number for the target architecture.
        a0: The first argument.
        a1: The second argument.
        a2: The third argument.
        a3: The fourth argument.
        a4: The fifth argument.
        a5: The sixth argument.

    Returns:
        The raw kernel result: non-negative on success, `-errno` on failure.
    """
    comptime if CompilationTarget.is_x86():
        # nr in rax; args in rdi rsi rdx r10 r8 r9; result in rax. The
        # instruction clobbers rcx and r11.
        return inlined_assembly[
            "syscall",
            Int,
            constraints="={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}",
            has_side_effect=True,
        ](nr, a0, a1, a2, a3, a4, a5)
    else:
        # aarch64: nr in x8; args in x0..x5; result in x0.
        return inlined_assembly[
            "svc #0",
            Int,
            constraints="={x0},{x8},{x0},{x1},{x2},{x3},{x4},{x5},~{memory}",
            has_side_effect=True,
        ](nr, a0, a1, a2, a3, a4, a5)


comptime _X86 = CompilationTarget.is_x86()

comptime SYS_READ = 0 if _X86 else 63
comptime SYS_WRITE = 1 if _X86 else 64
comptime SYS_CLOSE = 3 if _X86 else 57
comptime SYS_SOCKET = 41 if _X86 else 198
comptime SYS_CONNECT = 42 if _X86 else 203
comptime SYS_SENDTO = 44 if _X86 else 206
comptime SYS_RECVFROM = 45 if _X86 else 207
comptime SYS_SHUTDOWN = 48 if _X86 else 210
comptime SYS_BIND = 49 if _X86 else 200
comptime SYS_LISTEN = 50 if _X86 else 201
comptime SYS_GETSOCKNAME = 51 if _X86 else 204
comptime SYS_SETSOCKOPT = 54 if _X86 else 208
comptime SYS_GETSOCKOPT = 55 if _X86 else 209
comptime SYS_CLOCK_GETTIME = 228 if _X86 else 113
comptime SYS_PPOLL = 271 if _X86 else 73
comptime SYS_ACCEPT4 = 288 if _X86 else 242
comptime SYS_GETRANDOM = 318 if _X86 else 278

comptime AF_INET = 2
comptime SOCK_STREAM = 1
comptime SOCK_DGRAM = 2
comptime SOCK_NONBLOCK = 0o4000
comptime SOCK_CLOEXEC = 0o2000000
comptime SOL_SOCKET = 1
comptime SO_REUSEADDR = 2
comptime SO_ERROR = 4
comptime SO_BROADCAST = 6
comptime IPPROTO_TCP = 6
comptime TCP_NODELAY = 1
comptime MSG_NOSIGNAL = 0x4000
comptime SHUT_RDWR = 2
comptime CLOCK_REALTIME = 0
comptime CLOCK_MONOTONIC = 1
comptime POLLIN = 0x001
comptime POLLOUT = 0x004
comptime POLLERR = 0x008
comptime POLLHUP = 0x010

comptime EINTR = 4
comptime EAGAIN = 11
comptime EINPROGRESS = 115
comptime ECONNREFUSED = 111


@fieldwise_init
struct Errno(Equatable, ImplicitlyCopyable, Writable):
    """A failed system call, identified by its positive Linux errno value."""

    var code: Int
    """The errno value, for example 11 for `EAGAIN`."""

    def write_to(self, mut writer: Some[Writer]):
        """Writes a short description such as `errno 11`.

        Args:
            writer: The destination.
        """
        writer.write("errno ", self.code)


def check(rc: Int) raises Errno -> Int:
    """Converts a raw system-call result into a value or an `Errno`.

    Args:
        rc: The raw result from `syscall6()`.

    Returns:
        `rc` when it is non-negative.

    Raises:
        Errno: If `rc` is negative.
    """
    if rc < 0:
        raise Errno(-rc)
    return rc


@fieldwise_init
struct SockAddrIn(Copyable):
    """The kernel's `struct sockaddr_in`: 16 bytes, network byte order."""

    var family: UInt16
    """The address family, always `AF_INET`."""
    var port_be: UInt16
    """The port in network byte order."""
    var addr_be: UInt32
    """The IPv4 address in network byte order."""
    var zero: UInt64
    """Padding required by the kernel layout."""

    @staticmethod
    def from_host(ip: UInt32, port: UInt16) -> Self:
        """Builds an address from host-order values.

        Args:
            ip: The IPv4 address with the first octet in the top byte.
            port: The port number.

        Returns:
            The kernel-layout address.
        """
        return Self(
            family=AF_INET,
            port_be=byte_swap(port),
            addr_be=byte_swap(ip),
            zero=0,
        )

    def ip(self) -> UInt32:
        """Gets the IPv4 address in host order.

        Returns:
            The address with the first octet in the top byte.
        """
        return byte_swap(self.addr_be)

    def port(self) -> UInt16:
        """Gets the port in host order.

        Returns:
            The port number.
        """
        return byte_swap(self.port_be)


@fieldwise_init
struct Timespec(Copyable):
    """The kernel's 64-bit `struct timespec`."""

    var sec: Int64
    """Whole seconds."""
    var nsec: Int64
    """Nanoseconds past the second."""


def sys_close(fd: Int) -> Int:
    """Closes a file descriptor.

    Args:
        fd: The descriptor to close.

    Returns:
        The raw kernel result.
    """
    return syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0)


def sys_socket(domain: Int, type: Int, protocol: Int) raises Errno -> Int:
    """Creates a socket.

    Args:
        domain: The address family.
        type: The socket type, optionally OR-ed with `SOCK_NONBLOCK` and
            `SOCK_CLOEXEC`.
        protocol: The protocol, or 0 for the default.

    Returns:
        The new descriptor.

    Raises:
        Errno: If the kernel refuses.
    """
    return check(syscall6(SYS_SOCKET, domain, type, protocol, 0, 0, 0))


def sys_setsockopt_int(
    fd: Int, level: Int, name: Int, value: Int32
) raises Errno:
    """Sets an integer socket option.

    Args:
        fd: The socket.
        level: The option level.
        name: The option name.
        value: The option value.

    Raises:
        Errno: If the kernel refuses.
    """
    var v = value
    var rc = syscall6(SYS_SETSOCKOPT, fd, level, name, Int(Pointer(to=v)), 4, 0)
    _ = v
    _ = check(rc)


def sys_getsockopt_int(fd: Int, level: Int, name: Int) raises Errno -> Int32:
    """Reads an integer socket option.

    Args:
        fd: The socket.
        level: The option level.
        name: The option name.

    Returns:
        The option value.

    Raises:
        Errno: If the kernel refuses.
    """
    var v = Int32(0)
    var vlen = Int32(4)
    var rc = syscall6(
        SYS_GETSOCKOPT,
        fd,
        level,
        name,
        Int(Pointer(to=v)),
        Int(Pointer(to=vlen)),
        0,
    )
    _ = vlen
    _ = check(rc)
    return v


def sys_bind(fd: Int, mut addr: SockAddrIn) raises Errno:
    """Binds a socket to a local address.

    Args:
        fd: The socket.
        addr: The local address.

    Raises:
        Errno: If the kernel refuses.
    """
    _ = check(syscall6(SYS_BIND, fd, Int(Pointer(to=addr)), 16, 0, 0, 0))


def sys_connect(fd: Int, mut addr: SockAddrIn) -> Int:
    """Connects a socket, returning the raw result.

    Args:
        fd: The socket.
        addr: The peer address.

    Returns:
        0 on success, or `-errno` (for example `-EINPROGRESS`).
    """
    return syscall6(SYS_CONNECT, fd, Int(Pointer(to=addr)), 16, 0, 0, 0)


def sys_listen(fd: Int, backlog: Int) raises Errno:
    """Marks a socket as accepting connections.

    Args:
        fd: The socket.
        backlog: The pending-connection queue length.

    Raises:
        Errno: If the kernel refuses.
    """
    _ = check(syscall6(SYS_LISTEN, fd, backlog, 0, 0, 0, 0))


def sys_accept4(fd: Int, mut peer: SockAddrIn, flags: Int) -> Int:
    """Accepts a pending connection, returning the raw result.

    Args:
        fd: The listening socket.
        peer: Receives the peer address.
        flags: `SOCK_NONBLOCK` and/or `SOCK_CLOEXEC` for the new socket.

    Returns:
        The new descriptor, or `-errno` (for example `-EAGAIN`).
    """
    var alen = Int32(16)
    var rc = syscall6(
        SYS_ACCEPT4,
        fd,
        Int(Pointer(to=peer)),
        Int(Pointer(to=alen)),
        flags,
        0,
        0,
    )
    _ = alen
    return rc


def sys_getsockname(fd: Int, mut addr: SockAddrIn) raises Errno:
    """Reads the local address of a socket.

    Args:
        fd: The socket.
        addr: Receives the local address.

    Raises:
        Errno: If the kernel refuses.
    """
    var alen = Int32(16)
    var rc = syscall6(
        SYS_GETSOCKNAME,
        fd,
        Int(Pointer(to=addr)),
        Int(Pointer(to=alen)),
        0,
        0,
        0,
    )
    _ = alen
    _ = check(rc)


def sys_sendto(fd: Int, buf: Span[UInt8, _], mut to: SockAddrIn) -> Int:
    """Sends a datagram to an address, returning the raw result.

    Args:
        fd: The socket.
        buf: The payload.
        to: The destination.

    Returns:
        The number of bytes sent, or `-errno`.
    """
    return syscall6(
        SYS_SENDTO,
        fd,
        Int(buf.unsafe_ptr()),
        len(buf),
        MSG_NOSIGNAL,
        Int(Pointer(to=to)),
        16,
    )


def sys_send(fd: Int, buf: Span[UInt8, _]) -> Int:
    """Sends bytes on a connected socket, returning the raw result.

    Args:
        fd: The socket.
        buf: The bytes to send.

    Returns:
        The number of bytes sent, or `-errno`.
    """
    return syscall6(
        SYS_SENDTO, fd, Int(buf.unsafe_ptr()), len(buf), MSG_NOSIGNAL, 0, 0
    )


def sys_recvfrom(
    fd: Int, buf: Span[mut=True, UInt8, _], mut from_addr: SockAddrIn
) -> Int:
    """Receives a datagram and its source, returning the raw result.

    Args:
        fd: The socket.
        buf: Receives the payload.
        from_addr: Receives the source address.

    Returns:
        The number of bytes received, or `-errno` (for example `-EAGAIN`).
    """
    var alen = Int32(16)
    var rc = syscall6(
        SYS_RECVFROM,
        fd,
        Int(buf.unsafe_ptr()),
        len(buf),
        0,
        Int(Pointer(to=from_addr)),
        Int(Pointer(to=alen)),
    )
    _ = alen
    return rc


def sys_recv(fd: Int, buf: Span[mut=True, UInt8, _]) -> Int:
    """Receives bytes from a connected socket, returning the raw result.

    Args:
        fd: The socket.
        buf: Receives the bytes.

    Returns:
        The number of bytes received (0 at end of stream), or `-errno`.
    """
    return syscall6(SYS_RECVFROM, fd, Int(buf.unsafe_ptr()), len(buf), 0, 0, 0)


def sys_shutdown(fd: Int, how: Int) -> Int:
    """Shuts down part of a connection.

    Args:
        fd: The socket.
        how: `SHUT_RDWR` or one of the other shutdown modes.

    Returns:
        The raw kernel result.
    """
    return syscall6(SYS_SHUTDOWN, fd, how, 0, 0, 0, 0)


def sys_clock_ns(clock: Int) -> Int:
    """Reads a kernel clock.

    Args:
        clock: `CLOCK_MONOTONIC` or `CLOCK_REALTIME`.

    Returns:
        The clock value in nanoseconds.
    """
    var ts = Timespec(0, 0)
    var rc = syscall6(SYS_CLOCK_GETTIME, clock, Int(Pointer(to=ts)), 0, 0, 0, 0)
    _ = rc
    return Int(ts.sec) * 1_000_000_000 + Int(ts.nsec)


def sys_getrandom(buf: Span[mut=True, UInt8, _]) raises Errno -> Int:
    """Fills a buffer from the kernel's random number generator.

    Args:
        buf: Receives the random bytes.

    Returns:
        The number of bytes written, which may be fewer than requested.

    Raises:
        Errno: If the kernel refuses.
    """
    return check(
        syscall6(SYS_GETRANDOM, Int(buf.unsafe_ptr()), len(buf), 0, 0, 0, 0)
    )


def sys_ppoll(
    pollfds: Span[mut=True, Int32, _], timeout_ms: Int
) raises Errno -> Int:
    """Waits for readiness on a set of descriptors.

    Each descriptor occupies two `Int32` slots laid out as the kernel's
    `struct pollfd`: slot 0 is the descriptor; slot 1 holds the requested
    events in its low 16 bits and receives the returned events in its high
    16 bits.

    Args:
        pollfds: The `pollfd` records, two slots per descriptor.
        timeout_ms: The longest time to wait; negative waits forever.

    Returns:
        The number of descriptors with events, 0 on timeout. An interrupted
        wait also returns 0.

    Raises:
        Errno: If the kernel refuses.
    """
    var ts = Timespec(
        Int64(timeout_ms // 1000), Int64((timeout_ms % 1000) * 1_000_000)
    )
    var ts_ptr = 0
    if timeout_ms >= 0:
        ts_ptr = Int(Pointer(to=ts))
    var rc = syscall6(
        SYS_PPOLL, Int(pollfds.unsafe_ptr()), len(pollfds) // 2, ts_ptr, 0, 8, 0
    )
    _ = ts
    if rc == -EINTR:
        return 0
    return check(rc)
