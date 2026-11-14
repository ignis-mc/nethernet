"""Non-blocking UDP sockets."""

from ._sys.linux import (
    AF_INET,
    EAGAIN,
    Errno,
    SO_BROADCAST,
    SO_REUSEADDR,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_NONBLOCK,
    SOL_SOCKET,
    SockAddrIn,
    check,
    sys_bind,
    sys_close,
    sys_connect,
    sys_getsockname,
    sys_recvfrom,
    sys_sendto,
    sys_setsockopt_int,
    sys_socket,
)
from .addr import SocketAddr


struct UdpSocket(Movable):
    """A non-blocking IPv4 UDP socket that closes itself when destroyed."""

    var _fd: Int

    def __init__(
        out self, bind_addr: SocketAddr, reuse_addr: Bool = False
    ) raises Errno:
        """Creates a socket bound to `bind_addr`."""
        self._fd = sys_socket(
            AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0
        )
        try:
            if reuse_addr:
                sys_setsockopt_int(self._fd, SOL_SOCKET, SO_REUSEADDR, 1)
            var sa = SockAddrIn.from_host(bind_addr.ip, bind_addr.port)
            sys_bind(self._fd, sa)
        except e:
            _ = sys_close(self._fd)
            raise e

    def __deinit__(deinit self):
        """Closes the socket."""
        _ = sys_close(self._fd)

    def fd(self) -> Int:
        """Gets the descriptor, for use with `PollSet`."""
        return self._fd

    def local_addr(self) raises Errno -> SocketAddr:
        """Reads the address the socket is bound to."""
        var sa = SockAddrIn.from_host(0, 0)
        sys_getsockname(self._fd, sa)
        return SocketAddr(sa.ip(), sa.port())

    def set_broadcast(self, enabled: Bool) raises Errno:
        """Allows or forbids sending to broadcast addresses."""
        sys_setsockopt_int(
            self._fd, SOL_SOCKET, SO_BROADCAST, Int32(1 if enabled else 0)
        )

    def send_to(
        self, data: Span[UInt8, _], dest: SocketAddr
    ) raises Errno -> Bool:
        """Sends one datagram."""
        var sa = SockAddrIn.from_host(dest.ip, dest.port)
        var rc = sys_sendto(self._fd, data, sa)
        if rc == -EAGAIN:
            return False
        _ = check(rc)
        return True

    def recv_from(
        self, buf: Span[mut=True, UInt8, _], mut src: SocketAddr
    ) raises Errno -> Int:
        """Receives one datagram if one is waiting."""
        var sa = SockAddrIn.from_host(0, 0)
        var rc = sys_recvfrom(self._fd, buf, sa)
        if rc == -EAGAIN:
            return -1
        _ = check(rc)
        src = SocketAddr(sa.ip(), sa.port())
        return rc


def default_local_ip() raises Errno -> UInt32:
    """Finds the IPv4 address the host uses for outbound traffic.

    Connects a UDP socket towards a public address (no packet is sent) and
    reads back the source address the kernel picked.
    """
    var fd = sys_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)
    var target = SockAddrIn.from_host(0x08080808, 53)
    var rc = sys_connect(fd, target)
    if rc < 0:
        _ = sys_close(fd)
        raise Errno(-rc)
    var local = SockAddrIn.from_host(0, 0)
    try:
        sys_getsockname(fd, local)
    except e:
        _ = sys_close(fd)
        raise e
    _ = sys_close(fd)
    return local.ip()
