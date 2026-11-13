"""Non-blocking TCP sockets, used by the HTTP signaling endpoint."""

from ._sys.linux import (
    AF_INET,
    EAGAIN,
    EINPROGRESS,
    Errno,
    IPPROTO_TCP,
    SHUT_RDWR,
    SO_ERROR,
    SO_REUSEADDR,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
    SOL_SOCKET,
    SockAddrIn,
    TCP_NODELAY,
    check,
    sys_accept4,
    sys_bind,
    sys_close,
    sys_connect,
    sys_getsockname,
    sys_getsockopt_int,
    sys_listen,
    sys_recv,
    sys_send,
    sys_setsockopt_int,
    sys_shutdown,
    sys_socket,
)
from .addr import SocketAddr
from .poll import PollSet


struct TcpStream(Movable):
    """A non-blocking TCP connection that closes itself when destroyed."""

    var _fd: Int
    var _peer: SocketAddr

    def __init__(out self, *, fd: Int, peer: SocketAddr):
        """Wraps an already connected descriptor.

        Args:
            fd: The connected, non-blocking socket.
            peer: The remote address.
        """
        self._fd = fd
        self._peer = peer

    def __deinit__(deinit self):
        """Shuts down and closes the connection."""
        _ = sys_shutdown(self._fd, SHUT_RDWR)
        _ = sys_close(self._fd)

    @staticmethod
    def connect(addr: SocketAddr, timeout_ms: Int) raises -> TcpStream:
        """Opens a connection, waiting up to `timeout_ms` for it.

        Args:
            addr: The remote address.
            timeout_ms: The longest time to wait for the handshake.

        Returns:
            The connected stream.

        Raises:
            Error: If the connection fails or times out.
        """
        var fd = sys_socket(
            AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0
        )
        var sa = SockAddrIn.from_host(addr.ip, addr.port)
        var rc = sys_connect(fd, sa)
        if rc < 0 and rc != -EINPROGRESS:
            _ = sys_close(fd)
            raise Error(t"connect to {addr} failed: errno {-rc}")
        if rc == -EINPROGRESS:
            var set = PollSet()
            var index = set.add(fd, want_write=True)
            _ = set.wait(timeout_ms)
            if not set.writable(index) and not set.failed(index):
                _ = sys_close(fd)
                raise Error(t"connect to {addr} timed out")
            var so_error = sys_getsockopt_int(fd, SOL_SOCKET, SO_ERROR)
            if so_error != 0:
                _ = sys_close(fd)
                raise Error(t"connect to {addr} failed: errno {so_error}")
        try:
            sys_setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1)
        except:
            pass
        return TcpStream(fd=fd, peer=addr)

    def fd(self) -> Int:
        """Gets the descriptor, for use with `PollSet`.

        Returns:
            The file descriptor.
        """
        return self._fd

    def peer_addr(self) -> SocketAddr:
        """Gets the remote address.

        Returns:
            The address of the other end.
        """
        return self._peer

    def read(self, buf: Span[mut=True, UInt8, _]) raises Errno -> Int:
        """Reads whatever bytes are available.

        Args:
            buf: Receives the bytes.

        Returns:
            The number of bytes read, 0 at end of stream, or -1 if nothing
            is available yet.

        Raises:
            Errno: If the connection failed.
        """
        var rc = sys_recv(self._fd, buf)
        if rc == -EAGAIN:
            return -1
        return check(rc)

    def write(self, data: Span[UInt8, _]) raises Errno -> Int:
        """Writes as many bytes as the socket accepts right now.

        Args:
            data: The bytes to send.

        Returns:
            The number of bytes accepted, which may be 0.

        Raises:
            Errno: If the connection failed.
        """
        var rc = sys_send(self._fd, data)
        if rc == -EAGAIN:
            return 0
        return check(rc)

    def write_all(self, data: Span[UInt8, _], timeout_ms: Int) raises:
        """Writes every byte, waiting for the socket when it is full.

        Args:
            data: The bytes to send.
            timeout_ms: The longest time to wait each time the socket is full.

        Raises:
            Error: If the connection fails or stays full past the timeout.
        """
        var sent = 0
        while sent < len(data):
            var n = self.write(data[sent : len(data)])
            sent += n
            if n == 0:
                var set = PollSet()
                var index = set.add(self._fd, want_write=True)
                _ = set.wait(timeout_ms)
                if not set.writable(index):
                    raise Error("tcp write timed out")


struct TcpListener(Movable):
    """A non-blocking listening TCP socket."""

    var _fd: Int

    def __init__(
        out self, bind_addr: SocketAddr, backlog: Int = 64
    ) raises Errno:
        """Creates a listener bound to `bind_addr`.

        Args:
            bind_addr: The local address; port 0 picks a free port.
            backlog: The pending-connection queue length.

        Raises:
            Errno: If the socket cannot be created, bound or listened on.
        """
        self._fd = sys_socket(
            AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0
        )
        try:
            sys_setsockopt_int(self._fd, SOL_SOCKET, SO_REUSEADDR, 1)
            var sa = SockAddrIn.from_host(bind_addr.ip, bind_addr.port)
            sys_bind(self._fd, sa)
            sys_listen(self._fd, backlog)
        except e:
            _ = sys_close(self._fd)
            raise e

    def __deinit__(deinit self):
        """Closes the listener."""
        _ = sys_close(self._fd)

    def fd(self) -> Int:
        """Gets the descriptor, for use with `PollSet`.

        Returns:
            The file descriptor.
        """
        return self._fd

    def local_addr(self) raises Errno -> SocketAddr:
        """Reads the address the listener is bound to.

        Returns:
            The local address, with the kernel-assigned port if 0 was asked.

        Raises:
            Errno: If the kernel refuses.
        """
        var sa = SockAddrIn.from_host(0, 0)
        sys_getsockname(self._fd, sa)
        return SocketAddr(sa.ip(), sa.port())

    def accept(self) raises Errno -> Optional[TcpStream]:
        """Accepts one pending connection if there is one.

        Returns:
            The new connection, or `None` if none is pending.

        Raises:
            Errno: If the kernel reports an error other than "would block".
        """
        var sa = SockAddrIn.from_host(0, 0)
        var rc = sys_accept4(self._fd, sa, SOCK_NONBLOCK | SOCK_CLOEXEC)
        if rc == -EAGAIN:
            return None
        var fd = check(rc)
        try:
            sys_setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1)
        except:
            pass
        return TcpStream(fd=fd, peer=SocketAddr(sa.ip(), sa.port()))
