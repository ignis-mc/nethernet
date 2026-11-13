"""The LAN discovery endpoint: announces a world, finds worlds, carries signals."""

from ..os._sys.linux import Errno
from ..os.addr import SocketAddr
from ..os.random import random_u64
from ..os.udp import UdpSocket
from ..signaling.signal import Signal, Signaling, parse_signal
from .packet import (
    DISCOVERY_PORT,
    PACKET_MESSAGE,
    PACKET_REQUEST,
    PACKET_RESPONSE,
    DiscoveryPacket,
    marshal_packet,
    unmarshal_packet,
)
from .server_data import ServerData

comptime BROADCAST_INTERVAL_MS = 2000
"""How often a client-side listener broadcasts a request."""
comptime ADDRESS_LIFETIME_MS = 60000
"""How long a learned peer address is remembered without traffic."""
comptime RESPONSE_LIFETIME_MS = 5000
"""How long a world stays in `responses()` after its last response."""

comptime _MAX_PEERS = 1024
comptime _MAX_QUEUED_SIGNALS = 1024


@fieldwise_init
struct _Peer(Copyable):
    var addr: SocketAddr
    var seen_ms: Int


@fieldwise_init
struct DiscoveredServer(Copyable):
    """A world that answered a discovery request recently."""

    var network_id: UInt64
    """The network ID to dial."""
    var addr: SocketAddr
    """The address the response came from."""
    var data: List[UInt8]
    """The encoded `ServerData`; decode with `ServerData.decode()`."""
    var seen_ms: Int
    """When the latest response arrived, in monotonic milliseconds."""


struct DiscoveryListener(Signaling):
    """A UDP endpoint speaking the LAN discovery protocol.

    A host binds port 7551, calls `set_server_data()` and answers requests.
    A client binds any other port, broadcasts requests every two seconds and
    reads `responses()`. Either can then exchange signals with peers whose
    address it has learned.
    """

    var _socket: UdpSocket
    var _network_id: UInt64
    var _broadcast: Optional[SocketAddr]
    var _server_data: List[UInt8]
    var _peers: Dict[UInt64, _Peer]
    var _responses: Dict[UInt64, DiscoveredServer]
    var _signals: List[Signal]
    var _next_broadcast_ms: Int
    var _buf: List[UInt8]

    def __init__(
        out self,
        bind_addr: SocketAddr,
        network_id: UInt64 = 0,
        broadcast: Optional[SocketAddr] = None,
    ) raises Errno:
        """Binds the discovery socket.

        Args:
            bind_addr: The local address. Hosts use port 7551.
            network_id: This end's network ID; 0 picks a random one.
            broadcast: Where to send requests. By default a listener bound to
                port 7551 does not broadcast, and any other listener
                broadcasts to `255.255.255.255:7551`.

        Raises:
            Errno: If the socket cannot be created or bound.
        """
        self._socket = UdpSocket(bind_addr, reuse_addr=True)
        self._socket.set_broadcast(True)
        self._network_id = network_id
        if self._network_id == 0:
            self._network_id = random_u64()
        self._broadcast = broadcast
        if (
            broadcast is None
            and self._socket.local_addr().port != DISCOVERY_PORT
        ):
            self._broadcast = SocketAddr.v4(255, 255, 255, 255, DISCOVERY_PORT)
        self._server_data = List[UInt8]()
        self._peers = Dict[UInt64, _Peer]()
        self._responses = Dict[UInt64, DiscoveredServer]()
        self._signals = List[Signal]()
        self._next_broadcast_ms = 0
        self._buf = List[UInt8](length=65536, fill=0)

    def local_addr(self) raises Errno -> SocketAddr:
        """Reads the bound address.

        Returns:
            The local address of the discovery socket.

        Raises:
            Errno: If the kernel refuses.
        """
        return self._socket.local_addr()

    def id(self) -> UInt64:
        """Gets the numeric network ID.

        Returns:
            The local network ID.
        """
        return self._network_id

    def disable_broadcast(mut self):
        """Stops this listener from broadcasting discovery requests."""
        self._broadcast = None

    def set_server_data(mut self, data: ServerData):
        """Sets the world description sent in response to requests.

        Args:
            data: The description to announce.
        """
        self._server_data = data.encode()

    def responses(self) -> List[DiscoveredServer]:
        """Lists the worlds that answered recently.

        Returns:
            One entry per network ID seen within `RESPONSE_LIFETIME_MS` as of
            the last `service()` call.
        """
        var out = List[DiscoveredServer]()
        for entry in self._responses.items():
            out.append(entry.value.copy())
        return out^

    def add_peer(mut self, network_id: UInt64, addr: SocketAddr, now_ms: Int):
        """Records where a network ID can be reached.

        Addresses are normally learned from responses and messages; this is
        for callers that know the address by other means.

        Args:
            network_id: The peer's network ID.
            addr: The peer's discovery address.
            now_ms: The current monotonic time in milliseconds.
        """
        self._peers[network_id] = _Peer(addr, now_ms)

    # ===------------------------------------------------------------------=== #
    # Signaling
    # ===------------------------------------------------------------------=== #

    def network_id(self) -> String:
        """Gets the network ID other peers use to reach this end.

        Returns:
            The local network ID in decimal.
        """
        return String(self._network_id)

    def poll_fd(self) -> Int:
        """Gets the discovery socket's descriptor.

        Returns:
            The file descriptor.
        """
        return self._socket.fd()

    def trickle(self) -> Bool:
        """Says that candidates are signaled individually on the LAN.

        Returns:
            `True`.
        """
        return True

    def send_signal(mut self, signal: Signal) raises:
        """Sends a signal to a peer whose address is known.

        Args:
            signal: The signal; `network_id` is the recipient in decimal.

        Raises:
            Error: If the network ID is not a number or no address is known
                for it.
        """
        var recipient = UInt64(0)
        var digits = signal.network_id.as_bytes()
        if len(digits) == 0 or len(digits) > 20:
            raise Error("discovery: network ID is not a number")
        for c in digits:
            if c < 0x30 or c > 0x39:
                raise Error("discovery: network ID is not a number")
            recipient = recipient * 10 + UInt64(c - 0x30)
        if recipient not in self._peers:
            raise Error(t"discovery: no address for network ID {recipient}")
        var addr = self._peers[recipient].addr
        var pk = DiscoveryPacket.message(
            self._network_id, recipient, signal.encode()
        )
        var datagram = marshal_packet(pk)
        _ = self._socket.send_to(Span(datagram), addr)

    def poll_signal(mut self) -> Optional[Signal]:
        """Takes the next received signal.

        Returns:
            A signal whose `network_id` is the sender in decimal, or `None`.
        """
        if len(self._signals) == 0:
            return None
        return self._signals.pop(0)

    def service(mut self, now_ms: Int) raises:
        """Reads pending datagrams, answers requests and broadcasts.

        Args:
            now_ms: The current monotonic time in milliseconds.

        Raises:
            Error: If the socket fails.
        """
        if case .Some(target) = self._broadcast:
            if now_ms >= self._next_broadcast_ms:
                self._next_broadcast_ms = now_ms + BROADCAST_INTERVAL_MS
                var request = marshal_packet(
                    DiscoveryPacket.request(self._network_id)
                )
                try:
                    _ = self._socket.send_to(Span(request), target)
                except:
                    # No route for broadcasts (for example a loopback-only
                    # host): keep serving unicast traffic.
                    pass
        var src = SocketAddr(0, 0)
        while True:
            var n = self._socket.recv_from(Span(self._buf), src)
            if n < 0:
                break
            self._on_datagram(n, src, now_ms)
        self._expire(now_ms)

    def next_timeout(self) -> Int:
        """Computes when `service()` next has periodic work.

        Returns:
            The absolute time of the next broadcast, or a very large value
            if this listener does not broadcast.
        """
        if self._broadcast is None:
            return 0x3FFF_FFFF_FFFF_FFFF
        return self._next_broadcast_ms

    def _on_datagram(mut self, n: Int, src: SocketAddr, now_ms: Int):
        var pk: DiscoveryPacket
        try:
            pk = unmarshal_packet(Span(self._buf)[0:n])
        except:
            return
        if pk.sender_id == self._network_id:
            return
        if pk.kind == PACKET_REQUEST:
            if len(self._server_data) == 0:
                return
            try:
                var response = marshal_packet(
                    DiscoveryPacket.response(
                        self._network_id, Span(self._server_data)
                    )
                )
                _ = self._socket.send_to(Span(response), src)
            except:
                return
        elif pk.kind == PACKET_RESPONSE:
            self._learn(pk.sender_id, src, now_ms)
            if (
                pk.sender_id in self._responses
                or len(self._responses) < _MAX_PEERS
            ):
                self._responses[pk.sender_id] = DiscoveredServer(
                    pk.sender_id, src, pk.application_data.copy(), now_ms
                )
        elif pk.kind == PACKET_MESSAGE:
            self._learn(pk.sender_id, src, now_ms)
            if pk.recipient_id != self._network_id:
                return
            if pk.data.byte_length() == 0 or pk.data == "Ping":
                return
            if len(self._signals) >= _MAX_QUEUED_SIGNALS:
                return
            try:
                self._signals.append(
                    parse_signal(pk.data, String(pk.sender_id))
                )
            except:
                return

    def _learn(mut self, network_id: UInt64, addr: SocketAddr, now_ms: Int):
        if network_id in self._peers or len(self._peers) < _MAX_PEERS:
            self._peers[network_id] = _Peer(addr, now_ms)

    def _expire(mut self, now_ms: Int):
        var stale_peers = List[UInt64]()
        for entry in self._peers.items():
            if now_ms - entry.value.seen_ms > ADDRESS_LIFETIME_MS:
                stale_peers.append(entry.key)
        for id in stale_peers:
            try:
                _ = self._peers.pop(id)
            except:
                pass
        var stale_responses = List[UInt64]()
        for entry in self._responses.items():
            if now_ms - entry.value.seen_ms > RESPONSE_LIFETIME_MS:
                stale_responses.append(entry.key)
        for id in stale_responses:
            try:
                _ = self._responses.pop(id)
            except:
                pass
