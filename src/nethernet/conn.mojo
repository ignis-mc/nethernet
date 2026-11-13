"""A NetherNet connection: ICE, DTLS, SCTP and the two data channels.

`Conn` owns one UDP socket and the three protocol state machines stacked on
it. It never blocks unless asked to: `poll()` does whatever work is possible
right now, and `read()`, `write()` and `drive()` are conveniences that wait on
the socket.

Message framing: every data-channel message starts with one byte holding the
number of segments still to come, followed by a payload fragment. A message
larger than the peer's `max-message-size` minus one is split across several
ordered messages on `ReliableDataChannel`.
"""

from std.memory import OwnedPointer

from .crypto.p256 import p256_private_key_from_bytes
from .crypto.x509 import certificate_fingerprint, self_signed_certificate
from .datachannel.dcep import (
    PPID_BINARY,
    PPID_DCEP,
    PPID_STRING,
    RELIABLE_LABEL,
    UNRELIABLE_LABEL,
    ChannelOpen,
    encode_dcep_ack,
    is_dcep_ack,
)
from .dtls.conn import (
    DTLS_RANDOM_LEN,
    DTLS_STATE_CLOSED,
    DTLS_STATE_CONNECTED,
    DTLS_STATE_FAILED,
    DTLS_STATE_NEW,
    DtlsConfig,
    DtlsConn,
)
from .ice.agent import (
    ICE_STATE_CONNECTED,
    ICE_STATE_DISCONNECTED,
    ICE_STATE_FAILED,
    ICE_STATE_NEW,
    IceAgent,
)
from .ice.candidate import IceCandidate, parse_candidate
from .os.addr import SocketAddr
from .os.poll import PollSet
from .os.random import random_bytes, random_u32, random_u64
from .os.time import monotonic_ms, unix_time_s
from .os.udp import UdpSocket, default_local_ip
from .sctp.association import Association
from .sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SctpConfig,
)
from .sdp.description import (
    DEFAULT_MAX_MESSAGE_SIZE,
    SETUP_ACTIVE,
    SETUP_ACTPASS,
    SETUP_PASSIVE,
    Description,
)
from .stun.message import is_stun

comptime CONN_STATE_NEGOTIATING = 0
"""Waiting for the remote description or the first remote candidate."""
comptime CONN_STATE_CONNECTING = 1
"""ICE, DTLS, SCTP or the channel handshake is in progress."""
comptime CONN_STATE_OPEN = 2
"""Both data channels are open; messages may flow."""
comptime CONN_STATE_CLOSED = 3
"""The connection is closed; see `close_reason()`."""

comptime RELIABLE = 0
"""Ordered, reliable delivery on `ReliableDataChannel`."""
comptime UNRELIABLE = 1
"""Unordered, best-effort delivery on `UnreliableDataChannel`."""

comptime MAX_SEGMENTS = 256
"""The most segments one message may be split into (the count byte is 8 bits)."""

comptime _NEVER = 0x3FFF_FFFF_FFFF_FFFF
comptime _RECV_BUFFER_LEN = 65536


struct ConnConfig(Copyable):
    """Per-connection settings."""

    var bind_ip: UInt32
    """The local IPv4 address to bind and advertise; 0 picks the default route."""
    var max_message_size: Int
    """The `max-message-size` to advertise to the peer."""
    var max_packet_size: Int
    """The largest reassembled message accepted from the peer."""
    var common_name: String
    """The common name in the self-signed DTLS certificate."""

    def __init__(out self):
        """Creates the default configuration."""
        self.bind_ip = 0
        self.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        self.max_packet_size = 16 * 1024 * 1024
        self.common_name = "WebRTC"


struct _Channel(Copyable):
    var stream_id: Int
    var remaining: Int
    var buffer: List[UInt8]

    def __init__(out self):
        self.stream_id = -1
        self.remaining = -1
        self.buffer = List[UInt8]()


def _random_letters(n: Int) raises -> String:
    var alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".as_bytes()
    var raw = random_bytes(n)
    var out = List[UInt8](capacity=n)
    for b in raw:
        out.append(alphabet[Int(b) % 52])
    return String(unsafe_from_utf8=Span(out))


struct Conn(Movable):
    """One NetherNet connection."""

    var _config: ConnConfig
    var _offerer: Bool
    var _connection_id: UInt64
    var _remote_network_id: String
    var _state: Int
    var _close_reason: String

    var _socket: UdpSocket
    var _local_addr: SocketAddr
    var _recv_buf: List[UInt8]

    var _private_key: List[UInt8]
    var _certificate: List[UInt8]
    var _local: Description
    var _have_remote: Bool
    var _remote_max_message_size: Int

    var _ice: IceAgent
    var _dtls: OwnedPointer[DtlsConn]
    var _dtls_client: Bool
    var _sctp: OwnedPointer[Association]
    var _sctp_started: Bool
    var _sctp_connected: Bool

    var _reliable: _Channel
    var _unreliable: _Channel
    var _inbox: List[List[UInt8]]
    var _inbox_unreliable: List[List[UInt8]]
    var _peer_public_key: List[UInt8]

    def __init__(
        out self, offerer: Bool, connection_id: UInt64, config: ConnConfig
    ) raises:
        """Creates a connection and binds its socket.

        Generates the ICE credentials and a fresh self-signed certificate.

        Args:
            offerer: `True` for the dialing side, which sends the offer, is
                ICE controlling and opens the data channels.
            connection_id: The identifier carried in every signal.
            config: The connection settings.

        Raises:
            Error: If the socket cannot be bound or the kernel cannot supply
                randomness.
        """
        # Everything that can raise happens before the first field is
        # assigned, so a failure never leaves a half-built connection.
        var ip = config.bind_ip
        if ip == 0:
            try:
                ip = default_local_ip()
            except:
                ip = 0x7F000001
        var socket = UdpSocket(SocketAddr(ip, 0))
        var local_addr = socket.local_addr()

        var key_seed = random_bytes(40)
        var key = p256_private_key_from_bytes(Span(key_seed))
        var private_key = List[UInt8](Span(key))
        var serial = random_bytes(16)
        var now_s = unix_time_s()
        var certificate = self_signed_certificate(
            Span(private_key),
            Span(serial),
            now_s - 86400,
            now_s + 30 * 86400,
            config.common_name,
        )

        var local = Description()
        local.session_id = random_u64() >> 1
        local.ice_ufrag = _random_letters(16)
        local.ice_pwd = _random_letters(32)
        local.fingerprint = certificate_fingerprint(Span(certificate))
        local.setup = SETUP_ACTPASS
        local.max_message_size = config.max_message_size

        var ice = IceAgent(
            offerer, local.ice_ufrag, local.ice_pwd, random_u64(), random_u64()
        )
        # Placeholder until the remote description fixes the DTLS role.
        var dtls_random = random_bytes(DTLS_RANDOM_LEN)
        var dtls = DtlsConn(
            DtlsConfig(
                False, Span(certificate), Span(private_key), Span(dtls_random)
            )
        )
        var tag = random_u32()
        if tag == 0:
            tag = 1
        var cookie_secret = random_bytes(32)
        var sctp_config = SctpConfig(tag, random_u32(), Span(cookie_secret))
        sctp_config.max_message_size = max(
            sctp_config.max_message_size, config.max_message_size
        )

        self._config = config.copy()
        self._offerer = offerer
        self._connection_id = connection_id
        self._remote_network_id = String()
        self._state = CONN_STATE_NEGOTIATING
        self._close_reason = String()
        self._socket = socket^
        self._local_addr = local_addr
        self._recv_buf = List[UInt8](length=_RECV_BUFFER_LEN, fill=0)
        self._private_key = private_key^
        self._certificate = certificate^
        self._local = local^
        self._have_remote = False
        self._remote_max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        self._ice = ice^
        self._dtls = OwnedPointer(dtls^)
        self._dtls_client = False
        self._sctp = OwnedPointer(Association(sctp_config))
        self._sctp_started = False
        self._sctp_connected = False
        self._reliable = _Channel()
        self._unreliable = _Channel()
        self._inbox = List[List[UInt8]]()
        self._inbox_unreliable = List[List[UInt8]]()
        self._peer_public_key = List[UInt8]()

    # ===------------------------------------------------------------------=== #
    # Negotiation
    # ===------------------------------------------------------------------=== #

    def local_description(self, include_candidates: Bool) -> Description:
        """Builds the description to signal to the peer.

        For the answering side, call this after `set_remote_description()`,
        which decides the DTLS role.

        Args:
            include_candidates: Whether to embed the local candidate, which
                signaling channels without trickle ICE require.

        Returns:
            The local description.
        """
        var d = self._local.copy()
        if include_candidates:
            d.candidates.append(
                self.local_candidate().attribute_value(self._local.ice_ufrag, 0)
            )
        return d^

    def local_fingerprint(self) -> String:
        """Gets the SHA-256 fingerprint of the local DTLS certificate.

        Returns:
            Uppercase colon-separated hex, as written in `a=fingerprint`.
        """
        return self._local.fingerprint.copy()

    def set_local_identity(mut self, value: StringSpan):
        """Attaches an identity assertion to the local description.

        Args:
            value: The base64 text for `a=identity`, from `Identity.sign()`
                over `local_fingerprint()`.
        """
        self._local.identity = String(value)

    def peer_public_key(self) -> List[UInt8]:
        """Gets the identity key the peer proved possession of.

        Returns:
            The uncompressed P-384 point, or an empty list if the peer was
            anonymous or its identity was not checked.
        """
        return self._peer_public_key.copy()

    def set_peer_public_key(mut self, key: Span[UInt8, _]):
        """Records the peer's verified identity key.

        Args:
            key: The uncompressed P-384 point.
        """
        self._peer_public_key = List[UInt8](key)

    def local_candidate(self) -> IceCandidate:
        """Gets the host candidate for this connection's socket.

        Returns:
            The single local candidate.
        """
        return IceCandidate.host(self._local_addr)

    def local_candidate_signal(self) -> String:
        """Formats the local candidate as `CANDIDATEADD` signal data.

        Returns:
            The candidate line with its `candidate:` prefix.
        """
        return self.local_candidate().signal_value(self._local.ice_ufrag, 0)

    def set_remote_description(mut self, remote: Description) raises:
        """Applies the peer's description and fixes the DTLS role.

        The offerer becomes the DTLS server unless the answer says `passive`.
        The answerer takes the client role (`a=setup:active`) unless the
        offer says `active`.

        Args:
            remote: The parsed description from the offer or the answer.

        Raises:
            Error: If the fingerprint is not SHA-256, a description was
                already applied, or the kernel cannot supply randomness.
        """
        if self._have_remote:
            raise Error("remote description already set")
        if remote.fingerprint_algorithm.lower() != "sha-256":
            raise Error("unsupported fingerprint algorithm")
        var fingerprint = remote.fingerprint_bytes()
        if len(fingerprint) != 32:
            raise Error("malformed SHA-256 fingerprint")
        if self._offerer:
            self._dtls_client = remote.setup == SETUP_PASSIVE
        else:
            self._dtls_client = remote.setup != SETUP_ACTIVE
            self._local.setup = (
                String(SETUP_ACTIVE)
                if self._dtls_client
                else String(SETUP_PASSIVE)
            )
        var dtls_random = random_bytes(DTLS_RANDOM_LEN)
        var dtls_config = DtlsConfig(
            self._dtls_client,
            Span(self._certificate),
            Span(self._private_key),
            Span(dtls_random),
        )
        dtls_config.remote_fingerprint = fingerprint^
        self._dtls = OwnedPointer(DtlsConn(dtls_config))
        self._remote_max_message_size = remote.max_message_size
        self._ice.set_remote_credentials(remote.ice_ufrag, remote.ice_pwd)
        self._have_remote = True
        for c in remote.candidates:
            self.add_remote_candidate(c)

    def add_remote_candidate(mut self, text: StringSpan):
        """Adds a remote ICE candidate from a signal or an SDP line.

        Candidates this library cannot use (TCP, IPv6, mDNS names) and
        malformed lines are ignored.

        Args:
            text: The candidate line, with or without a `candidate:` prefix.
        """
        try:
            var cand = parse_candidate(text)
            self._ice.add_remote_candidate(cand.addr, monotonic_ms())
        except:
            return

    # ===------------------------------------------------------------------=== #
    # Queries
    # ===------------------------------------------------------------------=== #

    def state(self) -> Int:
        """Gets the connection state.

        Returns:
            One of the `CONN_STATE_*` constants.
        """
        return self._state

    def is_open(self) -> Bool:
        """Checks whether messages can be sent and received.

        Returns:
            `True` in the `CONN_STATE_OPEN` state.
        """
        return self._state == CONN_STATE_OPEN

    def is_closed(self) -> Bool:
        """Checks whether the connection has ended.

        Returns:
            `True` in the `CONN_STATE_CLOSED` state.
        """
        return self._state == CONN_STATE_CLOSED

    def close_reason(self) -> String:
        """Describes why the connection closed.

        Returns:
            A short reason, empty while the connection is not closed.
        """
        return self._close_reason.copy()

    def connection_id(self) -> UInt64:
        """Gets the connection identifier used in signals.

        Returns:
            The identifier chosen by the dialing side.
        """
        return self._connection_id

    def remote_network_id(self) -> String:
        """Gets the network ID of the peer.

        Returns:
            The peer's network ID as given to the dialer or the listener.
        """
        return self._remote_network_id.copy()

    def set_remote_network_id(mut self, network_id: StringSpan):
        """Records the network ID of the peer.

        Args:
            network_id: The peer's network ID.
        """
        self._remote_network_id = String(network_id)

    def local_addr(self) -> SocketAddr:
        """Gets the local socket address.

        Returns:
            The bound address, which is also the advertised candidate.
        """
        return self._local_addr

    def remote_addr(self) -> Optional[SocketAddr]:
        """Gets the peer address ICE selected.

        Returns:
            The remote address, or `None` before ICE completes.
        """
        return self._ice.selected()

    def latency_ms(self) -> Int:
        """Estimates the one-way latency from ICE round-trip times.

        Returns:
            Half the latest round-trip time, or -1 if not yet measured.
        """
        var rtt = self._ice.rtt_ms()
        if rtt < 0:
            return -1
        return rtt // 2

    def fd(self) -> Int:
        """Gets the socket descriptor, for waiting with a `PollSet`.

        Returns:
            The file descriptor.
        """
        return self._socket.fd()

    def buffered_amount(self) -> Int:
        """Counts bytes queued for sending that the peer has not acknowledged.

        Returns:
            The number of payload bytes still buffered in SCTP.
        """
        return self._sctp[].buffered_amount()

    def next_timeout(self) -> Int:
        """Computes when `poll()` next has timer work to do.

        Returns:
            An absolute monotonic time in milliseconds; a very large value if
            no timer is pending.
        """
        if self._state == CONN_STATE_CLOSED:
            return _NEVER
        var t = min(self._ice.next_timeout(), self._dtls[].next_timeout())
        if self._sctp_started:
            if case .Some(sctp_deadline) = self._sctp[].next_timeout():
                t = min(t, sctp_deadline)
        return t

    # ===------------------------------------------------------------------=== #
    # Driving
    # ===------------------------------------------------------------------=== #

    def poll(mut self, now_ms: Int) raises:
        """Does all work that is possible without blocking.

        Reads pending datagrams, advances ICE, DTLS and SCTP, and sends what
        they produce.

        Args:
            now_ms: The current monotonic time in milliseconds.

        Raises:
            Error: If the socket fails.
        """
        if self._state == CONN_STATE_CLOSED:
            return
        var src = SocketAddr(0, 0)
        while True:
            var n = self._socket.recv_from(Span(self._recv_buf), src)
            if n < 0:
                break
            self._on_datagram(n, src, now_ms)
        self._advance(now_ms)
        self._flush(now_ms)

    def drive(mut self, timeout_ms: Int) raises:
        """Waits for socket activity or a timer, then calls `poll()`.

        Args:
            timeout_ms: The longest time to wait.

        Raises:
            Error: If the socket fails.
        """
        var now = monotonic_ms()
        var wait = max(0, min(timeout_ms, self.next_timeout() - now))
        var set = PollSet()
        _ = set.add(self._socket.fd())
        _ = set.wait(wait)
        self.poll(monotonic_ms())

    def _on_datagram(mut self, n: Int, src: SocketAddr, now_ms: Int):
        var data = Span(self._recv_buf)[0:n]
        if is_stun(data):
            self._ice.handle_packet(data, src, now_ms)
            return
        if n == 0 or data[0] < 20 or data[0] > 63:
            return
        # DTLS is accepted only on the pair ICE selected.
        if case .Some(selected) = self._ice.selected():
            if selected == src:
                self._ice.note_activity(src, now_ms)
                if self._dtls[].state() == DTLS_STATE_NEW:
                    self._dtls[].start(now_ms)
                self._dtls[].handle_datagram(data, now_ms)

    def _advance(mut self, now_ms: Int) raises:
        if self._have_remote and self._ice.state() == ICE_STATE_NEW:
            if self._ice.selected() is None:
                self._ice.start(now_ms)
                if self._state == CONN_STATE_NEGOTIATING:
                    self._state = CONN_STATE_CONNECTING
        self._ice.handle_timeout(now_ms)
        if self._ice.state() == ICE_STATE_FAILED:
            self._fail("ICE failed")
            return
        if (
            self._ice.state() == ICE_STATE_CONNECTED
            or self._ice.state() == ICE_STATE_DISCONNECTED
        ):
            if self._dtls[].state() == DTLS_STATE_NEW:
                self._dtls[].start(now_ms)
        self._dtls[].handle_timeout(now_ms)
        if self._dtls[].state() == DTLS_STATE_FAILED:
            self._fail(self._dtls[].failure_reason())
            return
        if self._dtls[].state() == DTLS_STATE_CLOSED:
            self._fail("closed by peer")
            return
        if self._dtls[].state() != DTLS_STATE_CONNECTED:
            return
        if not self._sctp_started:
            self._sctp_started = True
            self._sctp[].connect(now_ms)
        while True:
            var packet = self._dtls[].poll_app_data()
            if packet is None:
                break
            self._sctp[].handle_packet(Span(packet.value()), now_ms)
        self._sctp[].handle_timeout(now_ms)
        while True:
            var event = self._sctp[].poll_event()
            if event is None:
                break
            var ev = event.take()
            if ev.kind == SCTP_EVENT_CONNECTED:
                self._sctp_connected = True
                if self._offerer:
                    self._open_channels()
            elif ev.kind == SCTP_EVENT_MESSAGE:
                self._on_message(ev.stream_id, ev.ppid, Span(ev.payload))
            elif ev.kind == SCTP_EVENT_STREAM_RESET:
                self._fail("data channel closed by peer")
            elif ev.kind == SCTP_EVENT_CLOSED:
                self._fail(String(t"SCTP closed: {ev.reason}"))
            if self._state == CONN_STATE_CLOSED:
                return

    def _flush(mut self, now_ms: Int) raises:
        while True:
            var t = self._ice.poll_transmit()
            if t is None:
                break
            var tx = t.take()
            _ = self._socket.send_to(Span(tx.payload), tx.dest)
        if self._sctp_started and self._dtls[].state() == DTLS_STATE_CONNECTED:
            while True:
                var p = self._sctp[].poll_transmit(now_ms)
                if p is None:
                    break
                self._dtls[].send_app_data(Span(p.value()))
        if case .Some(dest) = self._ice.selected():
            while True:
                var d = self._dtls[].poll_transmit()
                if d is None:
                    break
                _ = self._socket.send_to(Span(d.value()), dest)

    # ===------------------------------------------------------------------=== #
    # Channels and messages
    # ===------------------------------------------------------------------=== #

    def _open_channels(mut self) raises:
        # RFC 8832: the DTLS client uses even stream IDs, the server odd.
        var base = 0 if self._dtls_client else 1
        self._reliable.stream_id = base
        self._unreliable.stream_id = base + 2
        var a = List[UInt8]()
        ChannelOpen.reliable().encode(a)
        self._sctp[].send(UInt16(base), PPID_DCEP, Span(a), False, -1)
        var b = List[UInt8]()
        ChannelOpen.unreliable().encode(b)
        self._sctp[].send(UInt16(base + 2), PPID_DCEP, Span(b), False, -1)
        self._state = CONN_STATE_OPEN

    def _on_message(mut self, stream_id: UInt16, ppid: UInt32, data: Span[UInt8, _]):
        if ppid == PPID_DCEP:
            self._on_dcep(stream_id, data)
            return
        if ppid != PPID_BINARY and ppid != PPID_STRING:
            self._fail("unexpected payload protocol on a data channel")
            return
        if len(data) < 2:
            self._fail("data channel message shorter than two bytes")
            return
        var count = Int(data[0])
        if Int(stream_id) == self._unreliable.stream_id:
            if count != 0:
                self._fail("segmented message on the unreliable channel")
                return
            self._inbox_unreliable.append(List[UInt8](data[1 : len(data)]))
            return
        if Int(stream_id) != self._reliable.stream_id:
            self._fail("message on an unknown data channel")
            return
        if self._reliable.remaining >= 0 and count != self._reliable.remaining - 1:
            self._fail("out-of-sequence message segment")
            return
        if len(self._reliable.buffer) + len(data) - 1 > self._config.max_packet_size:
            self._fail("message exceeds the maximum packet size")
            return
        self._reliable.buffer.extend(data[1 : len(data)])
        if count == 0:
            var whole = List[UInt8]()
            swap(whole, self._reliable.buffer)
            self._inbox.append(whole^)
            self._reliable.remaining = -1
        else:
            self._reliable.remaining = count

    def _on_dcep(mut self, stream_id: UInt16, data: Span[UInt8, _]):
        if is_dcep_ack(data):
            return
        if self._offerer:
            # NetherNet channels are only ever opened by the dialing side.
            self._fail("peer opened a data channel")
            return
        var open: ChannelOpen
        try:
            open = ChannelOpen.decode(data)
        except:
            self._fail("malformed DATA_CHANNEL_OPEN")
            return
        var expect_reliable = ChannelOpen.reliable()
        var expect_unreliable = ChannelOpen.unreliable()
        if (
            open.label == RELIABLE_LABEL
            and open.channel_type == expect_reliable.channel_type
            and self._reliable.stream_id < 0
        ):
            self._reliable.stream_id = Int(stream_id)
        elif (
            open.label == UNRELIABLE_LABEL
            and open.channel_type == expect_unreliable.channel_type
            and open.reliability == 0
            and self._unreliable.stream_id < 0
        ):
            self._unreliable.stream_id = Int(stream_id)
        else:
            self._fail("unexpected data channel")
            return
        var ack = List[UInt8]()
        encode_dcep_ack(ack)
        try:
            self._sctp[].send(stream_id, PPID_DCEP, Span(ack), False, -1)
        except:
            self._fail("failed to acknowledge a data channel")
            return
        if self._reliable.stream_id >= 0 and self._unreliable.stream_id >= 0:
            self._state = CONN_STATE_OPEN

    def max_segment_size(self) -> Int:
        """Gets the largest payload one data-channel message can carry.

        Returns:
            The peer's `max-message-size` minus the segment-count byte.
        """
        return self._remote_max_message_size - 1

    def send(mut self, data: Span[UInt8, _], reliability: Int = RELIABLE) raises:
        """Queues one message for the peer.

        Nothing is transmitted until the next `poll()`. An empty message is
        not sent at all, because the peer treats it as a protocol error.

        Args:
            data: The message payload.
            reliability: `RELIABLE` or `UNRELIABLE`.

        Raises:
            Error: If the connection is not open, the message needs more
                than `MAX_SEGMENTS` segments, or an unreliable message does
                not fit in one segment.
        """
        if self._state != CONN_STATE_OPEN:
            raise Error("connection is not open")
        if len(data) == 0:
            return
        var segment = self.max_segment_size()
        if reliability == UNRELIABLE:
            if len(data) > segment:
                raise Error("unreliable message does not fit in one segment")
            var msg = List[UInt8](capacity=len(data) + 1)
            msg.append(0)
            msg.extend(data)
            self._sctp[].send(
                UInt16(self._unreliable.stream_id), PPID_BINARY, Span(msg), True, 0
            )
            return
        var segments = (len(data) + segment - 1) // segment
        if segments > MAX_SEGMENTS:
            raise Error("message needs too many segments")
        var offset = 0
        for i in range(segments):
            var n = min(segment, len(data) - offset)
            var msg = List[UInt8](capacity=n + 1)
            msg.append(UInt8(segments - 1 - i))
            msg.extend(data[offset : offset + n])
            self._sctp[].send(
                UInt16(self._reliable.stream_id), PPID_BINARY, Span(msg), False, -1
            )
            offset += n

    def receive(mut self, reliability: Int = RELIABLE) -> Optional[List[UInt8]]:
        """Takes the next complete message without blocking.

        Args:
            reliability: Which channel to read: `RELIABLE` or `UNRELIABLE`.

        Returns:
            A whole message, or `None` if none has arrived.
        """
        if reliability == UNRELIABLE:
            if len(self._inbox_unreliable) == 0:
                return None
            return self._inbox_unreliable.pop(0)
        if len(self._inbox) == 0:
            return None
        return self._inbox.pop(0)

    def read(mut self, timeout_ms: Int) raises -> List[UInt8]:
        """Waits for the next message on the reliable channel.

        Args:
            timeout_ms: The longest time to wait; negative waits forever.

        Returns:
            A whole message.

        Raises:
            Error: If the connection closes or the timeout passes first.
        """
        var deadline = _NEVER
        if timeout_ms >= 0:
            deadline = monotonic_ms() + timeout_ms
        while True:
            self.poll(monotonic_ms())
            if len(self._inbox) > 0:
                return self._inbox.pop(0)
            if self._state == CONN_STATE_CLOSED:
                raise Error(t"connection closed: {self._close_reason}")
            var now = monotonic_ms()
            if now >= deadline:
                raise Error("read timed out")
            self.drive(min(deadline - now, 1000))

    def write(mut self, data: Span[UInt8, _]) raises:
        """Sends a message on the reliable channel and transmits it now.

        Args:
            data: The message payload.

        Raises:
            Error: If the connection is not open or the message is too large.
        """
        self.send(data, RELIABLE)
        self.poll(monotonic_ms())

    def flush(mut self, timeout_ms: Int) raises -> Bool:
        """Drives the connection until the peer acknowledged all sent data.

        Args:
            timeout_ms: The longest time to wait.

        Returns:
            `True` if nothing is left buffered, `False` on timeout or close.

        Raises:
            Error: If the socket fails.
        """
        var deadline = monotonic_ms() + timeout_ms
        while True:
            self.poll(monotonic_ms())
            if self._state == CONN_STATE_CLOSED:
                return False
            if self._sctp[].buffered_amount() == 0:
                return True
            var now = monotonic_ms()
            if now >= deadline:
                return False
            self.drive(min(deadline - now, 50))

    # ===------------------------------------------------------------------=== #
    # Closing
    # ===------------------------------------------------------------------=== #

    def close(mut self, linger_ms: Int = 3000):
        """Closes the connection.

        Waits up to `linger_ms` for buffered data to be acknowledged, then
        aborts SCTP and sends a DTLS `close_notify`.

        Args:
            linger_ms: The longest time to wait for unacknowledged data.
        """
        if self._state == CONN_STATE_CLOSED:
            return
        if self._state == CONN_STATE_OPEN and linger_ms > 0:
            try:
                _ = self.flush(linger_ms)
            except:
                pass
        self._shutdown("closed locally")

    def abort(mut self):
        """Closes the connection immediately, discarding unsent data."""
        self._shutdown("aborted locally")

    def _fail(mut self, reason: StringSpan):
        self._shutdown(reason)

    def _shutdown(mut self, reason: StringSpan):
        if self._state == CONN_STATE_CLOSED:
            return
        self._state = CONN_STATE_CLOSED
        self._close_reason = String(reason)
        var now = monotonic_ms()
        try:
            if self._sctp_started:
                self._sctp[].abort("")
            self._flush(now)
            self._dtls[].close()
            self._flush(now)
        except:
            pass
