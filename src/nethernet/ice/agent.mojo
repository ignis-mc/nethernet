"""A single-socket ICE agent: connectivity checks, nomination and keepalives.

The agent is sans-I/O. Feed it STUN datagrams with `handle_packet()`, call
`handle_timeout()` when `next_timeout()` passes, and send whatever
`poll_transmit()` returns from the one UDP socket the connection owns.

Scope: one local host candidate (the bound socket), IPv4 UDP remote
candidates, regular nomination when controlling, and peer-reflexive learning
from authenticated requests. There is no gathering of server-reflexive or
relayed candidates.
"""

from ..os.addr import SocketAddr
from ..stun.message import (
    STUN_ATTR_USE_CANDIDATE,
    STUN_BINDING_ERROR,
    STUN_BINDING_INDICATION,
    STUN_BINDING_REQUEST,
    STUN_BINDING_SUCCESS,
    STUN_ERROR_ROLE_CONFLICT,
    StunBuilder,
    StunMessage,
    is_stun,
    parse_stun,
    verify_message_integrity,
)
from .candidate import ICE_PRFLX_PRIORITY

comptime ICE_STATE_NEW = 0
"""No checks have been sent yet."""
comptime ICE_STATE_CHECKING = 1
"""Connectivity checks are running; no pair is selected."""
comptime ICE_STATE_CONNECTED = 2
"""A candidate pair is selected and alive."""
comptime ICE_STATE_DISCONNECTED = 3
"""The selected pair has been silent for `ICE_DISCONNECT_MS`."""
comptime ICE_STATE_FAILED = 4
"""Checks never succeeded, or the selected pair stayed silent too long."""

comptime ICE_CHECK_INTERVAL_MS = 200
"""How often an unselected pair is re-checked."""
comptime ICE_KEEPALIVE_INTERVAL_MS = 2000
"""How often the selected pair is checked to keep consent fresh."""
comptime ICE_DISCONNECT_MS = 5000
"""Silence on the selected pair before the agent reports disconnected."""
comptime ICE_FAILED_MS = 30000
"""Silence (or fruitless checking) before the agent reports failed."""

comptime _MAX_PAIRS = 32
comptime _MAX_TXNS = 8
comptime _NEVER = 0x3FFF_FFFF_FFFF_FFFF


@fieldwise_init
struct IceTransmit(Copyable):
    """A datagram the agent wants sent."""

    var dest: SocketAddr
    """The destination address."""
    var payload: List[UInt8]
    """The STUN message bytes."""


@fieldwise_init
struct _Txn(Copyable):
    var id: Array[UInt8, 12]
    var sent_ms: Int
    var nominate: Bool


struct _Pair(Copyable):
    var remote: SocketAddr
    var succeeded: Bool
    var nominated: Bool
    var nominating: Bool
    var next_check_ms: Int
    var txns: List[_Txn]
    var rtt_ms: Int

    def __init__(out self, remote: SocketAddr, now_ms: Int):
        self.remote = remote
        self.succeeded = False
        self.nominated = False
        self.nominating = False
        self.next_check_ms = now_ms
        self.txns = List[_Txn]()
        self.rtt_ms = -1


struct IceAgent(Movable):
    """The ICE state machine for one connection."""

    var _controlling: Bool
    var _tie_breaker: UInt64
    var _local_ufrag: String
    var _local_pwd: String
    var _remote_ufrag: String
    var _remote_pwd: String
    var _pairs: List[_Pair]
    var _selected: Int
    var _state: Int
    var _started_ms: Int
    var _last_rx_ms: Int
    var _out: List[IceTransmit]
    var _rng: UInt64

    def __init__(
        out self,
        controlling: Bool,
        local_ufrag: StringSpan,
        local_pwd: StringSpan,
        tie_breaker: UInt64,
        seed: UInt64,
    ):
        """Creates an agent.

        Args:
            controlling: `True` for the offerer (the dialer), `False` for the
                answerer.
            local_ufrag: The local username fragment sent in the SDP.
            local_pwd: The local password sent in the SDP.
            tie_breaker: A random value used to resolve role conflicts.
            seed: A random value that seeds transaction identifiers.
        """
        self._controlling = controlling
        self._tie_breaker = tie_breaker
        self._local_ufrag = String(local_ufrag)
        self._local_pwd = String(local_pwd)
        self._remote_ufrag = String()
        self._remote_pwd = String()
        self._pairs = List[_Pair]()
        self._selected = -1
        self._state = ICE_STATE_NEW
        self._started_ms = 0
        self._last_rx_ms = 0
        self._out = List[IceTransmit]()
        self._rng = seed | 1

    # ===------------------------------------------------------------------=== #
    # Configuration
    # ===------------------------------------------------------------------=== #

    def set_remote_credentials(mut self, ufrag: StringSpan, pwd: StringSpan):
        """Records the peer's username fragment and password from its SDP.

        Args:
            ufrag: The remote username fragment.
            pwd: The remote password.
        """
        self._remote_ufrag = String(ufrag)
        self._remote_pwd = String(pwd)

    def add_remote_candidate(mut self, addr: SocketAddr, now_ms: Int):
        """Adds a remote transport address to check.

        Duplicates are ignored, and so are candidates beyond a fixed cap.

        Args:
            addr: The remote candidate address.
            now_ms: The current monotonic time in milliseconds.
        """
        _ = self._pair_for(addr, now_ms)

    def start(mut self, now_ms: Int):
        """Begins connectivity checks.

        Call once the remote credentials are known. Checks go out on the next
        `handle_timeout()`.

        Args:
            now_ms: The current monotonic time in milliseconds.
        """
        if self._state == ICE_STATE_NEW:
            self._state = ICE_STATE_CHECKING
            self._started_ms = now_ms
            self._last_rx_ms = now_ms
            for i in range(len(self._pairs)):
                self._pairs[i].next_check_ms = now_ms

    # ===------------------------------------------------------------------=== #
    # Queries
    # ===------------------------------------------------------------------=== #

    def state(self) -> Int:
        """Gets the connection state.

        Returns:
            One of the `ICE_STATE_*` constants.
        """
        return self._state

    def is_controlling(self) -> Bool:
        """Checks the current role, which a role conflict can change.

        Returns:
            `True` if the agent is controlling.
        """
        return self._controlling

    def selected(self) -> Optional[SocketAddr]:
        """Gets the remote address of the selected candidate pair.

        Returns:
            The address to send DTLS to, or `None` before selection.
        """
        if self._selected < 0:
            return None
        return self._pairs[self._selected].remote

    def rtt_ms(self) -> Int:
        """Gets the latest round-trip time measured on the selected pair.

        Returns:
            The round-trip time in milliseconds, or -1 if not measured.
        """
        if self._selected < 0:
            return -1
        return self._pairs[self._selected].rtt_ms

    def next_timeout(self) -> Int:
        """Computes when `handle_timeout()` next has work to do.

        Returns:
            An absolute monotonic time in milliseconds; a very large value if
            the agent is idle.
        """
        if self._state == ICE_STATE_NEW or self._state == ICE_STATE_FAILED:
            return _NEVER
        var t: Int
        if self._selected >= 0:
            t = self._pairs[self._selected].next_check_ms
            if self._state == ICE_STATE_CONNECTED:
                t = min(t, self._last_rx_ms + ICE_DISCONNECT_MS)
            else:
                t = min(t, self._last_rx_ms + ICE_FAILED_MS)
            return t
        t = self._started_ms + ICE_FAILED_MS
        if self._remote_pwd.byte_length() > 0:
            for i in range(len(self._pairs)):
                t = min(t, self._pairs[i].next_check_ms)
        return t

    def poll_transmit(mut self) -> Optional[IceTransmit]:
        """Takes the next datagram to send.

        Returns:
            A datagram and its destination, or `None` when nothing is queued.
        """
        if len(self._out) == 0:
            return None
        return self._out.pop(0)

    # ===------------------------------------------------------------------=== #
    # Input
    # ===------------------------------------------------------------------=== #

    def note_activity(mut self, src: SocketAddr, now_ms: Int):
        """Records that a non-STUN packet arrived from the selected address.

        Any traffic on the selected pair proves the path is alive.

        Args:
            src: The source address of the packet.
            now_ms: The current monotonic time in milliseconds.
        """
        if self._selected >= 0 and self._pairs[self._selected].remote == src:
            self._touch(now_ms)

    def handle_packet(
        mut self, data: Span[UInt8, _], src: SocketAddr, now_ms: Int
    ):
        """Processes one inbound STUN datagram.

        Malformed or unauthenticated messages are dropped silently.

        Args:
            data: The datagram.
            src: The source address of the datagram.
            now_ms: The current monotonic time in milliseconds.
        """
        if not is_stun(data):
            return
        try:
            var msg = parse_stun(data)
            if msg.msg_type == STUN_BINDING_REQUEST:
                self._on_request(data, msg, src, now_ms)
            elif msg.msg_type == STUN_BINDING_SUCCESS:
                self._on_response(data, msg, src, now_ms, True)
            elif msg.msg_type == STUN_BINDING_ERROR:
                self._on_response(data, msg, src, now_ms, False)
            elif msg.msg_type == STUN_BINDING_INDICATION:
                self.note_activity(src, now_ms)
        except:
            return

    def handle_timeout(mut self, now_ms: Int):
        """Sends due checks and keepalives and updates liveness.

        Args:
            now_ms: The current monotonic time in milliseconds.
        """
        if self._state == ICE_STATE_NEW or self._state == ICE_STATE_FAILED:
            return
        if self._selected >= 0:
            var silent = now_ms - self._last_rx_ms
            if silent >= ICE_FAILED_MS:
                self._state = ICE_STATE_FAILED
                return
            if silent >= ICE_DISCONNECT_MS:
                self._state = ICE_STATE_DISCONNECTED
            if now_ms >= self._pairs[self._selected].next_check_ms:
                self._send_check(self._selected, now_ms)
                self._pairs[self._selected].next_check_ms = (
                    now_ms + ICE_KEEPALIVE_INTERVAL_MS
                )
            return
        if now_ms - self._started_ms >= ICE_FAILED_MS:
            self._state = ICE_STATE_FAILED
            return
        if self._remote_pwd.byte_length() == 0:
            return
        for i in range(len(self._pairs)):
            if now_ms >= self._pairs[i].next_check_ms:
                self._send_check(i, now_ms)
                self._pairs[i].next_check_ms = now_ms + ICE_CHECK_INTERVAL_MS

    # ===------------------------------------------------------------------=== #
    # Internals
    # ===------------------------------------------------------------------=== #

    def _touch(mut self, now_ms: Int):
        self._last_rx_ms = now_ms
        if self._state == ICE_STATE_DISCONNECTED:
            self._state = ICE_STATE_CONNECTED

    def _pair_for(mut self, addr: SocketAddr, now_ms: Int) -> Int:
        for i in range(len(self._pairs)):
            if self._pairs[i].remote == addr:
                return i
        if len(self._pairs) >= _MAX_PAIRS:
            return -1
        self._pairs.append(_Pair(addr, now_ms))
        return len(self._pairs) - 1

    def _next_random(mut self) -> UInt64:
        # xorshift64*: transaction IDs only need to be unique and hard to
        # guess off-path; the seed comes from the kernel.
        self._rng ^= self._rng >> 12
        self._rng ^= self._rng << 25
        self._rng ^= self._rng >> 27
        return self._rng * 0x2545F4914F6CDD1D

    def _new_transaction_id(mut self) -> Array[UInt8, 12]:
        var id = Array[UInt8, 12](fill=0)
        var a = self._next_random()
        var b = self._next_random()
        for i in range(8):
            id[i] = UInt8((a >> UInt64(8 * i)) & 0xFF)
        for i in range(4):
            id[8 + i] = UInt8((b >> UInt64(8 * i)) & 0xFF)
        return id^

    def _select(mut self, index: Int, now_ms: Int):
        if self._selected < 0:
            self._selected = index
            self._state = ICE_STATE_CONNECTED
            self._last_rx_ms = now_ms
            self._pairs[index].next_check_ms = (
                now_ms + ICE_KEEPALIVE_INTERVAL_MS
            )

    def _send_check(mut self, index: Int, now_ms: Int):
        if self._remote_pwd.byte_length() == 0:
            return
        var id = self._new_transaction_id()
        var nominate = self._controlling and (
            self._pairs[index].nominating or self._selected == index
        )
        var b = StunBuilder(STUN_BINDING_REQUEST, id)
        b.add_username(String(t"{self._remote_ufrag}:{self._local_ufrag}"))
        if self._controlling:
            b.add_ice_controlling(self._tie_breaker)
        else:
            b.add_ice_controlled(self._tie_breaker)
        b.add_priority(ICE_PRFLX_PRIORITY)
        if nominate:
            b.add_use_candidate()
        var payload = b.finish(self._remote_pwd.as_bytes())
        if len(self._pairs[index].txns) >= _MAX_TXNS:
            _ = self._pairs[index].txns.pop(0)
        self._pairs[index].txns.append(_Txn(id^, now_ms, nominate))
        self._out.append(IceTransmit(self._pairs[index].remote, payload^))

    def _send_error(
        mut self,
        id: Array[UInt8, 12],
        dest: SocketAddr,
        code: Int,
        reason: StringSpan,
    ):
        var b = StunBuilder(STUN_BINDING_ERROR, id)
        b.add_error_code(code, reason)
        var payload = b.finish(self._local_pwd.as_bytes())
        self._out.append(IceTransmit(dest, payload^))

    def _on_request(
        mut self,
        raw: Span[UInt8, _],
        msg: StunMessage,
        src: SocketAddr,
        now_ms: Int,
    ):
        if not verify_message_integrity(raw, self._local_pwd.as_bytes()):
            return
        var username = msg.username().or_else(String())
        if not username.startswith(self._local_ufrag + ":"):
            return

        # Role conflict resolution (RFC 8445 section 7.3.1.1).
        if case .Some(their) = msg.ice_controlling():
            if self._controlling:
                if self._tie_breaker >= their:
                    self._send_error(
                        msg.transaction_id,
                        src,
                        STUN_ERROR_ROLE_CONFLICT,
                        "Role Conflict",
                    )
                    return
                self._controlling = False
        if case .Some(their) = msg.ice_controlled():
            if not self._controlling:
                if self._tie_breaker >= their:
                    self._controlling = True
                else:
                    self._send_error(
                        msg.transaction_id,
                        src,
                        STUN_ERROR_ROLE_CONFLICT,
                        "Role Conflict",
                    )
                    return

        var b = StunBuilder(STUN_BINDING_SUCCESS, msg.transaction_id)
        b.add_xor_mapped_address(src)
        var payload = b.finish(self._local_pwd.as_bytes())
        self._out.append(IceTransmit(src, payload^))

        var index = self._pair_for(src, now_ms)
        if index < 0:
            return
        if self._selected == index:
            self._touch(now_ms)
        if self._state == ICE_STATE_NEW:
            # Checks arrived before start(): begin as soon as credentials
            # allow, and answer in the meantime.
            self._pairs[index].next_check_ms = now_ms
            return
        if self._selected < 0:
            # Triggered check towards the address the request came from.
            self._pairs[index].next_check_ms = now_ms
            if not self._controlling and msg.has(STUN_ATTR_USE_CANDIDATE):
                self._pairs[index].nominated = True
                self._select(index, now_ms)

    def _on_response(
        mut self,
        raw: Span[UInt8, _],
        msg: StunMessage,
        src: SocketAddr,
        now_ms: Int,
        success: Bool,
    ):
        var index = -1
        var txn_index = -1
        for i in range(len(self._pairs)):
            for j in range(len(self._pairs[i].txns)):
                var same = True
                for k in range(12):
                    if self._pairs[i].txns[j].id[k] != msg.transaction_id[k]:
                        same = False
                if same:
                    index = i
                    txn_index = j
        if index < 0:
            return
        if not (self._pairs[index].remote == src):
            return
        if not verify_message_integrity(raw, self._remote_pwd.as_bytes()):
            return
        var txn = self._pairs[index].txns.pop(txn_index)

        if not success:
            if msg.error_code().or_else(0) == STUN_ERROR_ROLE_CONFLICT:
                self._controlling = not self._controlling
                self._pairs[index].next_check_ms = now_ms
            return

        self._pairs[index].succeeded = True
        self._pairs[index].rtt_ms = now_ms - txn.sent_ms
        if self._selected == index:
            self._touch(now_ms)
            return
        if self._selected >= 0:
            return
        if self._controlling:
            if txn.nominate:
                self._pairs[index].nominated = True
                self._select(index, now_ms)
            else:
                var nominating = False
                for i in range(len(self._pairs)):
                    if self._pairs[i].nominating:
                        nominating = True
                if not nominating:
                    self._pairs[index].nominating = True
                    self._pairs[index].next_check_ms = now_ms
        elif self._pairs[index].nominated:
            self._select(index, now_ms)
