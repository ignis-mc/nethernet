"""Listening: the answering side of NetherNet connections."""

from .conn import Conn, ConnConfig
from .crypto.p384 import p384_private_key_from_bytes
from .os.poll import PollSet
from .os.random import random_bytes
from .os.time import monotonic_ms, unix_time_s
from .sdp.description import Description, parse_description
from .signaling.identity import IDENTITY_DOMAIN_SERVER, Identity, RemoteIdentity
from .signaling.signal import (
    ERROR_FAILED_TO_CREATE_IDENTITY_ASSERTION,
    ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION,
    ERROR_IDENTITY_NOT_ALLOWED,
    ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_ACCEPT,
    SIGNAL_ANSWER,
    SIGNAL_CANDIDATE,
    SIGNAL_ERROR,
    SIGNAL_OFFER,
    Signal,
    Signaling,
)

comptime DEFAULT_NEGOTIATION_TIMEOUT_MS = 15000
"""How long an incoming connection may take to open before it is dropped."""
comptime MAX_PENDING_NEGOTIATIONS = 64
"""The most incoming connections negotiated at the same time."""

comptime _NEVER = 0x3FFF_FFFF_FFFF_FFFF


struct ListenConfig(Copyable):
    """Settings for a `Listener`."""

    var conn: ConnConfig
    """The settings of every accepted connection."""
    var negotiation_timeout_ms: Int
    """How long an incoming connection may take to open."""
    var allow_anonymous: Bool
    """Whether to accept offers that carry no identity assertion."""
    var identity_key: List[UInt8]
    """The listener's 48-byte P-384 identity key; empty generates one.

    Clients may pin this key on first use, so a long-lived server should
    persist it.
    """
    var identity_domain: String
    """The identity-provider domain announced with each answer."""

    def __init__(out self):
        """Creates the default configuration."""
        self.conn = ConnConfig()
        self.negotiation_timeout_ms = DEFAULT_NEGOTIATION_TIMEOUT_MS
        self.allow_anonymous = False
        self.identity_key = List[UInt8]()
        self.identity_domain = IDENTITY_DOMAIN_SERVER


struct _Pending(Movable):
    var conn: Conn
    var network_id: String
    var connection_id: UInt64
    var deadline_ms: Int

    def __init__(
        out self,
        var conn: Conn,
        network_id: StringSpan,
        connection_id: UInt64,
        deadline_ms: Int,
    ):
        self.conn = conn^
        self.network_id = String(network_id)
        self.connection_id = connection_id
        self.deadline_ms = deadline_ms

    def into_conn(deinit self) -> Conn:
        return self.conn^


struct Listener[S: Signaling](Movable):
    """Accepts NetherNet connections offered over a signaling channel.

    The listener owns its signaling channel. It is polled: call `poll()`
    regularly (or `accept()`, which does) so that negotiations advance.
    """

    var _signaling: Self.S
    var _config: ListenConfig
    var _pending: List[_Pending]
    var _ready: List[Conn]
    var _identity_key: List[UInt8]

    def __init__(out self, var signaling: Self.S, config: ListenConfig) raises:
        """Creates a listener on a signaling channel."""
        var key = config.identity_key.copy()
        if len(key) == 0:
            var seed = random_bytes(56)
            var fresh = p384_private_key_from_bytes(Span(seed))
            key = List[UInt8](Span(fresh))
        self._signaling = signaling^
        self._config = config.copy()
        self._pending = List[_Pending]()
        self._ready = List[Conn]()
        self._identity_key = key^

    def identity_key(self) -> List[UInt8]:
        """Gets the P-384 identity key answers are signed with."""
        return self._identity_key.copy()

    def signaling(mut self) -> ref[self._signaling] Self.S:
        """Borrows the signaling channel, for example to set server data."""
        return self._signaling

    def network_id(self) -> String:
        """Gets the network ID peers dial to reach this listener."""
        return self._signaling.network_id()

    def pending_count(self) -> Int:
        """Counts the connections still being negotiated."""
        return len(self._pending)

    def add_poll_fds(self, mut set: PollSet):
        """Adds every descriptor `poll()` reads from to a `PollSet`.

        That is the signaling channel's descriptor and the socket of every
        connection still being negotiated. An event loop that waits on these
        (and until `next_timeout()`) reacts to each handshake packet at once
        instead of on its next tick.
        """
        self._signaling.add_poll_fds(set)
        for i in range(len(self._pending)):
            _ = set.add(self._pending[i].conn.fd())

    def next_timeout(self) -> Int:
        """Computes when `poll()` next has timer work to do."""
        var t = _NEVER
        for i in range(len(self._pending)):
            t = min(t, self._pending[i].conn.next_timeout())
            t = min(t, self._pending[i].deadline_ms)
        return t

    def _send(
        mut self, kind: StringSpan, id: UInt64, data: StringSpan, to: StringSpan
    ):
        try:
            self._signaling.send_signal(Signal(kind, id, data, to))
        except:
            pass

    def _find(self, network_id: StringSpan, connection_id: UInt64) -> Int:
        for i in range(len(self._pending)):
            if (
                self._pending[i].connection_id == connection_id
                and self._pending[i].network_id == network_id
            ):
                return i
        return -1

    def _on_offer(mut self, signal: Signal, now_ms: Int):
        if self._find(signal.network_id, signal.connection_id) >= 0:
            return
        if len(self._pending) >= MAX_PENDING_NEGOTIATIONS:
            return
        var remote: Description
        try:
            remote = parse_description(signal.data)
        except:
            self._send(
                SIGNAL_ERROR,
                signal.connection_id,
                String(ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION),
                signal.network_id,
            )
            return
        # Like go-nethernet's default: the token's time claims are checked
        # and its key must have signed the offer's DTLS fingerprint.
        var peer_key = List[UInt8]()
        try:
            if remote.identity.byte_length() == 0:
                if not self._config.allow_anonymous:
                    raise Error("identity: anonymous offers are not allowed")
            else:
                var identity = RemoteIdentity.parse(remote.identity)
                peer_key = identity.public_key(False, unix_time_s())
                identity.verify(
                    remote.fingerprint_algorithm,
                    remote.fingerprint,
                    Span(peer_key),
                )
        except:
            self._send(
                SIGNAL_ERROR,
                signal.connection_id,
                String(ERROR_IDENTITY_NOT_ALLOWED),
                signal.network_id,
            )
            return
        var code = ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION
        try:
            var conn = Conn(False, signal.connection_id, self._config.conn)
            conn.set_remote_network_id(signal.network_id)
            conn.set_remote_description(remote)
            if len(peer_key) > 0:
                conn.set_peer_public_key(Span(peer_key))
            code = ERROR_FAILED_TO_CREATE_IDENTITY_ASSERTION
            var local_identity = Identity.self_signed(
                Span(self._identity_key),
                self._config.identity_domain,
                unix_time_s(),
                True,
            )
            conn.set_local_identity(
                local_identity.sign("sha-256", conn.local_fingerprint())
            )
            code = ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION
            var trickle = self._signaling.trickle()
            var answer = conn.local_description(not trickle)
            self._signaling.send_signal(
                Signal(
                    SIGNAL_ANSWER,
                    signal.connection_id,
                    answer.encode(),
                    signal.network_id,
                )
            )
            if trickle:
                self._signaling.send_signal(
                    Signal(
                        SIGNAL_CANDIDATE,
                        signal.connection_id,
                        conn.local_candidate_signal(),
                        signal.network_id,
                    )
                )
            self._pending.append(
                _Pending(
                    conn^,
                    signal.network_id,
                    signal.connection_id,
                    now_ms + self._config.negotiation_timeout_ms,
                )
            )
        except:
            self._send(
                SIGNAL_ERROR,
                signal.connection_id,
                String(code),
                signal.network_id,
            )

    def poll(mut self, now_ms: Int) raises:
        """Processes signals and advances every pending negotiation."""
        self._signaling.service(now_ms)
        while True:
            var next = self._signaling.poll_signal()
            if next is None:
                break
            var signal = next.take()
            if signal.kind == SIGNAL_OFFER:
                self._on_offer(signal, now_ms)
                continue
            var index = self._find(signal.network_id, signal.connection_id)
            if index < 0:
                continue
            if signal.kind == SIGNAL_CANDIDATE:
                self._pending[index].conn.add_remote_candidate(signal.data)
            elif signal.kind == SIGNAL_ERROR:
                var dropped = self._pending.pop(index)
                dropped.conn.abort()
        var i = 0
        while i < len(self._pending):
            try:
                self._pending[i].conn.poll(now_ms)
            except:
                self._pending[i].conn.abort()
            if self._pending[i].conn.is_open():
                var done = self._pending.pop(i)
                self._ready.append(done^.into_conn())
                continue
            if self._pending[i].conn.is_closed():
                _ = self._pending.pop(i)
                continue
            if now_ms >= self._pending[i].deadline_ms:
                var late = self._pending.pop(i)
                self._send(
                    SIGNAL_ERROR,
                    late.connection_id,
                    String(ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_ACCEPT),
                    late.network_id,
                )
                late.conn.abort()
                continue
            i += 1

    def try_accept(mut self) -> Optional[Conn]:
        """Takes a connection that finished opening, without blocking."""
        if len(self._ready) == 0:
            return None
        return self._ready.pop(0)

    def accept(mut self, timeout_ms: Int) raises -> Optional[Conn]:
        """Waits for the next incoming connection to open."""
        var deadline = _NEVER
        if timeout_ms >= 0:
            deadline = monotonic_ms() + timeout_ms
        while True:
            var now = monotonic_ms()
            self.poll(now)
            if len(self._ready) > 0:
                return self._ready.pop(0)
            if now >= deadline:
                return None
            var wait = max(
                0, min(min(50, deadline - now), self.next_timeout() - now)
            )
            var set = PollSet()
            self.add_poll_fds(set)
            _ = set.wait(wait)
