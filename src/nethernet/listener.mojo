"""Listening: the answering side of NetherNet connections."""

from .conn import Conn, ConnConfig
from .os.poll import PollSet
from .os.time import monotonic_ms
from .sdp.description import parse_description
from .signaling.signal import (
    ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION,
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

    def __init__(out self):
        """Creates the default configuration."""
        self.conn = ConnConfig()
        self.negotiation_timeout_ms = DEFAULT_NEGOTIATION_TIMEOUT_MS


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

    Parameters:
        S: The signaling channel type.
    """

    var _signaling: Self.S
    var _config: ListenConfig
    var _pending: List[_Pending]
    var _ready: List[Conn]

    def __init__(out self, var signaling: Self.S, config: ListenConfig):
        """Creates a listener on a signaling channel.

        Args:
            signaling: The channel offers arrive on; the listener takes it.
            config: The listener settings.
        """
        self._signaling = signaling^
        self._config = config.copy()
        self._pending = List[_Pending]()
        self._ready = List[Conn]()

    def signaling(mut self) -> ref[self._signaling] Self.S:
        """Borrows the signaling channel, for example to set server data.

        Returns:
            A reference to the channel the listener owns.
        """
        return self._signaling

    def network_id(self) -> String:
        """Gets the network ID peers dial to reach this listener.

        Returns:
            The signaling channel's local network ID.
        """
        return self._signaling.network_id()

    def pending_count(self) -> Int:
        """Counts the connections still being negotiated.

        Returns:
            The number of incoming connections not yet open.
        """
        return len(self._pending)

    def next_timeout(self) -> Int:
        """Computes when `poll()` next has timer work to do.

        Returns:
            An absolute monotonic time in milliseconds.
        """
        var t = _NEVER
        for i in range(len(self._pending)):
            t = min(t, self._pending[i].conn.next_timeout())
            t = min(t, self._pending[i].deadline_ms)
        return t

    def _send(mut self, kind: StringSpan, id: UInt64, data: StringSpan, to: StringSpan):
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
        try:
            var remote = parse_description(signal.data)
            var conn = Conn(False, signal.connection_id, self._config.conn)
            conn.set_remote_network_id(signal.network_id)
            conn.set_remote_description(remote)
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
                String(ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION),
                signal.network_id,
            )

    def poll(mut self, now_ms: Int) raises:
        """Processes signals and advances every pending negotiation.

        Parameters:
            now_ms: The current monotonic time in milliseconds.

        Args:
            now_ms: The current monotonic time in milliseconds.

        Raises:
            Error: If the signaling channel fails.
        """
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
        """Takes a connection that finished opening, without blocking.

        Returns:
            An open connection, or `None` if none is ready.
        """
        if len(self._ready) == 0:
            return None
        return self._ready.pop(0)

    def accept(mut self, timeout_ms: Int) raises -> Optional[Conn]:
        """Waits for the next incoming connection to open.

        Args:
            timeout_ms: The longest time to wait; negative waits forever.

        Returns:
            An open connection, or `None` if the timeout passes first.

        Raises:
            Error: If the signaling channel fails.
        """
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
            var signaling_fd = self._signaling.poll_fd()
            if signaling_fd >= 0:
                _ = set.add(signaling_fd)
            for i in range(len(self._pending)):
                _ = set.add(self._pending[i].conn.fd())
            _ = set.wait(wait)
