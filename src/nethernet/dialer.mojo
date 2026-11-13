"""Dialing: the offering side of a NetherNet connection."""

from .conn import CONN_STATE_CLOSED, Conn, ConnConfig
from .os.poll import PollSet
from .crypto.p384 import p384_private_key_from_bytes
from .os.random import random_bytes, random_u64
from .os.time import monotonic_ms, unix_time_s
from .sdp.description import Description, parse_description
from .signaling.identity import IDENTITY_DOMAIN_CLIENT, Identity, RemoteIdentity
from .signaling.signal import (
    ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION,
    ERROR_IDENTITY_NOT_ALLOWED,
    ERROR_INACTIVITY_TIMEOUT,
    ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE,
    SIGNAL_ANSWER,
    SIGNAL_CANDIDATE,
    SIGNAL_ERROR,
    SIGNAL_OFFER,
    Signal,
    Signaling,
)

comptime DEFAULT_DIAL_TIMEOUT_MS = 15000
"""How long `dial()` waits for the connection to open."""


struct DialConfig(Copyable):
    """Settings for one dial attempt."""

    var conn: ConnConfig
    """The settings of the connection being created."""
    var connection_id: UInt64
    """The connection identifier to use; 0 picks a random one."""
    var timeout_ms: Int
    """How long to wait for the connection to open."""
    var anonymous: Bool
    """Whether to send the offer without an identity assertion.

    Listeners reject anonymous offers unless configured to allow them.
    """
    var identity_key: List[UInt8]
    """The 48-byte P-384 identity key; empty generates a throwaway key."""
    var identity_domain: String
    """The identity-provider domain announced with the assertion."""
    var allow_identityless_server: Bool
    """Whether to accept an answer that carries no identity assertion."""

    def __init__(out self):
        """Creates the default configuration."""
        self.conn = ConnConfig()
        self.connection_id = 0
        self.timeout_ms = DEFAULT_DIAL_TIMEOUT_MS
        self.anonymous = False
        self.identity_key = List[UInt8]()
        self.identity_domain = IDENTITY_DOMAIN_CLIENT
        self.allow_identityless_server = False


struct DialAttempt(Movable):
    """A dial in progress, for callers that drive their own event loop.

    Create it, then call `poll()` until `is_done()`; take the result with
    `finish()`. `dial()` wraps exactly this.
    """

    var _conn: Conn
    var _network_id: String
    var _connection_id: UInt64
    var _deadline_ms: Int
    var _answered: Bool
    var _error: String
    var _allow_identityless_server: Bool

    def __init__[
        S: Signaling
    ](
        out self, mut signaling: S, network_id: StringSpan, config: DialConfig
    ) raises:
        """Creates the connection and signals the offer.

        Parameters:
            S: The signaling channel type.

        Args:
            signaling: The channel to the peer.
            network_id: The network ID to dial.
            config: The dial settings.

        Raises:
            Error: If the socket cannot be created or the offer cannot be
                signaled.
        """
        var connection_id = config.connection_id
        if connection_id == 0:
            connection_id = random_u64()
        var conn = Conn(True, connection_id, config.conn)
        conn.set_remote_network_id(network_id)
        if not config.anonymous:
            var key = config.identity_key.copy()
            if len(key) == 0:
                var seed = random_bytes(56)
                var fresh = p384_private_key_from_bytes(Span(seed))
                key = List[UInt8](Span(fresh))
            var identity = Identity.self_signed(
                Span(key), config.identity_domain, unix_time_s(), False
            )
            conn.set_local_identity(
                identity.sign("sha-256", conn.local_fingerprint())
            )
        self._connection_id = connection_id
        self._network_id = String(network_id)
        self._conn = conn^
        self._deadline_ms = monotonic_ms() + config.timeout_ms
        self._answered = False
        self._error = String()
        self._allow_identityless_server = config.allow_identityless_server
        var trickle = signaling.trickle()
        var offer = self._conn.local_description(not trickle)
        signaling.send_signal(
            Signal(
                SIGNAL_OFFER, self._connection_id, offer.encode(), network_id
            )
        )
        if trickle:
            signaling.send_signal(
                Signal(
                    SIGNAL_CANDIDATE,
                    self._connection_id,
                    self._conn.local_candidate_signal(),
                    network_id,
                )
            )

    def fd(self) -> Int:
        """Gets the connection's socket descriptor.

        Returns:
            The file descriptor to wait on.
        """
        return self._conn.fd()

    def next_timeout(self) -> Int:
        """Computes when `poll()` next has timer work to do.

        Returns:
            An absolute monotonic time in milliseconds.
        """
        return min(self._conn.next_timeout(), self._deadline_ms)

    def is_done(self) -> Bool:
        """Checks whether the attempt has succeeded or failed.

        Returns:
            `True` once `finish()` can be called.
        """
        return (
            self._conn.is_open()
            or self._conn.is_closed()
            or self._error.byte_length() > 0
        )

    def _check_identity(mut self, remote: Description) raises:
        """Verifies the answer's identity assertion, like go-nethernet's
        default: the token must be signed by the key it presents, and that
        key must have signed the answer's DTLS fingerprint."""
        if remote.identity.byte_length() == 0:
            if self._allow_identityless_server:
                return
            raise Error("identity: the server sent no identity assertion")
        var identity = RemoteIdentity.parse(remote.identity)
        var key = identity.public_key(True, unix_time_s())
        identity.verify(
            remote.fingerprint_algorithm, remote.fingerprint, Span(key)
        )
        self._conn.set_peer_public_key(Span(key))

    def _send_error[S: Signaling](self, mut signaling: S, code: Int):
        try:
            signaling.send_signal(
                Signal(
                    SIGNAL_ERROR,
                    self._connection_id,
                    String(code),
                    self._network_id,
                )
            )
        except:
            pass

    def poll[S: Signaling](mut self, mut signaling: S, now_ms: Int) raises:
        """Processes signals for this connection and advances it.

        Signals for other connections are discarded, so a signaling channel
        should serve one dial at a time.

        Parameters:
            S: The signaling channel type.

        Args:
            signaling: The channel to the peer.
            now_ms: The current monotonic time in milliseconds.

        Raises:
            Error: If the signaling channel or the socket fails.
        """
        if self.is_done():
            return
        signaling.service(now_ms)
        while True:
            var next = signaling.poll_signal()
            if next is None:
                break
            var signal = next.take()
            if (
                signal.connection_id != self._connection_id
                or signal.network_id != self._network_id
            ):
                continue
            if signal.kind == SIGNAL_ANSWER:
                if self._answered:
                    continue
                var remote: Description
                try:
                    remote = parse_description(signal.data)
                except e:
                    self._send_error(
                        signaling, ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION
                    )
                    self._error = String(t"invalid answer: {e}")
                    return
                try:
                    self._check_identity(remote)
                except e:
                    self._send_error(signaling, ERROR_IDENTITY_NOT_ALLOWED)
                    self._error = String(t"{e}")
                    return
                try:
                    self._conn.set_remote_description(remote)
                    self._answered = True
                except e:
                    self._send_error(
                        signaling, ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION
                    )
                    self._error = String(t"invalid answer: {e}")
                    return
            elif signal.kind == SIGNAL_CANDIDATE:
                self._conn.add_remote_candidate(signal.data)
            elif signal.kind == SIGNAL_ERROR:
                self._error = String(
                    t"peer rejected the connection with error code"
                    t" {signal.error_code()}"
                )
                return
        self._conn.poll(now_ms)
        if self._conn.is_open() or self._conn.is_closed():
            return
        if now_ms >= self._deadline_ms:
            if self._answered:
                self._send_error(signaling, ERROR_INACTIVITY_TIMEOUT)
                self._error = "timed out establishing the connection"
            else:
                self._send_error(
                    signaling, ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE
                )
                self._error = "timed out waiting for the answer"

    def finish(deinit self) raises -> Conn:
        """Takes the open connection, or reports why the dial failed.

        Returns:
            The open connection.

        Raises:
            Error: If the attempt failed or is not finished.
        """
        if self._error.byte_length() > 0:
            self._conn.abort()
            raise Error(t"dial failed: {self._error}")
        if self._conn.is_closed():
            raise Error(t"dial failed: {self._conn.close_reason()}")
        if not self._conn.is_open():
            self._conn.abort()
            raise Error("dial is not finished")
        return self._conn^


def dial[
    S: Signaling
](mut signaling: S, network_id: StringSpan, config: DialConfig) raises -> Conn:
    """Connects to the peer with the given network ID, blocking until open.

    Parameters:
        S: The signaling channel type.

    Args:
        signaling: The channel to the peer.
        network_id: The network ID to dial.
        config: The dial settings.

    Returns:
        The open connection.

    Raises:
        Error: If the peer rejects the connection, negotiation times out, or
            a socket fails.
    """
    var attempt = DialAttempt(signaling, network_id, config)
    while not attempt.is_done():
        var now = monotonic_ms()
        attempt.poll(signaling, now)
        if attempt.is_done():
            break
        var wait = max(0, min(50, attempt.next_timeout() - monotonic_ms()))
        var set = PollSet()
        _ = set.add(attempt.fd())
        signaling.add_poll_fds(set)
        _ = set.wait(wait)
    return attempt^.finish()
