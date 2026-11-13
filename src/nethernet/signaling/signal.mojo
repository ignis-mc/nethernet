"""The signal wire format, error codes and the `Signaling` trait."""

comptime SIGNAL_OFFER: StaticString = "CONNECTREQUEST"
"""Carries the offerer's SDP."""
comptime SIGNAL_ANSWER: StaticString = "CONNECTRESPONSE"
"""Carries the answerer's SDP."""
comptime SIGNAL_CANDIDATE: StaticString = "CANDIDATEADD"
"""Carries one trickled ICE candidate."""
comptime SIGNAL_ERROR: StaticString = "CONNECTERROR"
"""Carries a decimal error code; the negotiation is over."""

comptime ERROR_NONE = 0
comptime ERROR_DESTINATION_NOT_LOGGED_IN = 1
comptime ERROR_NEGOTIATION_TIMEOUT = 2
comptime ERROR_WRONG_TRANSPORT_VERSION = 3
comptime ERROR_FAILED_TO_CREATE_PEER_CONNECTION = 4
comptime ERROR_ICE = 5
comptime ERROR_CONNECT_REQUEST = 6
comptime ERROR_CONNECT_RESPONSE = 7
comptime ERROR_CANDIDATE_ADD = 8
comptime ERROR_INACTIVITY_TIMEOUT = 9
comptime ERROR_FAILED_TO_CREATE_OFFER = 10
comptime ERROR_FAILED_TO_CREATE_ANSWER = 11
comptime ERROR_FAILED_TO_SET_LOCAL_DESCRIPTION = 12
comptime ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION = 13
comptime ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE = 14
comptime ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_ACCEPT = 15
comptime ERROR_INCOMING_CONNECTION_IGNORED = 16
comptime ERROR_SIGNALING_PARSING_FAILURE = 17
comptime ERROR_SIGNALING_UNKNOWN_ERROR = 18
comptime ERROR_SIGNALING_UNICAST_MESSAGE_DELIVERY_FAILED = 19
comptime ERROR_SIGNALING_BROADCAST_DELIVERY_FAILED = 20
comptime ERROR_SIGNALING_MESSAGE_DELIVERY_FAILED = 21
comptime ERROR_SIGNALING_TURN_AUTH_FAILED = 22
comptime ERROR_SIGNALING_FALLBACK_TO_BEST_EFFORT_DELIVERY = 23
comptime ERROR_NO_SIGNALING_CHANNEL = 24
comptime ERROR_NOT_LOGGED_IN = 25
comptime ERROR_SIGNALING_FAILED_TO_SEND = 26
comptime ERROR_DATA_CHANNEL_CLOSED = 32
comptime ERROR_INVALID_ARGUMENT = 34
comptime ERROR_GENERIC_FAILURE = 35
comptime ERROR_FAILED_TO_CREATE_IDENTITY_ASSERTION = 36
comptime ERROR_IDENTITY_NOT_ALLOWED = 37


struct Signal(Copyable, Writable):
    """One signaling message."""

    var kind: String
    """One of the `SIGNAL_*` type names."""
    var connection_id: UInt64
    """The connection this signal belongs to, chosen by the offerer."""
    var data: String
    """The SDP, the candidate line or the decimal error code."""
    var network_id: String
    """The peer's network ID: the sender on receipt, the recipient on send.

    Routing information only; it is not part of the encoded signal.
    """

    def __init__(
        out self,
        kind: StringSpan,
        connection_id: UInt64,
        data: StringSpan,
        network_id: StringSpan,
    ):
        """Creates a signal.

        Args:
            kind: One of the `SIGNAL_*` type names.
            connection_id: The connection identifier.
            data: The payload.
            network_id: The peer's network ID.
        """
        self.kind = String(kind)
        self.connection_id = connection_id
        self.data = String(data)
        self.network_id = String(network_id)

    def encode(self) -> String:
        """Formats the signal as `TYPE <connection id> <data>`.

        Returns:
            The wire text.
        """
        return String(t"{self.kind} {self.connection_id} {self.data}")

    def error_code(self) -> Int:
        """Reads the error code of a `CONNECTERROR` signal.

        Like go-nethernet, only the leading decimal digits (with an optional
        minus sign) count; anything else reads as 0.

        Returns:
            The signed 32-bit error code.
        """
        var bytes = self.data.as_bytes()
        var i = 0
        var negative = False
        if len(bytes) > 0 and bytes[0] == 0x2D:
            negative = True
            i = 1
        var v = 0
        while i < len(bytes) and bytes[i] >= 0x30 and bytes[i] <= 0x39:
            v = v * 10 + Int(bytes[i] - 0x30)
            if v > 0x7FFF_FFFF:
                return 0
            i += 1
        return -v if negative else v

    def write_to(self, mut writer: Some[Writer]):
        """Writes the wire text.

        Args:
            writer: The destination.
        """
        writer.write(self.encode())


def parse_signal(text: StringSpan, network_id: StringSpan) raises -> Signal:
    """Decodes `TYPE <connection id> <data>`.

    The connection ID is read from its leading decimal digits, so `42junk`
    is 42 and `0x10` is 0, which is what go-nethernet accepts.

    Args:
        text: The wire text.
        network_id: The network ID of the sender, recorded in the result.

    Returns:
        The decoded signal.

    Raises:
        Error: If there are fewer than three space-separated parts, the type
            is unknown, or the connection ID is empty, signed or overflows.
    """
    var first = text.find(" ")
    if first <= 0:
        raise Error("signal: missing connection ID")
    var kind = text[byte=0:first]
    var rest = text[byte=first + 1 : text.byte_length()]
    var second = rest.find(" ")
    if second < 0:
        raise Error("signal: missing data")
    var id_text = rest[byte=0:second]
    var data = rest[byte=second + 1 : rest.byte_length()]
    if (
        kind != SIGNAL_OFFER
        and kind != SIGNAL_ANSWER
        and kind != SIGNAL_CANDIDATE
        and kind != SIGNAL_ERROR
    ):
        raise Error("signal: unknown type")
    var id_bytes = id_text.as_bytes()
    if len(id_bytes) == 0:
        raise Error("signal: empty connection ID")
    if id_bytes[0] < 0x30 or id_bytes[0] > 0x39:
        raise Error("signal: invalid connection ID")
    var id = UInt64(0)
    for c in id_bytes:
        if c < 0x30 or c > 0x39:
            break
        var digit = UInt64(c - 0x30)
        if id > (0xFFFF_FFFF_FFFF_FFFF - digit) // 10:
            raise Error("signal: connection ID overflows")
        id = id * 10 + digit
    return Signal(kind, id, data, network_id)


trait Signaling(Deinitable, Movable):
    """A channel that carries signals to and from peers by network ID.

    Implementations are polled: nothing here blocks. The transport calls
    `service()` regularly (at least whenever `poll_fd()` is readable) and then
    drains `poll_signal()`.
    """

    def network_id(self) -> String:
        """Gets the network ID other peers use to reach this end.

        Returns:
            The local network ID.
        """
        ...

    def send_signal(mut self, signal: Signal) raises:
        """Sends a signal to the peer named by `signal.network_id`.

        Args:
            signal: The signal to deliver.

        Raises:
            Error: If the peer is unknown or the channel cannot send.
        """
        ...

    def poll_signal(mut self) -> Optional[Signal]:
        """Takes the next received signal.

        Returns:
            A signal whose `network_id` names the sender, or `None`.
        """
        ...

    def service(mut self, now_ms: Int) raises:
        """Performs pending I/O and periodic work without blocking.

        Args:
            now_ms: The current monotonic time in milliseconds.

        Raises:
            Error: If the channel has failed.
        """
        ...

    def poll_fd(self) -> Int:
        """Gets a descriptor that becomes readable when `service()` has work.

        Returns:
            A file descriptor, or -1 if there is none.
        """
        ...

    def trickle(self) -> Bool:
        """Says whether candidates can be signaled after the description.

        Returns:
            `False` if every candidate must be embedded in the SDP.
        """
        ...
