"""The signal wire format, error codes and the `Signaling` trait."""

from ..os.poll import PollSet

comptime SIGNAL_OFFER: StaticString = "CONNECTREQUEST"
"""Carries the offerer's SDP."""
comptime SIGNAL_ANSWER: StaticString = "CONNECTRESPONSE"
"""Carries the answerer's SDP."""
comptime SIGNAL_CANDIDATE: StaticString = "CANDIDATEADD"
"""Carries one trickled ICE candidate."""
comptime SIGNAL_ERROR: StaticString = "CONNECTERROR"
"""Carries a decimal error code; the negotiation is over."""

comptime ERROR_NONE = 0
"""No error."""
comptime ERROR_DESTINATION_NOT_LOGGED_IN = 1
"""The destination is not logged in to the signaling service."""
comptime ERROR_NEGOTIATION_TIMEOUT = 2
"""The negotiation timed out."""
comptime ERROR_WRONG_TRANSPORT_VERSION = 3
"""The peers use different transport versions."""
comptime ERROR_FAILED_TO_CREATE_PEER_CONNECTION = 4
"""The peer connection could not be created."""
comptime ERROR_ICE = 5
"""ICE failed, for example no candidate could be gathered."""
comptime ERROR_CONNECT_REQUEST = 6
"""The offer could not be processed."""
comptime ERROR_CONNECT_RESPONSE = 7
"""The answer could not be processed."""
comptime ERROR_CANDIDATE_ADD = 8
"""A candidate could not be added."""
comptime ERROR_INACTIVITY_TIMEOUT = 9
"""The connection did not open in time after the answer."""
comptime ERROR_FAILED_TO_CREATE_OFFER = 10
"""The offer could not be created."""
comptime ERROR_FAILED_TO_CREATE_ANSWER = 11
"""The answer could not be created."""
comptime ERROR_FAILED_TO_SET_LOCAL_DESCRIPTION = 12
"""The local description could not be applied."""
comptime ERROR_FAILED_TO_SET_REMOTE_DESCRIPTION = 13
"""The remote description was rejected, for example malformed SDP."""
comptime ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE = 14
"""No answer arrived in time."""
comptime ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_ACCEPT = 15
"""The connection did not open in time on the listening side."""
comptime ERROR_INCOMING_CONNECTION_IGNORED = 16
"""The listener ignored the offer."""
comptime ERROR_SIGNALING_PARSING_FAILURE = 17
"""A signal could not be parsed."""
comptime ERROR_SIGNALING_UNKNOWN_ERROR = 18
"""The signaling service reported an unknown error."""
comptime ERROR_SIGNALING_UNICAST_MESSAGE_DELIVERY_FAILED = 19
"""A unicast signal could not be delivered."""
comptime ERROR_SIGNALING_BROADCAST_DELIVERY_FAILED = 20
"""A broadcast signal could not be delivered."""
comptime ERROR_SIGNALING_MESSAGE_DELIVERY_FAILED = 21
"""A signal could not be delivered."""
comptime ERROR_SIGNALING_TURN_AUTH_FAILED = 22
"""Relay credentials could not be obtained."""
comptime ERROR_SIGNALING_FALLBACK_TO_BEST_EFFORT_DELIVERY = 23
"""The signaling service fell back to best-effort delivery."""
comptime ERROR_NO_SIGNALING_CHANNEL = 24
"""No signaling channel is available."""
comptime ERROR_NOT_LOGGED_IN = 25
"""This end is not logged in to the signaling service."""
comptime ERROR_SIGNALING_FAILED_TO_SEND = 26
"""A signal could not be sent."""
comptime ERROR_DATA_CHANNEL_CLOSED = 32
"""A data channel was closed."""
comptime ERROR_INVALID_ARGUMENT = 34
"""An argument was invalid."""
comptime ERROR_GENERIC_FAILURE = 35
"""An unspecified failure."""
comptime ERROR_FAILED_TO_CREATE_IDENTITY_ASSERTION = 36
"""The identity assertion could not be created."""
comptime ERROR_IDENTITY_NOT_ALLOWED = 37
"""The peer's identity assertion was missing or rejected."""


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
        """Creates a signal."""
        self.kind = String(kind)
        self.connection_id = connection_id
        self.data = String(data)
        self.network_id = String(network_id)

    def encode(self) -> String:
        """Formats the signal as `TYPE <connection id> <data>`."""
        return String(t"{self.kind} {self.connection_id} {self.data}")

    def error_code(self) -> Int:
        """Reads the error code of a `CONNECTERROR` signal.

        Like go-nethernet, only the leading decimal digits (with an optional
        minus sign) count; anything else reads as 0.
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
        """Writes the wire text."""
        writer.write(self.encode())


def parse_signal(text: StringSpan, network_id: StringSpan) raises -> Signal:
    """Decodes `TYPE <connection id> <data>`.

    The connection ID is read from its leading decimal digits, so `42junk`
    is 42 and `0x10` is 0, which is what go-nethernet accepts.
    """
    var first = text.find(" ")
    if first <= 0:
        raise Error("signal: missing connection ID")
    var kind = text[byte=0:first]
    var rest = text[byte = first + 1 : text.byte_length()]
    var second = rest.find(" ")
    if second < 0:
        raise Error("signal: missing data")
    var id_text = rest[byte=0:second]
    var data = rest[byte = second + 1 : rest.byte_length()]
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
        """Gets the network ID other peers use to reach this end."""
        ...

    def send_signal(mut self, signal: Signal) raises:
        """Sends a signal to the peer named by `signal.network_id`."""
        ...

    def poll_signal(mut self) -> Optional[Signal]:
        """Takes the next received signal."""
        ...

    def service(mut self, now_ms: Int) raises:
        """Performs pending I/O and periodic work without blocking."""
        ...

    def poll_fd(self) -> Int:
        """Gets a descriptor that becomes readable when `service()` has work."""
        ...

    def trickle(self) -> Bool:
        """Says whether candidates can be signaled after the description."""
        ...

    def add_poll_fds(self, mut set: PollSet):
        """Adds every descriptor `service()` reads from to a `PollSet`.

        The default adds `poll_fd()`. Channels with several sockets override
        this so an event loop wakes for all of them.
        """
        var fd = self.poll_fd()
        if fd >= 0:
            _ = set.add(fd)
