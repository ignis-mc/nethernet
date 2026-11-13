"""The Data Channel Establishment Protocol (RFC 8832) and NetherNet's channels.

NetherNet opens exactly two in-band channels, always from the dialing side:
`ReliableDataChannel` (ordered, reliable) carries game packets, and
`UnreliableDataChannel` (unordered, no retransmissions) exists but is rarely
used.
"""

from ..wire import Reader, put_bytes, put_u16, put_u32, put_u8

comptime PPID_DCEP = 50
"""Payload protocol identifier of DCEP messages."""
comptime PPID_STRING = 51
"""Payload protocol identifier of UTF-8 messages."""
comptime PPID_BINARY = 53
"""Payload protocol identifier of binary messages; the one NetherNet uses."""
comptime PPID_STRING_EMPTY = 56
"""Payload protocol identifier of an empty UTF-8 message."""
comptime PPID_BINARY_EMPTY = 57
"""Payload protocol identifier of an empty binary message."""

comptime DCEP_ACK = 0x02
"""Message type of DATA_CHANNEL_ACK."""
comptime DCEP_OPEN = 0x03
"""Message type of DATA_CHANNEL_OPEN."""

comptime CHANNEL_RELIABLE = 0x00
"""Ordered, fully reliable."""
comptime CHANNEL_RELIABLE_UNORDERED = 0x80
"""Unordered, fully reliable."""
comptime CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01
"""Ordered, limited number of retransmissions."""
comptime CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81
"""Unordered, limited number of retransmissions."""

comptime RELIABLE_LABEL: StaticString = "ReliableDataChannel"
"""Label of the ordered, reliable NetherNet channel."""
comptime UNRELIABLE_LABEL: StaticString = "UnreliableDataChannel"
"""Label of the unordered, lossy NetherNet channel."""

comptime _DEFAULT_PRIORITY = 256


struct ChannelOpen(Copyable):
    """A DATA_CHANNEL_OPEN message."""

    var channel_type: UInt8
    """One of the `CHANNEL_*` constants."""
    var priority: UInt16
    """The channel priority."""
    var reliability: UInt32
    """Retransmission count or lifetime, depending on the channel type."""
    var label: String
    """The channel label."""
    var protocol: String
    """The sub-protocol name, empty for NetherNet."""

    def __init__(
        out self, channel_type: UInt8, reliability: UInt32, label: StringSpan
    ):
        """Creates an open request with the default priority.

        Args:
            channel_type: One of the `CHANNEL_*` constants.
            reliability: The reliability parameter.
            label: The channel label.
        """
        self.channel_type = channel_type
        self.priority = _DEFAULT_PRIORITY
        self.reliability = reliability
        self.label = String(label)
        self.protocol = String()

    @staticmethod
    def reliable() -> ChannelOpen:
        """Describes NetherNet's `ReliableDataChannel`.

        Returns:
            The open request for the ordered, reliable channel.
        """
        return ChannelOpen(CHANNEL_RELIABLE, 0, RELIABLE_LABEL)

    @staticmethod
    def unreliable() -> ChannelOpen:
        """Describes NetherNet's `UnreliableDataChannel`.

        Returns:
            The open request for the unordered channel with no
            retransmissions.
        """
        return ChannelOpen(
            CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED, 0, UNRELIABLE_LABEL
        )

    def is_unordered(self) -> Bool:
        """Checks whether messages on the channel may arrive out of order.

        Returns:
            `True` if the unordered bit of the channel type is set.
        """
        return (self.channel_type & 0x80) != 0

    def max_retransmits(self) -> Int:
        """Gets the retransmission limit for sending on this channel.

        Returns:
            The limit for retransmission-limited channels, or -1 for fully
            reliable channels (and for lifetime-limited ones, which this
            library treats as reliable).
        """
        if (self.channel_type & 0x7F) == CHANNEL_PARTIAL_RELIABLE_REXMIT:
            return Int(self.reliability)
        return -1

    def encode(self, mut out: List[UInt8]):
        """Appends the encoded message.

        Args:
            out: The buffer to append to.
        """
        put_u8(out, DCEP_OPEN)
        put_u8(out, self.channel_type)
        put_u16(out, self.priority)
        put_u32(out, self.reliability)
        put_u16(out, UInt16(self.label.byte_length()))
        put_u16(out, UInt16(self.protocol.byte_length()))
        put_bytes(out, self.label.as_bytes())
        put_bytes(out, self.protocol.as_bytes())

    @staticmethod
    def decode(data: Span[UInt8, _]) raises -> ChannelOpen:
        """Decodes a DATA_CHANNEL_OPEN message.

        Args:
            data: The whole DCEP message.

        Returns:
            The decoded message.

        Raises:
            Error: If the message is not an OPEN or its lengths are wrong.
        """
        var r = Reader(data)
        if r.u8() != DCEP_OPEN:
            raise Error("DCEP: not a DATA_CHANNEL_OPEN message")
        var channel_type = r.u8()
        var priority = r.u16()
        var reliability = r.u32()
        var label_len = Int(r.u16())
        var protocol_len = Int(r.u16())
        var label = r.bytes(label_len)
        var protocol = r.bytes(protocol_len)
        if not r.at_end():
            raise Error("DCEP: trailing bytes after DATA_CHANNEL_OPEN")
        var open = ChannelOpen(
            channel_type, reliability, String(from_utf8=label)
        )
        open.priority = priority
        open.protocol = String(from_utf8=protocol)
        return open^


def is_dcep_ack(data: Span[UInt8, _]) -> Bool:
    """Checks whether a DCEP message is a DATA_CHANNEL_ACK.

    Args:
        data: The whole DCEP message.

    Returns:
        `True` if the first byte is the ACK type.
    """
    return len(data) >= 1 and data[0] == DCEP_ACK


def encode_dcep_ack(mut out: List[UInt8]):
    """Appends a DATA_CHANNEL_ACK message.

    Args:
        out: The buffer to append to.
    """
    put_u8(out, DCEP_ACK)
