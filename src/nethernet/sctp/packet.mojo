"""SCTP packet framing: common header, CRC32c checksum and chunk TLVs.

An SCTP packet (RFC 9260 section 3) is a 12-byte common header followed by
chunks. Each chunk is a type byte, a flags byte, a 16-bit length that covers
the 4-byte chunk header and the value, and zero padding up to a multiple of 4
bytes. The checksum is the CRC32c of the packet with the checksum field set to
zero, stored least significant byte first.
"""

from ..crypto.crc import crc32c_update
from ..wire import get_u16, get_u32, put_u16, put_u32, put_u8, set_u16

comptime SCTP_HEADER_SIZE = 12
"""The size of the SCTP common header in bytes."""
comptime SCTP_CHUNK_HEADER_SIZE = 4
"""The size of a chunk header in bytes."""
comptime SCTP_MAX_PACKET_SIZE = 65536
"""The largest inbound packet the parser accepts."""

comptime CHUNK_DATA = 0
"""Chunk type of DATA."""
comptime CHUNK_INIT = 1
"""Chunk type of INIT."""
comptime CHUNK_INIT_ACK = 2
"""Chunk type of INIT ACK."""
comptime CHUNK_SACK = 3
"""Chunk type of SACK."""
comptime CHUNK_HEARTBEAT = 4
"""Chunk type of HEARTBEAT."""
comptime CHUNK_HEARTBEAT_ACK = 5
"""Chunk type of HEARTBEAT ACK."""
comptime CHUNK_ABORT = 6
"""Chunk type of ABORT."""
comptime CHUNK_SHUTDOWN = 7
"""Chunk type of SHUTDOWN."""
comptime CHUNK_SHUTDOWN_ACK = 8
"""Chunk type of SHUTDOWN ACK."""
comptime CHUNK_ERROR = 9
"""Chunk type of ERROR."""
comptime CHUNK_COOKIE_ECHO = 10
"""Chunk type of COOKIE ECHO."""
comptime CHUNK_COOKIE_ACK = 11
"""Chunk type of COOKIE ACK."""
comptime CHUNK_SHUTDOWN_COMPLETE = 14
"""Chunk type of SHUTDOWN COMPLETE."""
comptime CHUNK_RECONFIG = 130
"""Chunk type of RE-CONFIG (RFC 6525)."""
comptime CHUNK_FORWARD_TSN = 192
"""Chunk type of FORWARD-TSN (RFC 3758)."""


def pad4(n: Int) -> Int:
    """Rounds a length up to a multiple of 4.

    Args:
        n: The unpadded length.

    Returns:
        The smallest multiple of 4 that is at least `n`.
    """
    return (n + 3) & ~3


def packet_checksum(packet: Span[UInt8, _]) -> UInt32:
    """Computes the CRC32c of a packet as if its checksum field were zero.

    Args:
        packet: The whole SCTP packet, at least 12 bytes long.

    Returns:
        The checksum. Its least significant byte goes first on the wire.
    """
    var zeros = Array[UInt8, 4](fill=0)
    var c = crc32c_update(0xFFFFFFFF, packet[0:8])
    c = crc32c_update(c, Span(zeros))
    c = crc32c_update(c, packet[12 : len(packet)])
    return ~c


def stored_checksum(packet: Span[UInt8, _]) -> UInt32:
    """Reads the checksum field of a packet.

    Args:
        packet: The whole SCTP packet, at least 12 bytes long.

    Returns:
        The checksum carried in the common header.
    """
    return (
        UInt32(packet[8])
        | (UInt32(packet[9]) << 8)
        | (UInt32(packet[10]) << 16)
        | (UInt32(packet[11]) << 24)
    )


def begin_packet(
    mut out: List[UInt8],
    source_port: UInt16,
    destination_port: UInt16,
    verification_tag: UInt32,
):
    """Appends a common header with a zero checksum.

    Append chunks after it and call `finish_packet()` last. `out` must hold
    nothing but this packet.

    Args:
        out: The empty buffer that will hold the packet.
        source_port: The sender's SCTP port.
        destination_port: The receiver's SCTP port.
        verification_tag: The receiver's initiate tag, or 0 for INIT.
    """
    put_u16(out, source_port)
    put_u16(out, destination_port)
    put_u32(out, verification_tag)
    put_u32(out, 0)


def finish_packet(mut out: List[UInt8]):
    """Computes the checksum of a packet and stores it in the header.

    Args:
        out: The packet built with `begin_packet()` and chunk encoders.
    """
    var c = packet_checksum(Span(out))
    out[8] = UInt8(c & 0xFF)
    out[9] = UInt8((c >> 8) & 0xFF)
    out[10] = UInt8((c >> 16) & 0xFF)
    out[11] = UInt8(c >> 24)


def begin_chunk(mut out: List[UInt8], kind: UInt8, flags: UInt8) -> Int:
    """Appends a chunk header with a placeholder length.

    Args:
        out: The buffer to append to.
        kind: The chunk type.
        flags: The chunk flags.

    Returns:
        The offset of the chunk header, to pass to `end_chunk()`.
    """
    var start = len(out)
    put_u8(out, kind)
    put_u8(out, flags)
    put_u16(out, 0)
    return start


def end_chunk(mut out: List[UInt8], start: Int):
    """Patches the length of a chunk and pads it to a multiple of 4 bytes.

    Args:
        out: The buffer holding the chunk.
        start: The offset returned by `begin_chunk()`.
    """
    var length = len(out) - start
    set_u16(out, start + 2, UInt16(length))
    while (len(out) - start) % 4 != 0:
        out.append(0)


struct ChunkRef(ImplicitlyCopyable):
    """The position of one chunk inside a packet."""

    var kind: UInt8
    """The chunk type."""
    var flags: UInt8
    """The chunk flags."""
    var offset: Int
    """The offset of the chunk value in the packet."""
    var length: Int
    """The length of the chunk value, without header or padding."""

    def __init__(out self, kind: UInt8, flags: UInt8, offset: Int, length: Int):
        """Creates a chunk reference.

        Args:
            kind: The chunk type.
            flags: The chunk flags.
            offset: The offset of the chunk value in the packet.
            length: The length of the chunk value.
        """
        self.kind = kind
        self.flags = flags
        self.offset = offset
        self.length = length


struct PacketView(Movable):
    """The common header of a parsed packet and where its chunks are."""

    var source_port: UInt16
    """The sender's SCTP port."""
    var destination_port: UInt16
    """The receiver's SCTP port."""
    var verification_tag: UInt32
    """The verification tag of the packet."""
    var chunks: List[ChunkRef]
    """The chunks in wire order."""

    def __init__(
        out self,
        source_port: UInt16,
        destination_port: UInt16,
        verification_tag: UInt32,
    ):
        """Creates a view with no chunks.

        Args:
            source_port: The sender's SCTP port.
            destination_port: The receiver's SCTP port.
            verification_tag: The verification tag of the packet.
        """
        self.source_port = source_port
        self.destination_port = destination_port
        self.verification_tag = verification_tag
        self.chunks = List[ChunkRef]()


def parse_packet(packet: Span[UInt8, _]) raises -> PacketView:
    """Checks the checksum and the chunk framing of a packet.

    The final chunk may omit its padding; every other chunk must be padded to
    4 bytes.

    Args:
        packet: The whole SCTP packet.

    Returns:
        The header fields and the location of every chunk.

    Raises:
        Error: If the packet is too short or too long, the checksum is wrong,
            or a chunk length is below 4 or runs past the end.
    """
    var size = len(packet)
    if size < SCTP_HEADER_SIZE:
        raise Error("sctp: packet shorter than the common header")
    if size > SCTP_MAX_PACKET_SIZE:
        raise Error("sctp: packet too large")
    if packet_checksum(packet) != stored_checksum(packet):
        raise Error("sctp: checksum mismatch")
    var view = PacketView(
        get_u16(packet, 0), get_u16(packet, 2), get_u32(packet, 4)
    )
    var pos = SCTP_HEADER_SIZE
    while pos < size:
        if size - pos < SCTP_CHUNK_HEADER_SIZE:
            raise Error("sctp: truncated chunk header")
        var length = Int(get_u16(packet, pos + 2))
        if length < SCTP_CHUNK_HEADER_SIZE:
            raise Error("sctp: chunk length below 4")
        if pos + length > size:
            raise Error("sctp: chunk runs past the end of the packet")
        view.chunks.append(
            ChunkRef(
                packet[pos],
                packet[pos + 1],
                pos + SCTP_CHUNK_HEADER_SIZE,
                length - SCTP_CHUNK_HEADER_SIZE,
            )
        )
        var padded = pos + pad4(length)
        if padded > size:
            # Only the last chunk may come without its padding.
            padded = size
        pos = padded
    return view^
