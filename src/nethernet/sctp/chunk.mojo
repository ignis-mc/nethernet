"""Typed encoders and decoders for the SCTP chunks used by data channels.

Decoders take the chunk value located by `parse_packet()` and raise on
malformed input. Encoders append one complete, padded chunk to a caller-owned
buffer. Covered here: RFC 9260 INIT, INIT ACK, COOKIE ECHO, COOKIE ACK, DATA,
SACK, HEARTBEAT, HEARTBEAT ACK, SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE and
RFC 3758 FORWARD-TSN. ABORT and ERROR are in `cause`, RE-CONFIG in
`reconfig`.
"""

from ..wire import Reader, get_u16, get_u32, put_bytes, put_u16, put_u32
from .packet import (
    CHUNK_COOKIE_ACK,
    CHUNK_COOKIE_ECHO,
    CHUNK_DATA,
    CHUNK_FORWARD_TSN,
    CHUNK_SACK,
    CHUNK_SHUTDOWN,
    CHUNK_SHUTDOWN_ACK,
    CHUNK_SHUTDOWN_COMPLETE,
    Tlv,
    begin_chunk,
    begin_param,
    end_chunk,
    end_param,
    parse_tlvs,
)

comptime DATA_FLAG_END = 0x01
"""DATA flag: last fragment of a user message."""
comptime DATA_FLAG_BEGIN = 0x02
"""DATA flag: first fragment of a user message."""
comptime DATA_FLAG_UNORDERED = 0x04
"""DATA flag: unordered delivery; the stream sequence number is unused."""
comptime DATA_FLAG_IMMEDIATE = 0x08
"""DATA flag: the sender asks for a SACK without delay (RFC 7053)."""
comptime DATA_CHUNK_OVERHEAD = 16
"""Bytes a DATA chunk adds around its payload, before padding."""

comptime PARAM_HEARTBEAT_INFO = 1
"""Parameter type of Heartbeat Info."""
comptime PARAM_STATE_COOKIE = 7
"""Parameter type of State Cookie."""
comptime PARAM_UNRECOGNIZED = 8
"""Parameter type of Unrecognized Parameter."""
comptime PARAM_SUPPORTED_EXTENSIONS = 0x8008
"""Parameter type of Supported Extensions (RFC 5061)."""
comptime PARAM_FORWARD_TSN_SUPPORTED = 0xC000
"""Parameter type of Forward-TSN-Supported (RFC 3758)."""


struct InitChunk(Copyable):
    """The contents of an INIT or INIT ACK chunk."""

    var initiate_tag: UInt32
    """The tag the sender wants in every packet addressed to it."""
    var a_rwnd: UInt32
    """The sender's advertised receiver window credit in bytes."""
    var num_outbound_streams: UInt16
    """The number of streams the sender wants to send on."""
    var num_inbound_streams: UInt16
    """The number of streams the sender accepts."""
    var initial_tsn: UInt32
    """The first TSN the sender will use."""
    var cookie: List[UInt8]
    """The State Cookie; empty when absent (always absent in INIT)."""
    var forward_tsn_supported: Bool
    """Whether the Forward-TSN-Supported parameter is present."""
    var extensions: List[UInt8]
    """The chunk types listed in Supported Extensions."""
    var unrecognized: List[UInt8]
    """Raw unknown parameters, each padded, that ask to be reported."""

    def __init__(
        out self,
        initiate_tag: UInt32,
        a_rwnd: UInt32,
        num_outbound_streams: UInt16,
        num_inbound_streams: UInt16,
        initial_tsn: UInt32,
    ):
        """Creates a chunk with the fixed fields and no parameters."""
        self.initiate_tag = initiate_tag
        self.a_rwnd = a_rwnd
        self.num_outbound_streams = num_outbound_streams
        self.num_inbound_streams = num_inbound_streams
        self.initial_tsn = initial_tsn
        self.cookie = List[UInt8]()
        self.forward_tsn_supported = False
        self.extensions = List[UInt8]()
        self.unrecognized = List[UInt8]()

    def supports_extension(self, kind: UInt8) -> Bool:
        """Checks whether a chunk type is listed in Supported Extensions."""
        for e in self.extensions:
            if e == kind:
                return True
        return False

    def encode(self, mut out: List[UInt8], kind: UInt8):
        """Appends the chunk.

        Parameters are written in the order State Cookie,
        Forward-TSN-Supported, Supported Extensions, Unrecognized Parameter.
        """
        var start = begin_chunk(out, kind, 0)
        put_u32(out, self.initiate_tag)
        put_u32(out, self.a_rwnd)
        put_u16(out, self.num_outbound_streams)
        put_u16(out, self.num_inbound_streams)
        put_u32(out, self.initial_tsn)
        if len(self.cookie) > 0:
            var p = begin_param(out, start, PARAM_STATE_COOKIE)
            put_bytes(out, Span(self.cookie))
            end_param(out, p)
        if self.forward_tsn_supported:
            var p = begin_param(out, start, PARAM_FORWARD_TSN_SUPPORTED)
            end_param(out, p)
        if len(self.extensions) > 0:
            var p = begin_param(out, start, PARAM_SUPPORTED_EXTENSIONS)
            put_bytes(out, Span(self.extensions))
            end_param(out, p)
        if len(self.unrecognized) > 0:
            var items = List[Tlv]()
            try:
                items = parse_tlvs(Span(self.unrecognized), 0)
            except:
                pass
            for item in items:
                var p = begin_param(out, start, PARAM_UNRECOGNIZED)
                put_bytes(
                    out,
                    Span(self.unrecognized)[
                        item.offset - 4 : item.offset + item.length
                    ],
                )
                end_param(out, p)
        end_chunk(out, start)


def _is_ignored_param(kind: UInt16) -> Bool:
    # Address, cookie-preservative, host-name, address-type, ECN,
    # zero-checksum, AUTH and adaptation-layer parameters carry nothing a
    # single-path association over DTLS needs.
    if kind == 5 or kind == 6 or kind == 9 or kind == 11 or kind == 12:
        return True
    if kind >= 0x8000 and kind <= 0x8004:
        return True
    return kind == 0xC006 or kind == PARAM_UNRECOGNIZED


def decode_init(value: Span[UInt8, _]) raises -> InitChunk:
    """Decodes the value of an INIT or INIT ACK chunk.

    Unknown parameters are handled by their two high type bits: when the top
    bit is clear the remaining parameters are not processed, and when the next
    bit is set the parameter is collected in `unrecognized`.
    """
    if len(value) < 16:
        raise Error("sctp: INIT shorter than its fixed fields")
    var chunk = InitChunk(
        get_u32(value, 0),
        get_u32(value, 4),
        get_u16(value, 8),
        get_u16(value, 10),
        get_u32(value, 12),
    )
    var items = parse_tlvs(value, 16)
    for item in items:
        var body = value[item.offset : item.offset + item.length]
        if item.kind == PARAM_STATE_COOKIE:
            chunk.cookie = List[UInt8](body)
        elif item.kind == PARAM_FORWARD_TSN_SUPPORTED:
            chunk.forward_tsn_supported = True
        elif item.kind == PARAM_SUPPORTED_EXTENSIONS:
            chunk.extensions = List[UInt8](body)
        elif _is_ignored_param(item.kind):
            pass
        else:
            if (item.kind & 0x4000) != 0 and len(chunk.unrecognized) < 256:
                put_u16(chunk.unrecognized, item.kind)
                put_u16(chunk.unrecognized, UInt16(item.length + 4))
                put_bytes(chunk.unrecognized, body)
                while len(chunk.unrecognized) % 4 != 0:
                    chunk.unrecognized.append(0)
            if (item.kind & 0x8000) == 0:
                break
    return chunk^


def encode_data(
    mut out: List[UInt8],
    tsn: UInt32,
    stream_id: UInt16,
    ssn: UInt16,
    ppid: UInt32,
    flags: UInt8,
    payload: Span[UInt8, _],
):
    """Appends a DATA chunk."""
    var start = begin_chunk(out, CHUNK_DATA, flags)
    put_u32(out, tsn)
    put_u16(out, stream_id)
    put_u16(out, ssn)
    put_u32(out, ppid)
    put_bytes(out, payload)
    end_chunk(out, start)


struct DataChunk(Copyable):
    """The contents of a DATA chunk."""

    var tsn: UInt32
    """The transmission sequence number."""
    var stream_id: UInt16
    """The stream identifier."""
    var ssn: UInt16
    """The stream sequence number; unused for unordered data."""
    var ppid: UInt32
    """The payload protocol identifier."""
    var flags: UInt8
    """The `DATA_FLAG_*` bits."""
    var payload: List[UInt8]
    """The user data fragment."""

    def __init__(
        out self,
        tsn: UInt32,
        stream_id: UInt16,
        ssn: UInt16,
        ppid: UInt32,
        flags: UInt8,
        payload: Span[UInt8, _],
    ):
        """Creates a chunk, copying the payload."""
        self.tsn = tsn
        self.stream_id = stream_id
        self.ssn = ssn
        self.ppid = ppid
        self.flags = flags
        self.payload = List[UInt8](payload)

    def unordered(self) -> Bool:
        """Checks the U bit."""
        return (self.flags & DATA_FLAG_UNORDERED) != 0

    def beginning(self) -> Bool:
        """Checks the B bit."""
        return (self.flags & DATA_FLAG_BEGIN) != 0

    def ending(self) -> Bool:
        """Checks the E bit."""
        return (self.flags & DATA_FLAG_END) != 0

    def encode(self, mut out: List[UInt8]):
        """Appends the chunk."""
        encode_data(
            out,
            self.tsn,
            self.stream_id,
            self.ssn,
            self.ppid,
            self.flags,
            Span(self.payload),
        )


def decode_data(value: Span[UInt8, _], flags: UInt8) raises -> DataChunk:
    """Decodes the value of a DATA chunk."""
    if len(value) < 12:
        raise Error("sctp: DATA shorter than its fixed fields")
    return DataChunk(
        get_u32(value, 0),
        get_u16(value, 4),
        get_u16(value, 6),
        get_u32(value, 8),
        flags,
        value[12 : len(value)],
    )


struct GapBlock(ImplicitlyCopyable):
    """A run of received TSNs, as offsets from the cumulative TSN ack."""

    var start: UInt16
    """The offset of the first TSN in the run."""
    var end: UInt16
    """The offset of the last TSN in the run."""

    def __init__(out self, start: UInt16, end: UInt16):
        """Creates a gap ack block."""
        self.start = start
        self.end = end


struct SackChunk(Copyable):
    """The contents of a SACK chunk."""

    var cumulative_tsn: UInt32
    """The highest TSN received with no gap before it."""
    var a_rwnd: UInt32
    """The sender's remaining receive buffer in bytes."""
    var gaps: List[GapBlock]
    """The received runs above the cumulative TSN, in ascending order."""
    var duplicates: List[UInt32]
    """TSNs received more than once since the last SACK."""

    def __init__(out self, cumulative_tsn: UInt32, a_rwnd: UInt32):
        """Creates a SACK with no gap blocks and no duplicates."""
        self.cumulative_tsn = cumulative_tsn
        self.a_rwnd = a_rwnd
        self.gaps = List[GapBlock]()
        self.duplicates = List[UInt32]()

    def encode(self, mut out: List[UInt8]):
        """Appends the chunk."""
        var start = begin_chunk(out, CHUNK_SACK, 0)
        put_u32(out, self.cumulative_tsn)
        put_u32(out, self.a_rwnd)
        put_u16(out, UInt16(len(self.gaps)))
        put_u16(out, UInt16(len(self.duplicates)))
        for g in self.gaps:
            put_u16(out, g.start)
            put_u16(out, g.end)
        for d in self.duplicates:
            put_u32(out, d)
        end_chunk(out, start)

    def encoded_size(self) -> Int:
        """Computes the size of the encoded chunk."""
        return 16 + 4 * len(self.gaps) + 4 * len(self.duplicates)


def decode_sack(value: Span[UInt8, _]) raises -> SackChunk:
    """Decodes the value of a SACK chunk."""
    var r = Reader(value)
    var sack = SackChunk(r.u32(), r.u32())
    var num_gaps = Int(r.u16())
    var num_dups = Int(r.u16())
    if r.remaining() < 4 * (num_gaps + num_dups):
        raise Error("sctp: SACK shorter than its block counts")
    for _ in range(num_gaps):
        var s = r.u16()
        var e = r.u16()
        sack.gaps.append(GapBlock(s, e))
    for _ in range(num_dups):
        sack.duplicates.append(r.u32())
    return sack^


struct ForwardTsnChunk(Copyable):
    """The contents of a FORWARD-TSN chunk (RFC 3758)."""

    var new_cumulative_tsn: UInt32
    """The TSN the receiver should move its cumulative point to."""
    var stream_ids: List[UInt16]
    """The ordered streams that had messages skipped."""
    var ssns: List[UInt16]
    """For each entry of `stream_ids`, the largest skipped sequence number."""

    def __init__(out self, new_cumulative_tsn: UInt32):
        """Creates a chunk with no stream entries."""
        self.new_cumulative_tsn = new_cumulative_tsn
        self.stream_ids = List[UInt16]()
        self.ssns = List[UInt16]()

    def encode(self, mut out: List[UInt8]):
        """Appends the chunk."""
        var start = begin_chunk(out, CHUNK_FORWARD_TSN, 0)
        put_u32(out, self.new_cumulative_tsn)
        for i in range(len(self.stream_ids)):
            put_u16(out, self.stream_ids[i])
            put_u16(out, self.ssns[i])
        end_chunk(out, start)


def decode_forward_tsn(value: Span[UInt8, _]) raises -> ForwardTsnChunk:
    """Decodes the value of a FORWARD-TSN chunk."""
    var r = Reader(value)
    var chunk = ForwardTsnChunk(r.u32())
    if r.remaining() % 4 != 0:
        raise Error("sctp: FORWARD-TSN ends inside a stream entry")
    while r.remaining() > 0:
        chunk.stream_ids.append(r.u16())
        chunk.ssns.append(r.u16())
    return chunk^


def encode_cookie_echo(mut out: List[UInt8], cookie: Span[UInt8, _]):
    """Appends a COOKIE ECHO chunk."""
    var start = begin_chunk(out, CHUNK_COOKIE_ECHO, 0)
    put_bytes(out, cookie)
    end_chunk(out, start)


def encode_cookie_ack(mut out: List[UInt8]):
    """Appends a COOKIE ACK chunk."""
    var start = begin_chunk(out, CHUNK_COOKIE_ACK, 0)
    end_chunk(out, start)


def encode_heartbeat(mut out: List[UInt8], kind: UInt8, info: Span[UInt8, _]):
    """Appends a HEARTBEAT or HEARTBEAT ACK chunk."""
    var start = begin_chunk(out, kind, 0)
    put_bytes(out, info)
    end_chunk(out, start)


def encode_shutdown(mut out: List[UInt8], cumulative_tsn: UInt32):
    """Appends a SHUTDOWN chunk."""
    var start = begin_chunk(out, CHUNK_SHUTDOWN, 0)
    put_u32(out, cumulative_tsn)
    end_chunk(out, start)


def decode_shutdown(value: Span[UInt8, _]) raises -> UInt32:
    """Decodes the value of a SHUTDOWN chunk."""
    if len(value) < 4:
        raise Error("sctp: SHUTDOWN shorter than its fixed field")
    return get_u32(value, 0)


def encode_shutdown_ack(mut out: List[UInt8]):
    """Appends a SHUTDOWN ACK chunk."""
    var start = begin_chunk(out, CHUNK_SHUTDOWN_ACK, 0)
    end_chunk(out, start)


def encode_shutdown_complete(mut out: List[UInt8], t_bit: Bool):
    """Appends a SHUTDOWN COMPLETE chunk."""
    var flags = UInt8(1) if t_bit else UInt8(0)
    var start = begin_chunk(out, CHUNK_SHUTDOWN_COMPLETE, flags)
    end_chunk(out, start)
