"""RE-CONFIG chunks: the stream reset signalling of RFC 6525."""

from ..wire import Reader, put_u16, put_u32
from .packet import (
    CHUNK_RECONFIG,
    begin_chunk,
    begin_param,
    end_chunk,
    end_param,
    parse_tlvs,
)

comptime PARAM_OUTGOING_RESET = 13
"""RE-CONFIG parameter: Outgoing SSN Reset Request."""
comptime PARAM_INCOMING_RESET = 14
"""RE-CONFIG parameter: Incoming SSN Reset Request."""
comptime PARAM_SSN_TSN_RESET = 15
"""RE-CONFIG parameter: SSN/TSN Reset Request."""
comptime PARAM_RECONFIG_RESPONSE = 16
"""RE-CONFIG parameter: Re-configuration Response."""
comptime PARAM_ADD_OUTGOING_STREAMS = 17
"""RE-CONFIG parameter: Add Outgoing Streams Request."""
comptime PARAM_ADD_INCOMING_STREAMS = 18
"""RE-CONFIG parameter: Add Incoming Streams Request."""

comptime RECONFIG_RESULT_NOTHING_TO_DO = 0
"""Re-configuration result: success, nothing to do."""
comptime RECONFIG_RESULT_PERFORMED = 1
"""Re-configuration result: success, performed."""
comptime RECONFIG_RESULT_DENIED = 2
"""Re-configuration result: denied."""
comptime RECONFIG_RESULT_WRONG_SSN = 3
"""Re-configuration result: error, wrong SSN."""
comptime RECONFIG_RESULT_ALREADY_IN_PROGRESS = 4
"""Re-configuration result: error, request already in progress."""
comptime RECONFIG_RESULT_BAD_SEQUENCE = 5
"""Re-configuration result: error, bad sequence number."""
comptime RECONFIG_RESULT_IN_PROGRESS = 6
"""Re-configuration result: in progress."""


struct ReconfigParam(Copyable):
    """One parameter of a RE-CONFIG chunk (RFC 6525)."""

    var kind: UInt16
    """The parameter type, one of the `PARAM_*` re-configuration types."""
    var request_seq: UInt32
    """The request sequence number, or the response sequence number."""
    var response_seq: UInt32
    """Outgoing reset only: the last request sequence number seen."""
    var last_tsn: UInt32
    """Outgoing reset only: the sender's last assigned TSN."""
    var streams: List[UInt16]
    """Reset requests only: the affected streams; empty means all."""
    var result: UInt32
    """Response only: one of the `RECONFIG_RESULT_*` values."""
    var count: UInt16
    """Add-streams requests only: the number of new streams."""

    def __init__(out self, kind: UInt16, request_seq: UInt32):
        """Creates a parameter with every other field zero.

        Args:
            kind: The parameter type.
            request_seq: The request or response sequence number.
        """
        self.kind = kind
        self.request_seq = request_seq
        self.response_seq = 0
        self.last_tsn = 0
        self.streams = List[UInt16]()
        self.result = 0
        self.count = 0

    def encode(self, mut out: List[UInt8], chunk_start: Int):
        """Appends the parameter inside a RE-CONFIG chunk being built.

        Args:
            out: The buffer to append to.
            chunk_start: The offset of the enclosing chunk header.
        """
        var p = begin_param(out, chunk_start, self.kind)
        put_u32(out, self.request_seq)
        if self.kind == PARAM_OUTGOING_RESET:
            put_u32(out, self.response_seq)
            put_u32(out, self.last_tsn)
            for s in self.streams:
                put_u16(out, s)
        elif self.kind == PARAM_INCOMING_RESET:
            for s in self.streams:
                put_u16(out, s)
        elif self.kind == PARAM_RECONFIG_RESPONSE:
            put_u32(out, self.result)
        elif (
            self.kind == PARAM_ADD_OUTGOING_STREAMS
            or self.kind == PARAM_ADD_INCOMING_STREAMS
        ):
            put_u16(out, self.count)
            put_u16(out, 0)
        end_param(out, p)


def outgoing_reset_request(
    request_seq: UInt32,
    response_seq: UInt32,
    last_tsn: UInt32,
    streams: Span[UInt16, _],
) -> ReconfigParam:
    """Builds an Outgoing SSN Reset Request parameter.

    Args:
        request_seq: The sender's request sequence number.
        response_seq: The last request sequence number seen from the peer.
        last_tsn: The sender's last assigned TSN.
        streams: The outgoing streams to reset.

    Returns:
        The parameter.
    """
    var p = ReconfigParam(PARAM_OUTGOING_RESET, request_seq)
    p.response_seq = response_seq
    p.last_tsn = last_tsn
    p.streams = List[UInt16](streams)
    return p^


def reconfig_response(response_seq: UInt32, result: UInt32) -> ReconfigParam:
    """Builds a Re-configuration Response parameter.

    Args:
        response_seq: The sequence number of the request being answered.
        result: One of the `RECONFIG_RESULT_*` values.

    Returns:
        The parameter.
    """
    var p = ReconfigParam(PARAM_RECONFIG_RESPONSE, response_seq)
    p.result = result
    return p^


def encode_reconfig(mut out: List[UInt8], params: Span[ReconfigParam, _]):
    """Appends a RE-CONFIG chunk.

    Args:
        out: The buffer to append to.
        params: The parameters, at most two per RFC 6525.
    """
    var start = begin_chunk(out, CHUNK_RECONFIG, 0)
    for p in params:
        p.encode(out, start)
    end_chunk(out, start)


def decode_reconfig(value: Span[UInt8, _]) raises -> List[ReconfigParam]:
    """Decodes the value of a RE-CONFIG chunk.

    Parameters of unknown type are returned with only `kind` set.

    Args:
        value: The chunk value.

    Returns:
        The parameters in wire order.

    Raises:
        Error: If a parameter is truncated.
    """
    var params = List[ReconfigParam]()
    var items = parse_tlvs(value, 0)
    for item in items:
        var r = Reader(value[item.offset : item.offset + item.length])
        if item.kind < PARAM_OUTGOING_RESET or (
            item.kind > PARAM_ADD_INCOMING_STREAMS
        ):
            params.append(ReconfigParam(item.kind, 0))
            continue
        var p = ReconfigParam(item.kind, r.u32())
        if item.kind == PARAM_OUTGOING_RESET:
            p.response_seq = r.u32()
            p.last_tsn = r.u32()
        if item.kind == PARAM_OUTGOING_RESET or (
            item.kind == PARAM_INCOMING_RESET
        ):
            if r.remaining() % 2 != 0:
                raise Error("sctp: reset request ends inside a stream id")
            while r.remaining() > 0:
                p.streams.append(r.u16())
        elif item.kind == PARAM_RECONFIG_RESPONSE:
            p.result = r.u32()
        elif (
            item.kind == PARAM_ADD_OUTGOING_STREAMS
            or item.kind == PARAM_ADD_INCOMING_STREAMS
        ):
            p.count = r.u16()
        params.append(p^)
    return params^
