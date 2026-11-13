"""Builders for the control packets and reports an association sends.

These are the packets that do not depend on the state of data transfer:
INIT and INIT ACK, ABORT, the replies to packets that belong to no
association, and the ERROR chunks that report what was not understood.
"""

from ..wire import put_u32
from .cause import (
    CAUSE_INVALID_STREAM,
    CAUSE_PROTOCOL_VIOLATION,
    CAUSE_STALE_COOKIE,
    CAUSE_UNRECOGNIZED_CHUNK,
    CAUSE_USER_INITIATED_ABORT,
    ErrorCause,
    decode_causes,
    encode_abort,
    encode_error,
)
from .chunk import InitChunk, encode_shutdown_complete
from .config import SctpConfig
from .cookie import CookieData, encode_cookie
from .packet import (
    CHUNK_ABORT,
    CHUNK_COOKIE_ACK,
    CHUNK_ERROR,
    CHUNK_FORWARD_TSN,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_RECONFIG,
    CHUNK_SHUTDOWN_ACK,
    CHUNK_SHUTDOWN_COMPLETE,
    PacketView,
    begin_packet,
    finish_packet,
)

comptime _MAX_REASON_BYTES = 256


def printable(text: Span[UInt8, _]) -> String:
    """Turns text supplied by the peer into a safe string.

    Args:
        text: Bytes from an error cause.

    Returns:
        At most 256 characters, with everything but printable ASCII replaced
        by `?`.
    """
    var out = List[UInt8]()
    for b in text:
        if len(out) >= _MAX_REASON_BYTES:
            break
        out.append(b if b >= 0x20 and b < 0x7F else UInt8(0x3F))
    return String(from_utf8_lossy=Span(out))


def init_is_valid(init: InitChunk) -> Bool:
    """Checks the mandatory fields of an INIT or INIT ACK.

    Args:
        init: The decoded chunk.

    Returns:
        `True` if the tag and stream counts are non-zero and the window is
        at least 1500 bytes, as RFC 9260 section 3.3.2 requires.
    """
    return (
        init.initiate_tag != 0
        and init.num_outbound_streams != 0
        and init.num_inbound_streams != 0
        and init.a_rwnd >= 1500
    )


def supports_forward_tsn(init: InitChunk) -> Bool:
    """Checks whether the sender of an INIT or INIT ACK does PR-SCTP.

    Args:
        init: The decoded chunk.

    Returns:
        `True` if it carries Forward-TSN-Supported (RFC 3758) or lists
        FORWARD-TSN in Supported Extensions, which is all pion sends.
    """
    return init.forward_tsn_supported or init.supports_extension(
        CHUNK_FORWARD_TSN
    )


def local_init(cfg: SctpConfig) -> InitChunk:
    """Builds the INIT contents this endpoint announces.

    RE-CONFIG and FORWARD-TSN are listed as supported extensions. I-DATA
    never is: pion would switch to it.

    Args:
        cfg: The association configuration.

    Returns:
        The chunk, without a cookie.
    """
    var init = InitChunk(
        cfg.local_tag,
        cfg.a_rwnd,
        cfg.num_outbound_streams,
        cfg.num_inbound_streams,
        cfg.initial_tsn,
    )
    init.forward_tsn_supported = True
    init.extensions = [UInt8(CHUNK_RECONFIG), UInt8(CHUNK_FORWARD_TSN)]
    return init^


def init_packet(cfg: SctpConfig) -> List[UInt8]:
    """Builds the INIT packet, with verification tag 0.

    Args:
        cfg: The association configuration.

    Returns:
        The complete packet.
    """
    var pkt = List[UInt8](capacity=64)
    begin_packet(pkt, cfg.local_port, cfg.remote_port, 0)
    local_init(cfg).encode(pkt, CHUNK_INIT)
    finish_packet(pkt)
    return pkt^


def init_ack_packet(
    cfg: SctpConfig, init: InitChunk, now_ms: Int
) -> List[UInt8]:
    """Builds the INIT ACK that answers a peer's INIT.

    The tag and TSN are the configured ones, so that an INIT of ours that
    crosses the peer's stays consistent with it. Everything COOKIE ECHO
    needs goes into the State Cookie; no state is kept (RFC 9260 5.1.3).

    Args:
        cfg: The association configuration.
        init: The peer's valid INIT.
        now_ms: The current time, stored in the cookie.

    Returns:
        The complete packet, addressed with the peer's initiate tag.
    """
    var data = CookieData()
    data.peer_tag = init.initiate_tag
    data.peer_initial_tsn = init.initial_tsn
    data.peer_a_rwnd = init.a_rwnd
    data.peer_outbound_streams = init.num_outbound_streams
    data.peer_inbound_streams = init.num_inbound_streams
    data.peer_forward_tsn = supports_forward_tsn(init)
    data.peer_reconfig = init.supports_extension(CHUNK_RECONFIG)
    data.local_tag = cfg.local_tag
    data.local_initial_tsn = cfg.initial_tsn
    data.created_ms = now_ms
    var ack = local_init(cfg)
    ack.cookie = encode_cookie(data, Span(cfg.cookie_secret))
    ack.unrecognized = init.unrecognized.copy()
    var pkt = List[UInt8](capacity=128)
    begin_packet(pkt, cfg.local_port, cfg.remote_port, init.initiate_tag)
    ack.encode(pkt, CHUNK_INIT_ACK)
    finish_packet(pkt)
    return pkt^


def abort_packet(
    cfg: SctpConfig,
    tag: UInt32,
    t_bit: Bool,
    causes: Span[ErrorCause, _],
) -> List[UInt8]:
    """Builds an ABORT packet.

    Args:
        cfg: The association configuration.
        tag: The verification tag: the peer's tag, or with `t_bit` the tag
            of the packet being answered.
        t_bit: Whether the tag is reflected.
        causes: The error causes to report.

    Returns:
        The complete packet.
    """
    var pkt = List[UInt8](capacity=64)
    begin_packet(pkt, cfg.local_port, cfg.remote_port, tag)
    encode_abort(pkt, t_bit, causes)
    finish_packet(pkt)
    return pkt^


def stray_reply(cfg: SctpConfig, view: PacketView) -> List[UInt8]:
    """Builds the answer to a packet that belongs to no association.

    RFC 9260 section 8.4: an ABORT that reflects the packet's verification
    tag with the T bit, or a SHUTDOWN COMPLETE for a SHUTDOWN ACK. Packets
    that contain an ABORT, and INIT, COOKIE ACK, ERROR and SHUTDOWN
    COMPLETE packets, get no answer.

    Args:
        cfg: The association configuration.
        view: The parsed packet, with at least one chunk.

    Returns:
        The complete reply packet, or an empty list for no reply.
    """
    var pkt = List[UInt8]()
    for c in view.chunks:
        if c.kind == CHUNK_ABORT:
            return pkt^
    var first = view.chunks[0].kind
    if (
        first == CHUNK_SHUTDOWN_COMPLETE
        or first == CHUNK_COOKIE_ACK
        or first == CHUNK_ERROR
        or first == CHUNK_INIT
    ):
        return pkt^
    begin_packet(pkt, cfg.local_port, cfg.remote_port, view.verification_tag)
    if first == CHUNK_SHUTDOWN_ACK:
        encode_shutdown_complete(pkt, True)
    else:
        var none = List[ErrorCause]()
        encode_abort(pkt, True, Span(none))
    finish_packet(pkt)
    return pkt^


def unrecognized_chunk_report(
    kind: UInt8, flags: UInt8, value_length: Int
) -> List[UInt8]:
    """Builds the ERROR chunk that reports an unknown chunk type.

    Args:
        kind: The type of the chunk that was not understood.
        flags: Its flags.
        value_length: The length of its value.

    Returns:
        An ERROR chunk with an Unrecognized Chunk Type cause that carries
        the header of the offending chunk.
    """
    var header: List[UInt8] = [
        kind,
        flags,
        UInt8(((value_length + 4) >> 8) & 0xFF),
        UInt8((value_length + 4) & 0xFF),
    ]
    var causes: List[ErrorCause] = []
    causes.append(ErrorCause(CAUSE_UNRECOGNIZED_CHUNK, Span(header)))
    var report = List[UInt8]()
    encode_error(report, Span(causes))
    return report^


def invalid_stream_report(stream_id: UInt16) -> List[UInt8]:
    """Builds the ERROR chunk that reports DATA on a nonexistent stream.

    Args:
        stream_id: The stream identifier of the DATA chunk.

    Returns:
        An ERROR chunk with an Invalid Stream Identifier cause.
    """
    var info: List[UInt8] = [
        UInt8(stream_id >> 8),
        UInt8(stream_id & 0xFF),
        0,
        0,
    ]
    var causes: List[ErrorCause] = []
    causes.append(ErrorCause(CAUSE_INVALID_STREAM, Span(info)))
    var report = List[UInt8]()
    encode_error(report, Span(causes))
    return report^


def stale_cookie_packet(
    cfg: SctpConfig, peer_tag: UInt32, age_ms: Int
) -> List[UInt8]:
    """Builds the ERROR packet that refuses an expired State Cookie.

    Args:
        cfg: The association configuration.
        peer_tag: The peer's initiate tag, taken from the cookie.
        age_ms: The age of the cookie in milliseconds.

    Returns:
        The complete packet, with a Stale Cookie cause whose measure of
        staleness is in microseconds.
    """
    var staleness = List[UInt8]()
    put_u32(staleness, UInt32((age_ms & 0xFFFFF) * 1000))
    var causes: List[ErrorCause] = []
    causes.append(ErrorCause(CAUSE_STALE_COOKIE, Span(staleness)))
    var pkt = List[UInt8](capacity=32)
    begin_packet(pkt, cfg.local_port, cfg.remote_port, peer_tag)
    encode_error(pkt, Span(causes))
    finish_packet(pkt)
    return pkt^


def abort_reason(value: Span[UInt8, _]) -> String:
    """Describes a received ABORT for the closed event.

    Args:
        value: The value of the ABORT chunk.

    Returns:
        `aborted by peer`, followed by the peer's text for a user-initiated
        abort or protocol violation, or by the first cause code.
    """
    try:
        var causes = decode_causes(value)
        if len(causes) > 0:
            if (
                causes[0].code == CAUSE_USER_INITIATED_ABORT
                or causes[0].code == CAUSE_PROTOCOL_VIOLATION
            ) and len(causes[0].info) > 0:
                return String(
                    t"aborted by peer: {printable(Span(causes[0].info))}"
                )
            return String(t"aborted by peer (cause {causes[0].code})")
    except:
        pass
    return String("aborted by peer")


def init_backoff(cfg: SctpConfig, attempts: Int) -> Int:
    """Computes the T1 timeout after a number of expiries.

    Args:
        cfg: The association configuration.
        attempts: How often T1 has expired so far.

    Returns:
        The initial RTO doubled once per expiry, capped at the maximum RTO.
    """
    var delay = cfg.rto_initial_ms
    for _ in range(attempts):
        delay *= 2
        if delay >= cfg.rto_max_ms:
            return cfg.rto_max_ms
    return delay
