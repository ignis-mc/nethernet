from nethernet.sctp.cause import (
    CAUSE_INVALID_STREAM,
    CAUSE_STALE_COOKIE,
    CAUSE_UNRECOGNIZED_CHUNK,
    CAUSE_USER_INITIATED_ABORT,
    ErrorCause,
    decode_causes,
    encode_abort,
)
from nethernet.sctp.chunk import InitChunk, decode_init, encode_cookie_ack
from nethernet.sctp.config import SctpConfig
from nethernet.sctp.control import (
    abort_packet,
    abort_reason,
    init_ack_packet,
    init_backoff,
    init_is_valid,
    init_packet,
    invalid_stream_report,
    local_init,
    printable,
    stale_cookie_packet,
    stray_reply,
    supports_forward_tsn,
    unrecognized_chunk_report,
)
from nethernet.sctp.cookie import decode_cookie
from nethernet.sctp.packet import (
    CHUNK_ABORT,
    CHUNK_DATA,
    CHUNK_ERROR,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_SHUTDOWN_ACK,
    CHUNK_SHUTDOWN_COMPLETE,
    begin_chunk,
    begin_packet,
    end_chunk,
    finish_packet,
    parse_packet,
)
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _cfg() -> SctpConfig:
    var secret = bytes_of("secret")
    return SctpConfig(0x01020304, 0x0A0B0C0D, Span(secret))


def _packet_with(kind: UInt8, tag: UInt32) -> List[UInt8]:
    var p = List[UInt8]()
    begin_packet(p, 5000, 5000, tag)
    var start = begin_chunk(p, kind, 0)
    end_chunk(p, start)
    finish_packet(p)
    return p^


def test_printable() raises:
    var text = hex_decode("48690a00ff7e7f20")
    assert_equal(printable(Span(text)), "Hi???~? ")
    var long = List[UInt8](length=1000, fill=0x41)
    assert_equal(printable(Span(long)).byte_length(), 256)
    var empty = List[UInt8]()
    assert_equal(printable(Span(empty)), "")


def test_init_validity() raises:
    assert_true(init_is_valid(InitChunk(1, 1500, 1, 1, 0)))
    assert_false(init_is_valid(InitChunk(0, 1500, 1, 1, 0)))
    assert_false(init_is_valid(InitChunk(1, 1499, 1, 1, 0)))
    assert_false(init_is_valid(InitChunk(1, 1500, 0, 1, 0)))
    assert_false(init_is_valid(InitChunk(1, 1500, 1, 0, 0)))


def test_forward_tsn_support_detection() raises:
    var init = InitChunk(1, 1500, 1, 1, 0)
    assert_false(supports_forward_tsn(init))
    init.extensions = [0x82]
    assert_false(supports_forward_tsn(init))
    init.extensions = [0x82, 0xC0]
    assert_true(supports_forward_tsn(init))
    var other = InitChunk(1, 1500, 1, 1, 0)
    other.forward_tsn_supported = True
    assert_true(supports_forward_tsn(other))


def test_init_packet() raises:
    var cfg = _cfg()
    var p = init_packet(cfg)
    var view = parse_packet(Span(p))
    assert_equal(view.verification_tag, 0)
    assert_equal(view.source_port, 5000)
    assert_equal(len(view.chunks), 1)
    assert_true(view.chunks[0].kind == CHUNK_INIT)
    # Fixed fields, Forward-TSN-Supported, Supported Extensions 82 c0.
    assert_equal(
        hex_encode(Span(p)[12 : len(p)]),
        "0100001e0102030400100000ffffffff0a0b0c0dc00000048008000682c00000",
    )
    var init = local_init(cfg)
    assert_equal(len(init.cookie), 0)
    assert_false(init.supports_extension(0x40))


def test_init_ack_packet_carries_a_valid_cookie() raises:
    var cfg = _cfg()
    var peer = InitChunk(0x55667788, 4000, 20, 30, 99)
    peer.extensions = [0x82, 0xC0]
    var p = init_ack_packet(cfg, peer, 1234)
    var view = parse_packet(Span(p))
    assert_equal(view.verification_tag, 0x55667788)
    assert_true(view.chunks[0].kind == CHUNK_INIT_ACK)
    var ack = decode_init(Span(p)[16 : len(p)])
    assert_equal(ack.initiate_tag, 0x01020304)
    assert_equal(ack.initial_tsn, 0x0A0B0C0D)
    var data = decode_cookie(Span(ack.cookie), Span(cfg.cookie_secret))
    assert_equal(data.peer_tag, 0x55667788)
    assert_equal(data.peer_initial_tsn, 99)
    assert_equal(data.peer_a_rwnd, 4000)
    assert_equal(data.peer_outbound_streams, 20)
    assert_equal(data.peer_inbound_streams, 30)
    assert_true(data.peer_forward_tsn)
    assert_true(data.peer_reconfig)
    assert_equal(data.local_tag, 0x01020304)
    assert_equal(data.local_initial_tsn, 0x0A0B0C0D)
    assert_equal(data.created_ms, 1234)
    # A peer without the extensions is remembered as such.
    var plain = InitChunk(7, 4000, 1, 1, 1)
    var q = init_ack_packet(cfg, plain, 0)
    var ack2 = decode_init(Span(q)[16 : len(q)])
    var data2 = decode_cookie(Span(ack2.cookie), Span(cfg.cookie_secret))
    assert_false(data2.peer_forward_tsn)
    assert_false(data2.peer_reconfig)


def test_abort_packet() raises:
    var cfg = _cfg()
    var causes: List[ErrorCause] = []
    var why = bytes_of("bye")
    causes.append(ErrorCause(CAUSE_USER_INITIATED_ABORT, Span(why)))
    var p = abort_packet(cfg, 0xAABBCCDD, False, Span(causes))
    assert_equal(hex_encode(Span(p)[0:8]), "13881388aabbccdd")
    assert_equal(hex_encode(Span(p)[12 : len(p)]), "0600000b000c000762796500")
    var none = List[ErrorCause]()
    var t = abort_packet(cfg, 5, True, Span(none))
    assert_equal(hex_encode(Span(t)[12 : len(t)]), "06010004")
    _ = parse_packet(Span(t))


def test_stray_reply() raises:
    var cfg = _cfg()
    # DATA: ABORT with the T bit and the packet's own tag.
    var data = _packet_with(CHUNK_DATA, 0x11111111)
    var reply = stray_reply(cfg, parse_packet(Span(data)))
    assert_equal(hex_encode(Span(reply)[4:8]), "11111111")
    assert_equal(hex_encode(Span(reply)[12:16]), "06010004")
    # SHUTDOWN ACK: SHUTDOWN COMPLETE with the T bit.
    var sa = _packet_with(CHUNK_SHUTDOWN_ACK, 0x22222222)
    var done = stray_reply(cfg, parse_packet(Span(sa)))
    assert_equal(hex_encode(Span(done)[4:8]), "22222222")
    assert_equal(hex_encode(Span(done)[12:16]), "0e010004")
    # No reply to ABORT (anywhere in the packet), INIT, COOKIE ACK, ERROR
    # or SHUTDOWN COMPLETE.
    for kind in [
        CHUNK_ABORT,
        CHUNK_INIT,
        11,
        CHUNK_ERROR,
        CHUNK_SHUTDOWN_COMPLETE,
    ]:
        var p = _packet_with(UInt8(kind), 1)
        assert_equal(len(stray_reply(cfg, parse_packet(Span(p)))), 0)
    var mixed = List[UInt8]()
    begin_packet(mixed, 5000, 5000, 3)
    var s1 = begin_chunk(mixed, CHUNK_DATA, 0)
    end_chunk(mixed, s1)
    var none = List[ErrorCause]()
    encode_abort(mixed, False, Span(none))
    finish_packet(mixed)
    assert_equal(len(stray_reply(cfg, parse_packet(Span(mixed)))), 0)


def test_error_reports() raises:
    var unknown = unrecognized_chunk_report(0x7F, 0x05, 300)
    assert_equal(hex_encode(Span(unknown)), "0900000c000600087f050130")
    var causes = decode_causes(Span(unknown)[4:12])
    assert_true(causes[0].code == CAUSE_UNRECOGNIZED_CHUNK)
    var stream = invalid_stream_report(0xFFFE)
    assert_equal(hex_encode(Span(stream)), "0900000c00010008fffe0000")
    var c2 = decode_causes(Span(stream)[4:12])
    assert_true(c2[0].code == CAUSE_INVALID_STREAM)


def test_stale_cookie_packet() raises:
    var p = stale_cookie_packet(_cfg(), 0x0BADBEEF, 61000)
    var view = parse_packet(Span(p))
    assert_equal(view.verification_tag, 0x0BADBEEF)
    assert_true(view.chunks[0].kind == CHUNK_ERROR)
    var causes = decode_causes(Span(p)[16 : len(p)])
    assert_true(causes[0].code == CAUSE_STALE_COOKIE)
    # 61 s in microseconds.
    assert_equal(hex_encode(Span(causes[0].info)), "03a2c940")


def test_abort_reason() raises:
    var user = hex_decode("000c0007627965")
    assert_equal(abort_reason(Span(user)), "aborted by peer: bye")
    var violation = hex_decode("000d00076f6f70")
    assert_equal(abort_reason(Span(violation)), "aborted by peer: oop")
    var empty_user = hex_decode("000c0004")
    assert_equal(abort_reason(Span(empty_user)), "aborted by peer (cause 12)")
    var other = hex_decode("00040004")
    assert_equal(abort_reason(Span(other)), "aborted by peer (cause 4)")
    var none = List[UInt8]()
    assert_equal(abort_reason(Span(none)), "aborted by peer")
    var broken = hex_decode("000cffff00")
    assert_equal(abort_reason(Span(broken)), "aborted by peer")


def test_init_backoff() raises:
    var cfg = _cfg()
    var expected: List[Int] = [
        1000,
        2000,
        4000,
        8000,
        16000,
        32000,
        60000,
        60000,
        60000,
    ]
    for i in range(len(expected)):
        assert_equal(init_backoff(cfg, i), expected[i])
    assert_equal(init_backoff(cfg, 1000), 60000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
