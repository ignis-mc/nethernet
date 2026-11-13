"""Packet-level tests of the association against a hand-built peer."""

from nethernet.sctp.association import Association
from nethernet.sctp.cause import (
    CAUSE_INVALID_STREAM,
    CAUSE_NO_USER_DATA,
    CAUSE_STALE_COOKIE,
    CAUSE_UNRECOGNIZED_CHUNK,
    CAUSE_USER_INITIATED_ABORT,
    ErrorCause,
    decode_causes,
    encode_abort,
    encode_error,
)
from nethernet.sctp.chunk import (
    InitChunk,
    SackChunk,
    decode_data,
    decode_init,
    decode_sack,
    decode_shutdown,
    encode_cookie_ack,
    encode_cookie_echo,
    encode_data,
    encode_heartbeat,
    encode_shutdown,
    encode_shutdown_ack,
    encode_shutdown_complete,
)
from nethernet.sctp.reconfig import (
    PARAM_ADD_OUTGOING_STREAMS,
    PARAM_INCOMING_RESET,
    PARAM_OUTGOING_RESET,
    PARAM_RECONFIG_RESPONSE,
    RECONFIG_RESULT_BAD_SEQUENCE,
    RECONFIG_RESULT_DENIED,
    RECONFIG_RESULT_IN_PROGRESS,
    RECONFIG_RESULT_PERFORMED,
    ReconfigParam,
    decode_reconfig,
    encode_reconfig,
    outgoing_reset_request,
    reconfig_response,
)
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SCTP_STATE_CLOSED,
    SCTP_STATE_COOKIE_ECHOED,
    SCTP_STATE_COOKIE_WAIT,
    SCTP_STATE_ESTABLISHED,
    SCTP_STATE_SHUTDOWN_ACK_SENT,
    SCTP_STATE_SHUTDOWN_RECEIVED,
    SctpConfig,
    SctpEvent,
)
from nethernet.sctp.cookie import COOKIE_SIZE
from nethernet.sctp.packet import (
    CHUNK_ABORT,
    CHUNK_COOKIE_ACK,
    CHUNK_COOKIE_ECHO,
    CHUNK_DATA,
    CHUNK_ERROR,
    CHUNK_FORWARD_TSN,
    CHUNK_HEARTBEAT,
    CHUNK_HEARTBEAT_ACK,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_RECONFIG,
    CHUNK_SACK,
    CHUNK_SHUTDOWN,
    CHUNK_SHUTDOWN_ACK,
    CHUNK_SHUTDOWN_COMPLETE,
    begin_chunk,
    begin_packet,
    end_chunk,
    finish_packet,
    parse_packet,
)
from nethernet.wire import bytes_of, hex_decode, hex_encode, string_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

comptime LOCAL_TAG = 0x0A0B0C0D
comptime LOCAL_TSN = 5000
comptime PEER_TAG = 0x11223344
comptime PEER_TSN = 1000


def _assoc() -> Association:
    var secret = bytes_of("0123456789abcdef")
    return Association(SctpConfig(LOCAL_TAG, LOCAL_TSN, Span(secret)))


def _packet(tag: UInt32, chunks: List[UInt8]) -> List[UInt8]:
    """A packet from the peer carrying the given encoded chunks."""
    var p = List[UInt8]()
    begin_packet(p, 5000, 5000, tag)
    p.extend(Span(chunks))
    finish_packet(p)
    return p^


def _feed(mut a: Association, tag: UInt32, chunks: List[UInt8], now: Int):
    var p = _packet(tag, chunks)
    a.handle_packet(Span(p), now)


def _out(mut a: Association, now: Int) -> List[List[UInt8]]:
    var packets = List[List[UInt8]]()
    while True:
        var p = a.poll_transmit(now)
        if not p:
            break
        packets.append(p.value().copy())
    return packets^


def _events(mut a: Association) -> List[SctpEvent]:
    var events = List[SctpEvent]()
    while True:
        var e = a.poll_event()
        if not e:
            break
        events.append(e.value().copy())
    return events^


def _kinds(packet: List[UInt8]) raises -> String:
    """The chunk types of a packet, like `11,3`."""
    var view = parse_packet(Span(packet))
    var text = String("")
    for i in range(len(view.chunks)):
        if i > 0:
            text += ","
        text += String(view.chunks[i].kind)
    return text


def _value(packet: List[UInt8], index: Int) raises -> List[UInt8]:
    var view = parse_packet(Span(packet))
    var c = view.chunks[index]
    return List[UInt8](Span(packet)[c.offset : c.offset + c.length])


def _tag(packet: List[UInt8]) raises -> UInt32:
    return parse_packet(Span(packet)).verification_tag


def _peer_init(extensions: List[UInt8]) -> List[UInt8]:
    var init = InitChunk(PEER_TAG, 1048576, 65535, 65535, PEER_TSN)
    init.extensions = extensions.copy()
    var out = List[UInt8]()
    init.encode(out, CHUNK_INIT)
    return out^


def _data(
    tsn: UInt32, stream: UInt16, ssn: UInt16, flags: UInt8, text: StringSpan
) -> List[UInt8]:
    var out = List[UInt8]()
    encode_data(out, tsn, stream, ssn, 53, flags, text.as_bytes())
    return out^


def _sack(cum: UInt32) -> List[UInt8]:
    var out = List[UInt8]()
    SackChunk(cum, 1048576).encode(out)
    return out^


def _raw_chunk(kind: UInt8, body: StringSpan) raises -> List[UInt8]:
    var out = List[UInt8]()
    var start = begin_chunk(out, kind, 0)
    out.extend(Span(hex_decode(body)))
    end_chunk(out, start)
    return out^


def _join(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var out = a.copy()
    out.extend(Span(b))
    return out^


def _established_with(extensions: List[UInt8]) raises -> Association:
    """An association the hand-built peer has opened passively."""
    var a = _assoc()
    _feed(a, 0, _peer_init(extensions), 0)
    var replies = _out(a, 0)
    assert_equal(len(replies), 1)
    var ack = decode_init(Span(_value(replies[0], 0)))
    var echo = List[UInt8]()
    encode_cookie_echo(echo, Span(ack.cookie))
    _feed(a, LOCAL_TAG, echo, 1)
    var done = _out(a, 1)
    assert_equal(len(done), 1)
    assert_equal(_kinds(done[0]), "11")
    var events = _events(a)
    assert_equal(len(events), 1)
    assert_equal(events[0].kind, SCTP_EVENT_CONNECTED)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    return a^


def _established() raises -> Association:
    var ext: List[UInt8] = [0x82, 0xC0]
    return _established_with(ext)


def test_init_is_answered_without_keeping_state() raises:
    var a = _assoc()
    var ext: List[UInt8] = [0x82, 0xC0, 0x40, 0xC2]
    _feed(a, 0, _peer_init(ext), 0)
    var replies = _out(a, 0)
    assert_equal(len(replies), 1)
    # Addressed with the peer's initiate tag, INIT ACK alone in the packet.
    assert_equal(_tag(replies[0]), PEER_TAG)
    assert_equal(_kinds(replies[0]), "2")
    var ack = decode_init(Span(_value(replies[0], 0)))
    assert_equal(ack.initiate_tag, LOCAL_TAG)
    assert_equal(ack.initial_tsn, LOCAL_TSN)
    assert_equal(ack.a_rwnd, 1048576)
    assert_equal(ack.num_outbound_streams, 65535)
    assert_equal(ack.num_inbound_streams, 65535)
    assert_equal(len(ack.cookie), COOKIE_SIZE)
    assert_true(ack.forward_tsn_supported)
    # RE-CONFIG and FORWARD-TSN, and never I-DATA.
    assert_equal(hex_encode(Span(ack.extensions)), "82c0")
    # Nothing was allocated: still closed, no timer, no event.
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_false(Bool(a.next_timeout()))
    assert_equal(len(_events(a)), 0)
    # A repeated INIT gets another INIT ACK.
    _feed(a, 0, _peer_init(ext), 500)
    assert_equal(len(_out(a, 500)), 1)


def test_cookie_echo_establishes_and_is_idempotent() raises:
    var a = _established()
    # The peer did not see our COOKIE ACK and repeats its COOKIE ECHO.
    var first = _assoc()
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(first, 0, _peer_init(ext), 0)
    var ack = decode_init(Span(_value(_out(first, 0)[0], 0)))
    var echo = List[UInt8]()
    encode_cookie_echo(echo, Span(ack.cookie))
    for attempt in range(3):
        _feed(a, LOCAL_TAG, echo, 100 + attempt)
        var replies = _out(a, 100 + attempt)
        assert_equal(len(replies), 1)
        assert_equal(_kinds(replies[0]), "11")
        assert_equal(_tag(replies[0]), PEER_TAG)
    # Still one association, connected once.
    assert_equal(len(_events(a)), 0)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(a.stats().packets_dropped, 0)


def test_cookie_echo_bundled_with_data() raises:
    var a = _assoc()
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(a, 0, _peer_init(ext), 0)
    var ack = decode_init(Span(_value(_out(a, 0)[0], 0)))
    var echo = List[UInt8]()
    encode_cookie_echo(echo, Span(ack.cookie))
    _feed(a, LOCAL_TAG, _join(echo, _data(PEER_TSN, 0, 0, 3, "early")), 1)
    var events = _events(a)
    assert_equal(len(events), 2)
    assert_equal(events[0].kind, SCTP_EVENT_CONNECTED)
    assert_equal(events[1].kind, SCTP_EVENT_MESSAGE)
    assert_equal(string_of(Span(events[1].payload)), "early")
    # One packet answers both: COOKIE ACK first, then the SACK.
    var replies = _out(a, 1)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "11,3")
    var sack = decode_sack(Span(_value(replies[0], 1)))
    assert_equal(sack.cumulative_tsn, PEER_TSN)


def test_bad_and_stale_cookies() raises:
    var a = _assoc()
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(a, 0, _peer_init(ext), 0)
    var ack = decode_init(Span(_value(_out(a, 0)[0], 0)))
    # A forged cookie.
    var forged = ack.cookie.copy()
    forged[10] ^= 0x40
    var bad = List[UInt8]()
    encode_cookie_echo(bad, Span(forged))
    _feed(a, LOCAL_TAG, bad, 1)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_equal(len(_out(a, 1)), 0)
    # Random bytes of the wrong size (like another stack's cookie).
    var other = List[UInt8]()
    var junk = List[UInt8](length=32, fill=0x5A)
    encode_cookie_echo(other, Span(junk))
    _feed(a, LOCAL_TAG, other, 2)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_equal(len(_out(a, 2)), 0)
    # The right cookie, but after its lifetime of 60 s: a Stale Cookie
    # error goes back and nothing is established.
    var echo = List[UInt8]()
    encode_cookie_echo(echo, Span(ack.cookie))
    _feed(a, LOCAL_TAG, echo, 60002)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    var replies = _out(a, 60002)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "9")
    assert_equal(_tag(replies[0]), PEER_TAG)
    var causes = decode_causes(Span(_value(replies[0], 0)))
    assert_true(causes[0].code == CAUSE_STALE_COOKIE)
    # Within its lifetime it works.
    _feed(a, LOCAL_TAG, echo, 59000)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(len(_events(a)), 1)


def test_invalid_init_is_refused() raises:
    var a = _assoc()
    # Initiate tag 0: nothing to address a reply with.
    var zero_tag = InitChunk(0, 1048576, 10, 10, 1)
    var out = List[UInt8]()
    zero_tag.encode(out, CHUNK_INIT)
    _feed(a, 0, out, 0)
    assert_equal(len(_out(a, 0)), 0)
    # No streams, or a window below 1500: ABORT.
    var no_streams = InitChunk(PEER_TAG, 1048576, 0, 10, 1)
    var out2 = List[UInt8]()
    no_streams.encode(out2, CHUNK_INIT)
    _feed(a, 0, out2, 0)
    var replies = _out(a, 0)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "6")
    assert_equal(_tag(replies[0]), PEER_TAG)
    var tiny = InitChunk(PEER_TAG, 1499, 10, 10, 1)
    var out3 = List[UInt8]()
    tiny.encode(out3, CHUNK_INIT)
    _feed(a, 0, out3, 0)
    assert_equal(_kinds(_out(a, 0)[0]), "6")
    # INIT with a non-zero verification tag, or bundled: dropped.
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(a, LOCAL_TAG, _peer_init(ext), 0)
    assert_equal(len(_out(a, 0)), 0)
    var ack_chunk = List[UInt8]()
    encode_cookie_ack(ack_chunk)
    _feed(a, 0, _join(_peer_init(ext), ack_chunk), 0)
    assert_equal(len(_out(a, 0)), 0)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_equal(len(_events(a)), 0)


def test_init_parameters_are_reported() raises:
    var a = _assoc()
    # Fixed fields, an unknown "skip and report" parameter, extensions.
    var chunk = _raw_chunk(
        CHUNK_INIT,
        "1122334400100000ffffffff000003e8"
        + "c0330006aabb0000"
        + "8008000682c0",
    )
    _feed(a, 0, chunk, 0)
    var replies = _out(a, 0)
    assert_equal(len(replies), 1)
    var value = _value(replies[0], 0)
    # The INIT ACK ends with Unrecognized Parameter (8) wrapping it.
    assert_true(hex_encode(Span(value)).endswith("0008000ac0330006aabb"))


def test_wrong_tag_or_port_is_dropped() raises:
    var a = _established()
    _feed(a, 0xBADBAD00, _data(PEER_TSN, 0, 0, 3, "x"), 10)
    assert_equal(len(_out(a, 10)), 0)
    assert_equal(len(_events(a)), 0)
    assert_equal(a.stats().packets_dropped, 1)
    var p = List[UInt8]()
    begin_packet(p, 5000, 5001, LOCAL_TAG)
    p.extend(Span(_data(PEER_TSN, 0, 0, 3, "x")))
    finish_packet(p)
    a.handle_packet(Span(p), 10)
    var q = List[UInt8]()
    begin_packet(q, 4999, 5000, LOCAL_TAG)
    q.extend(Span(_data(PEER_TSN, 0, 0, 3, "x")))
    finish_packet(q)
    a.handle_packet(Span(q), 10)
    assert_equal(len(_out(a, 10)), 0)
    assert_equal(a.stats().packets_dropped, 3)
    # The same chunk with the right tag and ports is accepted.
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "x"), 10)
    assert_equal(len(_events(a)), 1)


def test_sack_is_immediate_and_goes_first() raises:
    var a = _established()
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "one"), 10)
    var replies = _out(a, 10)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "3")
    assert_equal(_tag(replies[0]), PEER_TAG)
    var sack = decode_sack(Span(_value(replies[0], 0)))
    assert_equal(sack.cumulative_tsn, PEER_TSN)
    assert_equal(len(sack.gaps), 0)
    # The unread message counts against the advertised window.
    assert_equal(sack.a_rwnd, 1048576 - 3)
    # With data of our own to send, the SACK leads the packet.
    var mine = bytes_of("reply")
    a.send(0, 53, Span(mine), False, -1)
    _feed(a, LOCAL_TAG, _data(PEER_TSN + 2, 0, 2, 3, "three"), 20)
    var bundle = _out(a, 20)
    assert_equal(len(bundle), 1)
    assert_equal(_kinds(bundle[0]), "3,0")
    var gap = decode_sack(Span(_value(bundle[0], 0)))
    assert_equal(gap.cumulative_tsn, PEER_TSN)
    assert_equal(len(gap.gaps), 1)
    assert_equal(gap.gaps[0].start, 2)
    assert_equal(gap.gaps[0].end, 2)
    # A duplicate is reported once, in the next SACK.
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "one"), 30)
    var dup = decode_sack(Span(_value(_out(a, 30)[0], 0)))
    assert_equal(len(dup.duplicates), 1)
    assert_equal(dup.duplicates[0], PEER_TSN)
    _feed(a, LOCAL_TAG, _data(PEER_TSN + 1, 0, 1, 3, "two"), 40)
    var filled = decode_sack(Span(_value(_out(a, 40)[0], 0)))
    assert_equal(filled.cumulative_tsn, PEER_TSN + 2)
    assert_equal(len(filled.gaps), 0)
    assert_equal(len(filled.duplicates), 0)
    var events = _events(a)
    assert_equal(len(events), 3)
    assert_equal(string_of(Span(events[1].payload)), "two")
    assert_equal(string_of(Span(events[2].payload)), "three")
    # Two DATA chunks in one packet produce one SACK.
    _feed(
        a,
        LOCAL_TAG,
        _join(
            _data(PEER_TSN + 3, 0, 3, 3, "a"), _data(PEER_TSN + 4, 0, 4, 3, "b")
        ),
        50,
    )
    var one = _out(a, 50)
    assert_equal(len(one), 1)
    assert_equal(_kinds(one[0]), "3")
    # A SACK-only packet from the peer is not answered.
    _feed(a, LOCAL_TAG, _sack(LOCAL_TSN), 60)
    assert_equal(len(_out(a, 60)), 0)
    assert_equal(a.buffered_amount(), 0)


def test_heartbeat_ack_travels_alone() raises:
    var a = _established()
    var hb = List[UInt8]()
    var info = hex_decode("00010009aabbccddee")
    encode_heartbeat(hb, CHUNK_HEARTBEAT, Span(info))
    # A HEARTBEAT bundled with DATA: the answers must not share a packet,
    # because pion drops any packet that contains a HEARTBEAT ACK.
    _feed(a, LOCAL_TAG, _join(hb, _data(PEER_TSN, 0, 0, 3, "x")), 10)
    var mine = bytes_of("y")
    a.send(0, 53, Span(mine), False, -1)
    var replies = _out(a, 10)
    assert_equal(len(replies), 2)
    assert_equal(_kinds(replies[0]), "5")
    assert_equal(_tag(replies[0]), PEER_TAG)
    assert_equal(hex_encode(Span(_value(replies[0], 0))), "00010009aabbccddee")
    assert_equal(_kinds(replies[1]), "3,0")
    # A HEARTBEAT ACK or ERROR from the peer is ignored.
    var hback = List[UInt8]()
    encode_heartbeat(hback, CHUNK_HEARTBEAT_ACK, Span(info))
    _feed(a, LOCAL_TAG, hback, 20)
    var err = List[UInt8]()
    var causes: List[ErrorCause] = []
    causes.append(ErrorCause(CAUSE_UNRECOGNIZED_CHUNK, Span(info)))
    encode_error(err, Span(causes))
    _feed(a, LOCAL_TAG, err, 20)
    assert_equal(len(_out(a, 20)), 0)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(a.stats().packets_dropped, 0)


def test_unknown_chunk_types_follow_their_high_bits() raises:
    # 00: stop, silent. 01: stop, report. 10: skip, silent. 11: skip, report.
    var kinds: List[UInt8] = [0x3F, 0x7F, 0xBF, 0xFF, 0x40]
    var stops: List[Bool] = [True, True, False, False, True]
    var reports: List[Bool] = [False, True, False, True, True]
    for i in range(len(kinds)):
        var a = _established()
        var unknown = _raw_chunk(kinds[i], "01020304")
        _feed(a, LOCAL_TAG, _join(unknown, _data(PEER_TSN, 0, 0, 3, "x")), 10)
        var events = _events(a)
        var replies = _out(a, 10)
        if stops[i]:
            assert_equal(len(events), 0)
        else:
            assert_equal(len(events), 1)
        var expected = String("")
        if reports[i]:
            expected += "9"
        if not stops[i]:
            if reports[i]:
                expected += ","
            expected += "3"
        if expected == "":
            assert_equal(len(replies), 0)
            continue
        assert_equal(len(replies), 1)
        assert_equal(_kinds(replies[0]), expected)
        if reports[i]:
            var causes = decode_causes(Span(_value(replies[0], 0)))
            assert_true(causes[0].code == CAUSE_UNRECOGNIZED_CHUNK)
            # The cause carries the header of the offending chunk.
            assert_equal(causes[0].info[0], kinds[i])
            assert_equal(causes[0].info[3], 8)
        assert_equal(a.state(), SCTP_STATE_ESTABLISHED)


def test_abort_verification() raises:
    # Our tag, no T bit.
    var a = _established()
    var abort_chunk = List[UInt8]()
    var causes: List[ErrorCause] = []
    var why = bytes_of("going away")
    causes.append(ErrorCause(CAUSE_USER_INITIATED_ABORT, Span(why)))
    encode_abort(abort_chunk, False, Span(causes))
    _feed(a, LOCAL_TAG, abort_chunk, 10)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    var events = _events(a)
    assert_equal(len(events), 1)
    assert_equal(events[0].kind, SCTP_EVENT_CLOSED)
    assert_equal(events[0].reason, "aborted by peer: going away")
    assert_equal(len(_out(a, 10)), 0)
    # The tag we send, reflected with the T bit.
    var b = _established()
    var reflected = List[UInt8]()
    var none = List[ErrorCause]()
    encode_abort(reflected, True, Span(none))
    _feed(b, PEER_TAG, reflected, 10)
    assert_equal(b.state(), SCTP_STATE_CLOSED)
    assert_equal(_events(b)[0].reason, "aborted by peer")
    # The reflected tag without the T bit, or a wrong tag with it: ignored.
    var c = _established()
    var plain = List[UInt8]()
    encode_abort(plain, False, Span(none))
    _feed(c, PEER_TAG, plain, 10)
    _feed(c, 0x99999999, reflected, 10)
    assert_equal(c.state(), SCTP_STATE_ESTABLISHED)
    # pion's Stop(): a user-initiated abort without text.
    _feed(c, LOCAL_TAG, _raw_chunk(CHUNK_ABORT, "000c0004"), 10)
    assert_equal(c.state(), SCTP_STATE_CLOSED)
    assert_equal(_events(c)[0].reason, "aborted by peer (cause 12)")
    # Text from the peer is made printable.
    var d = _established()
    _feed(d, LOCAL_TAG, _raw_chunk(CHUNK_ABORT, "000c0008" + "41ff0a42"), 10)
    assert_equal(_events(d)[0].reason, "aborted by peer: A??B")


def test_out_of_the_blue_packets() raises:
    var a = _assoc()
    # DATA for an association that does not exist: ABORT with the T bit,
    # reflecting the tag of the packet.
    _feed(a, 0x77777777, _data(1, 0, 0, 3, "x"), 0)
    var replies = _out(a, 0)
    assert_equal(len(replies), 1)
    assert_equal(hex_encode(Span(replies[0])[12:16]), "06010004")
    assert_equal(_tag(replies[0]), 0x77777777)
    # SHUTDOWN ACK: SHUTDOWN COMPLETE with the T bit.
    var sa = List[UInt8]()
    encode_shutdown_ack(sa)
    _feed(a, 0x77777777, sa, 0)
    var done = _out(a, 0)
    assert_equal(hex_encode(Span(done[0])[12:16]), "0e010004")
    # ABORT, COOKIE ACK, SHUTDOWN COMPLETE and ERROR are not answered.
    var none = List[ErrorCause]()
    var ab = List[UInt8]()
    encode_abort(ab, False, Span(none))
    _feed(a, 0x77777777, ab, 0)
    _feed(a, LOCAL_TAG, ab, 0)
    var ca = List[UInt8]()
    encode_cookie_ack(ca)
    _feed(a, 0x77777777, ca, 0)
    var sc = List[UInt8]()
    encode_shutdown_complete(sc, False)
    _feed(a, 0x77777777, sc, 0)
    assert_equal(len(_out(a, 0)), 0)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_equal(len(_events(a)), 0)
    # An association that has ended answers the same way: the peer should
    # learn that it is gone. ABORTs and INITs get no answer.
    var b = _established()
    b.abort("done")
    _ = _out(b, 0)
    _feed(b, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "x"), 0)
    var gone = _out(b, 0)
    assert_equal(len(gone), 1)
    assert_equal(hex_encode(Span(gone[0])[12:16]), "06010004")
    assert_equal(_tag(gone[0]), LOCAL_TAG)
    _feed(b, LOCAL_TAG, ab, 0)
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(b, 0, _peer_init(ext), 0)
    assert_equal(len(_out(b, 0)), 0)
    assert_equal(len(_events(b)), 1)
    # A fresh association does not answer a stray INIT ACK's sender with
    # anything but an ABORT either, and never establishes from it.
    var c = _assoc()
    var ack = InitChunk(PEER_TAG, 1048576, 10, 10, PEER_TSN)
    ack.cookie = bytes_of("cookie")
    var ack_chunk = List[UInt8]()
    ack.encode(ack_chunk, CHUNK_INIT_ACK)
    _feed(c, LOCAL_TAG, ack_chunk, 0)
    assert_equal(hex_encode(Span(_out(c, 0)[0])[12:16]), "06010004")
    assert_equal(c.state(), SCTP_STATE_CLOSED)


def test_local_abort_packet() raises:
    var a = _established()
    a.abort("bye")
    var replies = _out(a, 5)
    assert_equal(len(replies), 1)
    assert_equal(_tag(replies[0]), PEER_TAG)
    # The same chunk pion sends for Abort("bye").
    assert_equal(
        hex_encode(Span(replies[0])[12 : len(replies[0])]),
        "0600000b000c000762796500",
    )
    assert_equal(len(_out(a, 5)), 0)
    # Aborting before the peer is known sends nothing.
    var b = _assoc()
    b.connect(0)
    _ = _out(b, 0)
    b.abort("never mind")
    assert_equal(len(_out(b, 0)), 0)
    assert_equal(_events(b)[0].reason, "never mind")


def test_no_user_data_and_bad_sack_abort() raises:
    var a = _established()
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, ""), 10)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    var replies = _out(a, 10)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "6")
    var causes = decode_causes(Span(_value(replies[0], 0)))
    assert_true(causes[0].code == CAUSE_NO_USER_DATA)
    assert_equal(hex_encode(Span(causes[0].info)), "000003e8")
    # A SACK for a TSN that was never sent.
    var b = _established()
    _feed(b, LOCAL_TAG, _sack(LOCAL_TSN + 5), 10)
    assert_equal(b.state(), SCTP_STATE_CLOSED)
    assert_equal(_kinds(_out(b, 10)[0]), "6")
    assert_equal(
        _events(b)[0].reason, "peer acknowledged a TSN that was never sent"
    )


def test_invalid_stream_is_reported_and_acknowledged() raises:
    var a = _established()
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 65535, 0, 3, "x"), 10)
    assert_equal(len(_events(a)), 0)
    var replies = _out(a, 10)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "9,3")
    var causes = decode_causes(Span(_value(replies[0], 0)))
    assert_true(causes[0].code == CAUSE_INVALID_STREAM)
    assert_equal(hex_encode(Span(causes[0].info)), "ffff0000")
    assert_equal(
        decode_sack(Span(_value(replies[0], 1))).cumulative_tsn, PEER_TSN
    )


def _reconfig(params: List[ReconfigParam]) -> List[UInt8]:
    var out = List[UInt8]()
    encode_reconfig(out, Span(params))
    return out^


def _reset_request(
    seq: UInt32, last_tsn: UInt32, stream: UInt16
) -> List[UInt8]:
    var streams: List[UInt16] = [stream]
    var params: List[ReconfigParam] = []
    params.append(outgoing_reset_request(seq, 0, last_tsn, Span(streams)))
    return _reconfig(params)


def _response_of(packet: List[UInt8], index: Int) raises -> ReconfigParam:
    var params = decode_reconfig(Span(_value(packet, index)))
    assert_equal(len(params), 1)
    assert_true(params[0].kind == PARAM_RECONFIG_RESPONSE)
    return params[0].copy()


def test_incoming_stream_reset() raises:
    var a = _established()
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 4, 0, 3, "a"), 10)
    _ = _out(a, 10)
    _ = _events(a)
    # pion's first request carries its initial TSN as sequence number.
    _feed(a, LOCAL_TAG, _reset_request(PEER_TSN, PEER_TSN, 4), 20)
    var replies = _out(a, 20)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "130")
    var response = _response_of(replies[0], 0)
    assert_equal(response.request_seq, PEER_TSN)
    assert_true(response.result == RECONFIG_RESULT_PERFORMED)
    var events = _events(a)
    assert_equal(len(events), 1)
    assert_equal(events[0].kind, SCTP_EVENT_STREAM_RESET)
    assert_equal(events[0].stream_id, 4)
    # A retransmitted request is answered again but not reported again.
    _feed(a, LOCAL_TAG, _reset_request(PEER_TSN, PEER_TSN, 4), 30)
    var again = _response_of(_out(a, 30)[0], 0)
    assert_true(again.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(_events(a)), 0)
    # An older sequence number is an error.
    _feed(a, LOCAL_TAG, _reset_request(PEER_TSN - 3, PEER_TSN, 4), 40)
    var old = _response_of(_out(a, 40)[0], 0)
    assert_equal(old.request_seq, PEER_TSN - 3)
    assert_true(old.result == RECONFIG_RESULT_BAD_SEQUENCE)
    assert_equal(len(_events(a)), 0)
    # After the reset the stream starts again at sequence number 0.
    _feed(a, LOCAL_TAG, _data(PEER_TSN + 1, 4, 0, 3, "b"), 50)
    var after = _events(a)
    assert_equal(len(after), 1)
    assert_equal(string_of(Span(after[0].payload)), "b")


def test_incoming_stream_reset_waits_for_missing_data() raises:
    var a = _established()
    # The request says data up to PEER_TSN + 1 precedes it, but it has not
    # arrived yet.
    _feed(a, LOCAL_TAG, _reset_request(PEER_TSN, PEER_TSN + 1, 4), 10)
    var first = _response_of(_out(a, 10)[0], 0)
    assert_true(first.result == RECONFIG_RESULT_IN_PROGRESS)
    assert_equal(len(_events(a)), 0)
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 4, 0, 3, "a"), 20)
    assert_equal(_kinds(_out(a, 20)[0]), "3")
    assert_equal(len(_events(a)), 1)
    # The last missing chunk arrives: data first, then the reset, and the
    # response goes out without waiting for a retransmitted request.
    _feed(a, LOCAL_TAG, _data(PEER_TSN + 1, 4, 1, 3, "b"), 30)
    var events = _events(a)
    assert_equal(len(events), 2)
    assert_equal(events[0].kind, SCTP_EVENT_MESSAGE)
    assert_equal(events[1].kind, SCTP_EVENT_STREAM_RESET)
    var replies = _out(a, 30)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "130,3")
    var done = _response_of(replies[0], 0)
    assert_equal(done.request_seq, PEER_TSN)
    assert_true(done.result == RECONFIG_RESULT_PERFORMED)


def test_other_reconfig_requests() raises:
    var a = _established()
    # Incoming SSN Reset Request: the peer asks us to reset our stream 6.
    var incoming = ReconfigParam(PARAM_INCOMING_RESET, PEER_TSN)
    incoming.streams = [6]
    var params: List[ReconfigParam] = []
    params.append(incoming^)
    _feed(a, LOCAL_TAG, _reconfig(params), 10)
    var replies = _out(a, 10)
    # The response, and our own Outgoing SSN Reset Request for stream 6.
    var responses = 0
    var requests = 0
    for i in range(len(replies)):
        var view = parse_packet(Span(replies[i]))
        for c in range(len(view.chunks)):
            var ps = decode_reconfig(Span(_value(replies[i], c)))
            for k in range(len(ps)):
                if ps[k].kind == PARAM_RECONFIG_RESPONSE:
                    responses += 1
                    assert_equal(ps[k].request_seq, PEER_TSN)
                    assert_true(ps[k].result == RECONFIG_RESULT_PERFORMED)
                elif ps[k].kind == PARAM_OUTGOING_RESET:
                    requests += 1
                    assert_equal(ps[k].request_seq, LOCAL_TSN)
                    # It names the peer's request as the last one seen.
                    assert_equal(ps[k].response_seq, PEER_TSN)
                    assert_equal(ps[k].last_tsn, LOCAL_TSN - 1)
                    assert_equal(ps[k].streams[0], 6)
    assert_equal(responses, 1)
    assert_equal(requests, 1)
    # Adding streams is not supported: denied.
    var add = ReconfigParam(PARAM_ADD_OUTGOING_STREAMS, PEER_TSN + 1)
    add.count = 4
    var more: List[ReconfigParam] = []
    more.append(add^)
    _feed(a, LOCAL_TAG, _reconfig(more), 20)
    var denied = _response_of(_out(a, 20)[0], 0)
    assert_equal(denied.request_seq, PEER_TSN + 1)
    assert_true(denied.result == RECONFIG_RESULT_DENIED)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)


def test_outgoing_stream_reset_is_retransmitted_until_answered() raises:
    var a = _established()
    var m = bytes_of("last words")
    a.send(9, 53, Span(m), False, -1)
    a.reset_stream(9)
    var first = _out(a, 0)
    # The data goes first; the request follows once it has a TSN.
    assert_equal(len(first), 2)
    assert_equal(_kinds(first[0]), "0")
    assert_equal(_kinds(first[1]), "130")
    var request = decode_reconfig(Span(_value(first[1], 0)))
    assert_true(request[0].kind == PARAM_OUTGOING_RESET)
    assert_equal(request[0].request_seq, LOCAL_TSN)
    assert_equal(request[0].last_tsn, LOCAL_TSN)
    assert_equal(request[0].streams[0], 9)
    _feed(a, LOCAL_TAG, _sack(LOCAL_TSN), 5)
    # No answer: the same request again after the timeout.
    assert_equal(a.next_timeout().value(), 1000)
    a.handle_timeout(1000)
    var second = _out(a, 1000)
    assert_equal(len(second), 1)
    assert_equal(
        hex_encode(Span(_value(second[0], 0))),
        hex_encode(Span(_value(first[1], 0))),
    )
    # "In progress" keeps the request alive.
    var params: List[ReconfigParam] = []
    params.append(reconfig_response(LOCAL_TSN, RECONFIG_RESULT_IN_PROGRESS))
    _feed(a, LOCAL_TAG, _reconfig(params), 1100)
    assert_true(Bool(a.next_timeout()))
    # Data queued on the stream meanwhile waits for the reset to finish.
    a.send(9, 53, Span(m), False, -1)
    assert_equal(len(_out(a, 1200)), 0)
    var done: List[ReconfigParam] = []
    done.append(reconfig_response(LOCAL_TSN, RECONFIG_RESULT_PERFORMED))
    _feed(a, LOCAL_TAG, _reconfig(done), 1300)
    var after = _out(a, 1300)
    assert_equal(len(after), 1)
    assert_equal(_kinds(after[0]), "0")
    var d = decode_data(Span(_value(after[0], 0)), 3)
    assert_equal(d.ssn, 0)
    assert_equal(d.tsn, LOCAL_TSN + 1)
    # A second reset uses the next request sequence number.
    a.reset_stream(9)
    _feed(a, LOCAL_TAG, _sack(LOCAL_TSN + 1), 1400)
    var third = _out(a, 1400)
    assert_equal(len(third), 1)
    var next = decode_reconfig(Span(_value(third[0], 0)))
    assert_equal(next[0].request_seq, LOCAL_TSN + 1)
    assert_equal(next[0].last_tsn, LOCAL_TSN + 1)


def test_peer_without_forward_tsn_gets_reliable_delivery() raises:
    var ext: List[UInt8] = [0x82]
    var a = _established_with(ext)
    var m = bytes_of("unreliable?")
    a.send(0, 53, Span(m), True, 0)
    assert_equal(_kinds(_out(a, 0)[0]), "0")
    a.handle_timeout(1000)
    # Without FORWARD-TSN there is no way to skip: retransmit instead.
    var again = _out(a, 1000)
    assert_equal(len(again), 1)
    assert_equal(_kinds(again[0]), "0")
    assert_equal(a.stats().abandoned_chunks, 0)
    # With it, the chunk is abandoned and a FORWARD-TSN goes out.
    var b = _established()
    b.send(0, 53, Span(m), True, 0)
    _ = _out(b, 0)
    b.handle_timeout(1000)
    var forward = _out(b, 1000)
    assert_equal(len(forward), 1)
    assert_equal(_kinds(forward[0]), "192")
    assert_equal(hex_encode(Span(_value(forward[0], 0))), "00001388")
    # The Forward-TSN-Supported parameter alone also enables it.
    var c = _assoc()
    _feed(
        c,
        0,
        _raw_chunk(CHUNK_INIT, "1122334400100000ffffffff000003e8" + "c0000004"),
        0,
    )
    var ack = decode_init(Span(_value(_out(c, 0)[0], 0)))
    var echo = List[UInt8]()
    encode_cookie_echo(echo, Span(ack.cookie))
    _feed(c, LOCAL_TAG, echo, 1)
    _ = _out(c, 1)
    c.send(0, 53, Span(m), True, 0)
    _ = _out(c, 1)
    c.handle_timeout(1001)
    assert_equal(_kinds(_out(c, 1001)[0]), "192")


def test_active_open_timers_and_stale_cookie() raises:
    var a = _assoc()
    a.connect(0)
    assert_equal(a.state(), SCTP_STATE_COOKIE_WAIT)
    var first = _out(a, 0)
    assert_equal(len(first), 1)
    assert_equal(_kinds(first[0]), "1")
    assert_equal(_tag(first[0]), 0)
    assert_equal(a.next_timeout().value(), 1000)
    # Calling connect again changes nothing.
    a.connect(10)
    assert_equal(len(_out(a, 10)), 0)
    a.handle_timeout(999)
    assert_equal(len(_out(a, 999)), 0)
    a.handle_timeout(1000)
    var second = _out(a, 1000)
    assert_equal(len(second), 1)
    # The retransmitted INIT is the same packet.
    assert_equal(hex_encode(Span(second[0])), hex_encode(Span(first[0])))
    assert_equal(a.next_timeout().value(), 3000)
    # INIT ACK from the peer.
    var ack = InitChunk(PEER_TAG, 1048576, 65535, 65535, PEER_TSN)
    ack.extensions = [0x82, 0xC0]
    ack.cookie = bytes_of("peer cookie bytes")
    var ack_chunk = List[UInt8]()
    ack.encode(ack_chunk, CHUNK_INIT_ACK)
    _feed(a, LOCAL_TAG, ack_chunk, 1500)
    assert_equal(a.state(), SCTP_STATE_COOKIE_ECHOED)
    var echo = _out(a, 1500)
    assert_equal(len(echo), 1)
    assert_equal(_kinds(echo[0]), "10")
    assert_equal(_tag(echo[0]), PEER_TAG)
    assert_equal(string_of(Span(_value(echo[0], 0))), "peer cookie bytes")
    assert_equal(a.next_timeout().value(), 2500)
    # A second INIT ACK is ignored now.
    _feed(a, LOCAL_TAG, ack_chunk, 1600)
    assert_equal(len(_out(a, 1600)), 0)
    # T1-cookie retransmits the COOKIE ECHO.
    a.handle_timeout(2500)
    var echo2 = _out(a, 2500)
    assert_equal(hex_encode(Span(echo2[0])), hex_encode(Span(echo[0])))
    # The peer reports the cookie stale: back to INIT.
    var err = List[UInt8]()
    var causes: List[ErrorCause] = []
    var staleness = hex_decode("00000001")
    causes.append(ErrorCause(CAUSE_STALE_COOKIE, Span(staleness)))
    encode_error(err, Span(causes))
    _feed(a, LOCAL_TAG, err, 2600)
    assert_equal(a.state(), SCTP_STATE_COOKIE_WAIT)
    assert_equal(_kinds(_out(a, 2600)[0]), "1")
    _feed(a, LOCAL_TAG, ack_chunk, 2700)
    _ = _out(a, 2700)
    var ca = List[UInt8]()
    encode_cookie_ack(ca)
    _feed(a, LOCAL_TAG, ca, 2800)
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    assert_false(Bool(a.next_timeout()))
    var events = _events(a)
    assert_equal(len(events), 1)
    assert_equal(events[0].kind, SCTP_EVENT_CONNECTED)
    # A duplicate COOKIE ACK is ignored.
    _feed(a, LOCAL_TAG, ca, 2900)
    assert_equal(len(_events(a)), 0)


def test_data_before_cookie_ack_is_accepted() raises:
    # The peer's COOKIE ACK was lost but its DATA arrives.
    var a = _assoc()
    a.connect(0)
    _ = _out(a, 0)
    var ack = InitChunk(PEER_TAG, 1048576, 65535, 65535, PEER_TSN)
    ack.extensions = [0x82, 0xC0]
    ack.cookie = bytes_of("cookie")
    var ack_chunk = List[UInt8]()
    ack.encode(ack_chunk, CHUNK_INIT_ACK)
    _feed(a, LOCAL_TAG, ack_chunk, 10)
    _ = _out(a, 10)
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "early"), 20)
    var events = _events(a)
    assert_equal(len(events), 1)
    assert_equal(events[0].kind, SCTP_EVENT_MESSAGE)
    assert_equal(_kinds(_out(a, 20)[0]), "3")
    assert_equal(a.state(), SCTP_STATE_COOKIE_ECHOED)


def test_init_while_established_does_not_disturb() raises:
    var a = _established()
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(a, 0, _peer_init(ext), 100)
    var replies = _out(a, 100)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "2")
    assert_equal(a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(len(_events(a)), 0)
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "still here"), 110)
    assert_equal(len(_events(a)), 1)


def test_shutdown_initiated_by_peer() raises:
    var a = _established()
    var m = bytes_of("pending")
    a.send(0, 53, Span(m), False, -1)
    _ = _out(a, 0)
    var sd = List[UInt8]()
    encode_shutdown(sd, LOCAL_TSN - 1)
    _feed(a, LOCAL_TAG, sd, 10)
    # Our data is not acknowledged yet: keep flushing.
    assert_equal(a.state(), SCTP_STATE_SHUTDOWN_RECEIVED)
    assert_equal(len(_out(a, 10)), 0)
    with assert_raises():
        a.send(0, 53, Span(m), False, -1)
    var sd2 = List[UInt8]()
    encode_shutdown(sd2, LOCAL_TSN)
    _feed(a, LOCAL_TAG, sd2, 20)
    assert_equal(a.state(), SCTP_STATE_SHUTDOWN_ACK_SENT)
    var replies = _out(a, 20)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "8")
    # T2 retransmits the SHUTDOWN ACK.
    assert_equal(a.next_timeout().value(), 1020)
    a.handle_timeout(1020)
    assert_equal(_kinds(_out(a, 1020)[0]), "8")
    # An INIT in this state is answered with the SHUTDOWN ACK again.
    var ext: List[UInt8] = [0x82, 0xC0]
    _feed(a, 0, _peer_init(ext), 1100)
    assert_equal(_kinds(_out(a, 1100)[0]), "8")
    var sc = List[UInt8]()
    encode_shutdown_complete(sc, False)
    _feed(a, LOCAL_TAG, sc, 1200)
    assert_equal(a.state(), SCTP_STATE_CLOSED)
    assert_equal(_events(a)[0].reason, "shutdown complete")
    assert_false(Bool(a.next_timeout()))


def test_local_shutdown_packets() raises:
    var a = _established()
    _feed(a, LOCAL_TAG, _data(PEER_TSN, 0, 0, 3, "x"), 5)
    _ = _out(a, 5)
    a.shutdown(10)
    var replies = _out(a, 10)
    assert_equal(len(replies), 1)
    assert_equal(_kinds(replies[0]), "7")
    # SHUTDOWN carries our cumulative TSN ack.
    assert_equal(decode_shutdown(Span(_value(replies[0], 0))), PEER_TSN)
    # DATA arriving now is answered with SHUTDOWN and a SACK.
    _feed(a, LOCAL_TAG, _data(PEER_TSN + 1, 0, 1, 3, "late"), 20)
    assert_equal(len(_events(a)), 2)
    var again = _out(a, 20)
    assert_equal(len(again), 1)
    assert_equal(_kinds(again[0]), "7,3")
    assert_equal(decode_shutdown(Span(_value(again[0], 0))), PEER_TSN + 1)
    var sa = List[UInt8]()
    encode_shutdown_ack(sa)
    _feed(a, LOCAL_TAG, sa, 30)
    var done = _out(a, 30)
    assert_equal(len(done), 1)
    assert_equal(_kinds(done[0]), "14")
    assert_equal(hex_encode(Span(done[0])[12:16]), "0e000004")
    assert_equal(a.state(), SCTP_STATE_CLOSED)


def test_counters_and_idle_state() raises:
    var a = _established()
    assert_false(Bool(a.next_timeout()))
    assert_false(Bool(a.poll_transmit(5)))
    assert_false(Bool(a.poll_event()))
    assert_equal(a.buffered_amount(), 0)
    var m = List[UInt8](length=3000, fill=1)
    a.send(0, 53, Span(m), False, -1)
    assert_equal(a.buffered_amount(), 3000)
    var sent = _out(a, 10)
    assert_equal(len(sent), 3)
    assert_equal(a.next_timeout().value(), 1010)
    var s = a.stats()
    assert_equal(s.messages_out, 1)
    assert_equal(s.data_chunks_out, 3)
    assert_equal(s.packets_in, 2)
    assert_equal(s.packets_out, 5)
    assert_true(s.bytes_out > 3000)
    assert_true(a.congestion_window() == 4380)
    assert_equal(a.rto_ms(), 1000)
    _feed(a, LOCAL_TAG, _sack(LOCAL_TSN + 2), 110)
    assert_equal(a.buffered_amount(), 0)
    assert_false(Bool(a.next_timeout()))
    # RTT 100 ms: the RTO stays at its 1 s floor.
    assert_equal(a.rto_ms(), 1000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
