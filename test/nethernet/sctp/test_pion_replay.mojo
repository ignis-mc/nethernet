"""Lock-step replay of recorded pion/sctp transcripts.

The association under test takes the place of pion side B. Its tag and initial
TSN are set to the ones pion B used, so that the recorded packets of pion A are
valid for it unchanged. The only packet that has to be rebuilt is A's COOKIE
ECHO, which must echo this library's cookie instead of pion B's. Whatever the
application on pion B did (answer a DCEP OPEN, close a stream) is mirrored at
the same point of the transcript. What the association then sends is compared
with what pion B sent: byte for byte where the encoding leaves no choice, by
content otherwise.
"""

from nethernet.sctp.association import Association
from nethernet.sctp.chunk import decode_init, decode_sack, encode_cookie_echo
from nethernet.sctp.reconfig import (
    PARAM_OUTGOING_RESET,
    PARAM_RECONFIG_RESPONSE,
    decode_reconfig,
)
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SCTP_STATE_CLOSED,
    SCTP_STATE_ESTABLISHED,
    SctpConfig,
    SctpEvent,
)
from nethernet.sctp.packet import (
    CHUNK_COOKIE_ACK,
    CHUNK_COOKIE_ECHO,
    CHUNK_DATA,
    CHUNK_FORWARD_TSN,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_RECONFIG,
    CHUNK_SACK,
    begin_packet,
    finish_packet,
    parse_packet,
)
from nethernet.wire import hex_decode, hex_encode
from pion_vectors import pion_collision, pion_cs, pion_fwd, pion_loss
from std.testing import TestSuite, assert_equal, assert_false, assert_true


struct Replay(Movable):
    var assoc: Association
    var mine: List[List[UInt8]]
    """Every packet the association under test sent."""
    var theirs: List[List[UInt8]]
    """Every packet pion B sent in the recording."""
    var events: List[SctpEvent]
    var b_got: List[String]
    """What the application on pion B received: `stream=.. ppi=.. len=..`."""
    var now: Int

    def __init__(out self, var assoc: Association):
        self.assoc = assoc^
        self.mine = List[List[UInt8]]()
        self.theirs = List[List[UInt8]]()
        self.events = List[SctpEvent]()
        self.b_got = List[String]()
        self.now = 0

    def drain(mut self):
        while True:
            var p = self.assoc.poll_transmit(self.now)
            if not p:
                break
            self.mine.append(p.value().copy())
        while True:
            var e = self.assoc.poll_event()
            if not e:
                break
            self.events.append(e.value().copy())


def _first_kind(packet: List[UInt8]) raises -> UInt8:
    var view = parse_packet(Span(packet))
    return view.chunks[0].kind


def _chunks_of(packets: List[List[UInt8]], kind: UInt8) raises -> List[String]:
    """Hex of every chunk of one type (header, value, padding), in order."""
    var out = List[String]()
    for i in range(len(packets)):
        var view = parse_packet(Span(packets[i]))
        for c in view.chunks:
            if c.kind != kind:
                continue
            var end = c.offset + c.length
            while end % 4 != 0 and end < len(packets[i]):
                end += 1
            out.append(hex_encode(Span(packets[i])[c.offset - 4 : end]))
    return out^


def _values_of(
    packets: List[List[UInt8]], kind: UInt8
) raises -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    for i in range(len(packets)):
        var view = parse_packet(Span(packets[i]))
        for c in view.chunks:
            if c.kind == kind:
                out.append(
                    List[UInt8](
                        Span(packets[i])[c.offset : c.offset + c.length]
                    )
                )
    return out^


def _packets_of(packets: List[List[UInt8]], kind: UInt8) raises -> List[String]:
    """Hex of every packet whose first chunk has the given type."""
    var out = List[String]()
    for i in range(len(packets)):
        if _first_kind(packets[i]) == kind:
            out.append(hex_encode(Span(packets[i])))
    return out^


def _sack_summaries(packets: List[List[UInt8]]) raises -> List[String]:
    """`cum:start-end,...` for every SACK, without the window."""
    var out = List[String]()
    var values = _values_of(packets, CHUNK_SACK)
    for i in range(len(values)):
        var sack = decode_sack(Span(values[i]))
        var text = String(sack.cumulative_tsn)
        text += ":"
        for g in sack.gaps:
            text += String(t"{g.start}-{g.end},")
        out.append(text)
    return out^


def _is_subsequence(needles: List[String], haystack: List[String]) -> Bool:
    var j = 0
    for i in range(len(needles)):
        while j < len(haystack) and haystack[j] != needles[i]:
            j += 1
        if j == len(haystack):
            return False
        j += 1
    return True


def _go_pattern(n: Int, seed: Int) -> List[UInt8]:
    """The payload pattern of the recorder: byte(i * 7) + seed."""
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8((i * 7 + seed) & 0xFF))
    return out^


def _same(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _run(lines: List[String], connect: Bool) raises -> Replay:
    # Take pion B's tag and initial TSN from its first packet.
    var tag = UInt32(0)
    var tsn = UInt32(0)
    for i in range(len(lines)):
        if lines[i].startswith("B "):
            var parts = lines[i].split(" ")
            var first = hex_decode(parts[2])
            var view = parse_packet(Span(first))
            var init = decode_init(
                Span(first)[
                    view.chunks[0].offset : view.chunks[0].offset
                    + view.chunks[0].length
                ]
            )
            tag = init.initiate_tag
            tsn = init.initial_tsn
            break
    var secret: List[UInt8] = [9, 8, 7, 6, 5, 4, 3, 2, 1]
    var r = Replay(Association(SctpConfig(tag, tsn, Span(secret))))
    if connect:
        r.assoc.connect(0)
        r.drain()
    var ack: List[UInt8] = [2, 0, 0, 0]
    for i in range(len(lines)):
        var line = lines[i]
        if line.startswith("# B got "):
            # "stream=0 ppi=50 len=31": mirror pion B's application, which
            # answers every DCEP message with a 4-byte ACK.
            var what = String(line[byte = 8 : line.byte_length()])
            r.b_got.append(what)
            var fields = what.split(" ")
            var stream = Int(String(fields[0]).removeprefix("stream="))
            if fields[1] == "ppi=50":
                r.assoc.send(UInt16(stream), 50, Span(ack), False, -1)
            r.drain()
            continue
        if line.startswith("# B stream 2 read end: EOF"):
            r.assoc.reset_stream(2)
            r.drain()
            continue
        if line.startswith("#") or line.startswith("A! "):
            continue
        var parts = line.split(" ")
        r.now = Int(String(parts[1]))
        r.assoc.handle_timeout(r.now)
        r.drain()
        var packet = hex_decode(parts[2])
        if parts[0] == "B":
            r.theirs.append(packet^)
            continue
        if _first_kind(packet) == CHUNK_COOKIE_ECHO:
            # Echo our cookie in place of pion B's.
            var acks = _values_of(r.mine, CHUNK_INIT_ACK)
            assert_true(len(acks) >= 1)
            var mine_ack = decode_init(Span(acks[len(acks) - 1]))
            var rebuilt = List[UInt8]()
            begin_packet(rebuilt, 5000, 5000, tag)
            encode_cookie_echo(rebuilt, Span(mine_ack.cookie))
            finish_packet(rebuilt)
            packet = rebuilt^
        r.assoc.handle_packet(Span(packet), r.now)
        r.drain()
    return r^


def _messages(events: List[SctpEvent]) -> List[SctpEvent]:
    var out = List[SctpEvent]()
    for i in range(len(events)):
        if events[i].kind == SCTP_EVENT_MESSAGE:
            out.append(events[i].copy())
    return out^


def _check_common(r: Replay, lost_unordered: Bool) raises:
    # Nothing pion sent was dropped as malformed or mis-tagged.
    assert_equal(r.assoc.stats().packets_dropped, 0)
    # Messages: same stream, PPID and length as pion B's application saw,
    # in the same order, and the right bytes.
    var got = _messages(r.events)
    assert_equal(len(got), len(r.b_got))
    for i in range(len(got)):
        assert_equal(
            String(
                t"stream={got[i].stream_id} ppi={got[i].ppid}"
                t" len={len(got[i].payload)}"
            ),
            r.b_got[i],
        )
    var open0 = hex_decode(
        "03000100000000000013000052656c6961626c65446174614368616e6e656c"
    )
    var open2 = hex_decode(
        "038101000000000000150000556e72656c6961626c65446174614368616e6e656c"
    )
    var at = 0
    assert_true(_same(got[at].payload, open0))
    assert_false(got[at].unordered)
    at += 1
    assert_true(_same(got[at].payload, _go_pattern(3000, 3)))
    at += 1
    assert_true(_same(got[at].payload, open2))
    at += 1
    if not lost_unordered:
        assert_true(_same(got[at].payload, _go_pattern(100, 9)))
        assert_true(got[at].unordered)
        assert_equal(got[at].stream_id, 2)
        at += 1
    assert_true(_same(got[at].payload, _go_pattern(10, 1)))
    assert_true(_same(got[at + 1].payload, _go_pattern(20, 2)))
    assert_equal(len(got), at + 2)

    # DATA: the two DCEP ACKs, byte for byte what pion B sent.
    var my_data = _chunks_of(r.mine, CHUNK_DATA)
    var their_data = _chunks_of(r.theirs, CHUNK_DATA)
    assert_equal(len(their_data), 2)
    assert_equal(len(my_data), 2)
    assert_equal(my_data[0], their_data[0])
    assert_equal(my_data[1], their_data[1])

    # COOKIE ACK: the whole packet matches, checksum included.
    var my_ack = _packets_of(r.mine, CHUNK_COOKIE_ACK)
    var their_ack = _packets_of(r.theirs, CHUNK_COOKIE_ACK)
    assert_equal(len(my_ack), 1)
    assert_equal(my_ack[0], their_ack[0])

    # SACK: pion B delays and so sends fewer, but each of its SACKs (same
    # cumulative TSN, same gap blocks) is among ours, in order.
    var my_sacks = _sack_summaries(r.mine)
    var their_sacks = _sack_summaries(r.theirs)
    assert_true(len(their_sacks) >= 4)
    assert_true(_is_subsequence(their_sacks, my_sacks))
    assert_equal(my_sacks[len(my_sacks) - 1], their_sacks[len(their_sacks) - 1])

    # RE-CONFIG: the response to pion's reset request is identical; our own
    # request asks for the same thing as pion B's.
    var my_reconf = _values_of(r.mine, CHUNK_RECONFIG)
    var their_reconf = _values_of(r.theirs, CHUNK_RECONFIG)
    assert_equal(len(my_reconf), 2)
    assert_equal(len(their_reconf), 2)
    var my_response = decode_reconfig(Span(my_reconf[0]))
    assert_true(my_response[0].kind == PARAM_RECONFIG_RESPONSE)
    assert_equal(
        hex_encode(Span(my_reconf[0])), hex_encode(Span(their_reconf[0]))
    )
    var my_request = decode_reconfig(Span(my_reconf[1]))
    var their_request = decode_reconfig(Span(their_reconf[1]))
    assert_true(my_request[0].kind == PARAM_OUTGOING_RESET)
    assert_true(their_request[0].kind == PARAM_OUTGOING_RESET)
    assert_equal(my_request[0].request_seq, their_request[0].request_seq)
    assert_equal(my_request[0].last_tsn, their_request[0].last_tsn)
    assert_equal(len(my_request[0].streams), 1)
    assert_equal(my_request[0].streams[0], their_request[0].streams[0])

    # Events: connected once, stream 2 reset once, closed by pion's ABORT.
    var connected = 0
    var resets = 0
    var closed = 0
    for i in range(len(r.events)):
        if r.events[i].kind == SCTP_EVENT_CONNECTED:
            connected += 1
        elif r.events[i].kind == SCTP_EVENT_STREAM_RESET:
            resets += 1
            assert_equal(r.events[i].stream_id, 2)
        elif r.events[i].kind == SCTP_EVENT_CLOSED:
            closed += 1
            assert_equal(r.events[i].reason, "aborted by peer: bye")
    assert_equal(connected, 1)
    assert_equal(resets, 1)
    assert_equal(closed, 1)
    assert_equal(r.assoc.state(), SCTP_STATE_CLOSED)
    # pion acknowledged everything we sent; nothing was retransmitted.
    assert_equal(r.assoc.stats().retransmits, 0)
    assert_equal(r.assoc.stats().t3_expiries, 0)


def test_replay_pion_client_against_passive_side() raises:
    var r = _run(pion_cs(), False)
    _check_common(r, False)
    # Our INIT ACK: pion B's tag and TSN, a usable window, both extensions
    # pion needs and no I-DATA.
    var acks = _values_of(r.mine, CHUNK_INIT_ACK)
    assert_equal(len(acks), 1)
    var mine = decode_init(Span(acks[0]))
    var theirs = decode_init(Span(_values_of(r.theirs, CHUNK_INIT_ACK)[0]))
    assert_equal(mine.initiate_tag, theirs.initiate_tag)
    assert_equal(mine.initial_tsn, theirs.initial_tsn)
    assert_equal(mine.a_rwnd, theirs.a_rwnd)
    assert_equal(mine.num_outbound_streams, theirs.num_outbound_streams)
    assert_equal(mine.num_inbound_streams, theirs.num_inbound_streams)
    assert_true(len(mine.cookie) > 0)
    assert_true(mine.supports_extension(0x82))
    assert_true(mine.supports_extension(0xC0))
    assert_false(mine.supports_extension(0x40))
    assert_false(mine.supports_extension(0xC2))
    assert_equal(hex_encode(Span(theirs.extensions)), "82c0")
    # The INIT ACK is addressed with pion A's initiate tag.
    var a_init = hex_decode(String(pion_cs()[0].split(" ")[2]))
    var a_tag = decode_init(Span(a_init)[16 : len(a_init)]).initiate_tag
    for i in range(len(r.mine)):
        var view = parse_packet(Span(r.mine[i]))
        assert_equal(view.verification_tag, a_tag)
        assert_equal(view.source_port, 5000)
        assert_equal(view.destination_port, 5000)
    # We never sent an INIT of our own.
    assert_equal(len(_chunks_of(r.mine, CHUNK_INIT)), 0)


def test_replay_pion_init_collision() raises:
    var r = _run(pion_collision(), True)
    _check_common(r, False)
    # Our INIT and INIT ACK carry the same tag and initial TSN.
    var inits = _values_of(r.mine, CHUNK_INIT)
    var acks = _values_of(r.mine, CHUNK_INIT_ACK)
    assert_equal(len(inits), 1)
    assert_equal(len(acks), 1)
    var init = decode_init(Span(inits[0]))
    var ack = decode_init(Span(acks[0]))
    assert_equal(init.initiate_tag, ack.initiate_tag)
    assert_equal(init.initial_tsn, ack.initial_tsn)
    assert_equal(len(init.cookie), 0)
    var their_init = decode_init(Span(_values_of(r.theirs, CHUNK_INIT)[0]))
    assert_equal(init.initiate_tag, their_init.initiate_tag)
    assert_equal(init.initial_tsn, their_init.initial_tsn)
    assert_equal(init.a_rwnd, their_init.a_rwnd)
    assert_equal(hex_encode(Span(init.extensions)), "82c0")
    # The INIT goes out with verification tag 0.
    var init_packets = _packets_of(r.mine, CHUNK_INIT)
    assert_true(init_packets[0].startswith("1388138800000000"))
    # Our COOKIE ECHO of pion A's cookie is the packet pion B sent.
    var my_echo = _packets_of(r.mine, CHUNK_COOKIE_ECHO)
    var their_echo = _packets_of(r.theirs, CHUNK_COOKIE_ECHO)
    assert_equal(len(my_echo), 1)
    assert_equal(my_echo[0], their_echo[0])


def test_replay_pion_forward_tsn() raises:
    var r = _run(pion_fwd(), True)
    _check_common(r, True)
    # The transcript really contains pion's FORWARD-TSN, and our SACK right
    # after it acknowledges the skipped TSN like pion B's did.
    var lines = pion_fwd()
    var forwards = 0
    for i in range(len(lines)):
        if lines[i].startswith("A "):
            var p = hex_decode(String(lines[i].split(" ")[2]))
            if _first_kind(p) == CHUNK_FORWARD_TSN:
                forwards += 1
    assert_equal(forwards, 1)
    assert_equal(r.assoc.receive_buffered(), 0)


def test_replay_pion_retransmission_after_gap() raises:
    var r = _run(pion_loss(), True)
    _check_common(r, False)
    # While the middle fragment was missing we reported the gap, with the
    # same block pion B reported.
    var their_sacks = _sack_summaries(r.theirs)
    var gap_seen = False
    for i in range(len(their_sacks)):
        if their_sacks[i].endswith(":2-2,"):
            gap_seen = True
    assert_true(gap_seen)
    assert_equal(r.assoc.stats().duplicate_tsns, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
