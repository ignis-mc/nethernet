from nethernet.sctp.chunk import (
    DataChunk,
    ForwardTsnChunk,
    GapBlock,
    SackChunk,
    decode_data,
    decode_forward_tsn,
)
from nethernet.sctp.packet import (
    CHUNK_DATA,
    CHUNK_FORWARD_TSN,
    begin_packet,
    finish_packet,
    parse_packet,
)
from nethernet.sctp.sender import Sender, fragment_size_for_mtu, initial_cwnd
from std.testing import TestSuite, assert_equal, assert_false, assert_true

comptime MTU = 1200
comptime FRAG = 1156


struct Flight(Movable):
    """What a sender emitted until it had nothing more to send."""

    var data: List[DataChunk]
    var forwards: List[ForwardTsnChunk]
    var packets: Int

    def __init__(out self):
        self.data = List[DataChunk]()
        self.forwards = List[ForwardTsnChunk]()
        self.packets = 0


def _flush(mut s: Sender, now: Int) raises -> Flight:
    var f = Flight()
    while True:
        var out = List[UInt8]()
        begin_packet(out, 5000, 5000, 1)
        if s.fill(out, MTU, now) == 0:
            break
        finish_packet(out)
        assert_true(len(out) <= MTU)
        f.packets += 1
        var view = parse_packet(Span(out))
        for c in view.chunks:
            var value = Span(out)[c.offset : c.offset + c.length]
            if c.kind == CHUNK_DATA:
                f.data.append(decode_data(value, c.flags))
            elif c.kind == CHUNK_FORWARD_TSN:
                f.forwards.append(decode_forward_tsn(value))
    return f^


def _sender(initial_tsn: UInt32, rwnd: UInt32) -> Sender:
    var s = Sender(initial_tsn, MTU, 1000, 1000, 60000)
    s.set_peer(rwnd, True)
    return s^


def _queue(mut s: Sender, stream: UInt16, size: Int, unordered: Bool, max_rtx: Int):
    var payload = List[UInt8](length=size, fill=UInt8(size & 0xFF))
    s.queue_message(stream, 53, Span(payload), unordered, max_rtx)


def _ack(mut s: Sender, cum: UInt32, now: Int) raises:
    assert_true(s.on_sack(SackChunk(cum, 1 << 20), now))


def test_window_constants() raises:
    assert_equal(initial_cwnd(1200), 4380)
    assert_equal(initial_cwnd(1500), 4380)
    assert_equal(initial_cwnd(500), 2000)
    assert_equal(initial_cwnd(3000), 6000)
    assert_equal(fragment_size_for_mtu(1200), 1156)
    assert_equal(fragment_size_for_mtu(1191), 1144)
    assert_equal(fragment_size_for_mtu(10), 4)


def test_fragmentation_flags_and_sequence_numbers() raises:
    var s = _sender(100, 1 << 20)
    _queue(s, 3, 2 * FRAG + 10, False, -1)
    _queue(s, 3, 5, False, -1)
    _queue(s, 3, 7, True, -1)
    _queue(s, 4, 9, False, -1)
    assert_equal(s.buffered_amount(), 2 * FRAG + 10 + 5 + 7 + 9)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 6)
    # One message in three fragments: B, middle, E; same ssn throughout.
    assert_equal(f.data[0].tsn, 100)
    assert_true(f.data[0].beginning() and not f.data[0].ending())
    assert_equal(len(f.data[0].payload), FRAG)
    assert_false(f.data[1].beginning() or f.data[1].ending())
    assert_equal(len(f.data[1].payload), FRAG)
    assert_true(f.data[2].ending() and not f.data[2].beginning())
    assert_equal(len(f.data[2].payload), 10)
    for i in range(3):
        assert_equal(f.data[i].ssn, 0)
        assert_equal(f.data[i].stream_id, 3)
        assert_equal(f.data[i].ppid, 53)
        assert_equal(f.data[i].tsn, UInt32(100 + i))
    # The next ordered message on the stream gets ssn 1.
    assert_equal(f.data[3].ssn, 1)
    assert_true(f.data[3].beginning() and f.data[3].ending())
    # Unordered data does not consume a sequence number.
    assert_true(f.data[4].unordered())
    assert_equal(f.data[5].stream_id, 4)
    assert_equal(f.data[5].ssn, 0)
    assert_equal(f.data[5].tsn, 105)
    assert_equal(s.next_tsn(), 106)
    # Small chunks are bundled: 2 full packets, then the rest together.
    assert_equal(f.packets, 3)
    assert_true(s.t3.armed)
    assert_equal(s.t3.deadline, 1000)
    _ack(s, 105, 10)
    assert_equal(s.buffered_amount(), 0)
    assert_true(s.is_drained())
    assert_false(s.t3.armed)
    _queue(s, 3, 1, False, -1)
    var g = _flush(s, 20)
    assert_equal(g.data[0].ssn, 2)


def test_congestion_window_limits_the_first_flight() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 20 * FRAG, False, -1)
    var f = _flush(s, 0)
    # cwnd 4380: three fragments of 1156 fit, a fourth would exceed it.
    assert_equal(len(f.data), 3)
    assert_equal(s.cwnd(), 4380)
    # Slow start: each SACK that acks new data grows cwnd by up to one MTU.
    _ack(s, 2, 10)
    assert_equal(s.cwnd(), 4380 + 1200)
    var g = _flush(s, 10)
    assert_equal(len(g.data), 3)
    _ack(s, 4, 20)
    assert_equal(s.cwnd(), 4380 + 2400)
    var h = _flush(s, 20)
    assert_equal(len(h.data), 3)
    _ack(s, 6, 30)
    assert_equal(s.cwnd(), 4380 + 3600)


def test_cwnd_does_not_grow_when_not_fully_used() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 100, False, -1)
    _ = _flush(s, 0)
    _ack(s, 1, 10)
    assert_equal(s.cwnd(), 4380)


def test_congestion_avoidance_grows_by_one_mtu_per_window() raises:
    var s = Sender(1, MTU, 1000, 1000, 60000)
    # A small receiver window sets a low ssthresh.
    s.set_peer(4000, True)
    assert_equal(s.on_sack(SackChunk(0, 1 << 20), 0), True)
    _queue(s, 0, 200 * FRAG, False, -1)
    var now = 0
    var cum = UInt32(0)
    var last = s.cwnd()
    var grew = 0
    for _ in range(40):
        var f = _flush(s, now)
        now += 10
        cum += UInt32(len(f.data))
        _ack(s, cum, now)
        if s.cwnd() != last:
            # Above ssthresh the window grows by exactly one MTU at a time.
            assert_equal(s.cwnd() - last, 1200)
            last = s.cwnd()
            grew += 1
    assert_true(grew >= 3)
    assert_true(grew < 20)


def test_receiver_window_and_zero_window_probe() raises:
    var s = _sender(1, 3000)
    _queue(s, 0, 10 * FRAG, False, -1)
    var f = _flush(s, 0)
    # 3000 bytes of window: two fragments fit, the third does not.
    assert_equal(len(f.data), 2)
    # The peer acks both but closes its window.
    assert_true(s.on_sack(SackChunk(2, 0), 10))
    assert_equal(s.peer_rwnd(), 0)
    var probe = _flush(s, 10)
    # Exactly one chunk goes out as the zero window probe.
    assert_equal(len(probe.data), 1)
    assert_equal(probe.data[0].tsn, 3)
    assert_equal(len(_flush(s, 11).data), 0)
    # The probe is not acked while the window stays closed.
    assert_true(s.on_sack(SackChunk(2, 0), 20))
    assert_equal(len(_flush(s, 20).data), 0)
    # T3 retransmits the probe with backoff.
    assert_true(s.t3.expired(1010))
    s.on_t3_expired(1010)
    var again = _flush(s, 1010)
    assert_equal(len(again.data), 1)
    assert_equal(again.data[0].tsn, 3)
    assert_equal(s.rto.rto(), 2000)
    # The window opens: the probe is acked and data flows again.
    assert_true(s.on_sack(SackChunk(3, 100000), 1020))
    assert_true(len(_flush(s, 1020).data) >= 1)


def test_rtt_measurement_and_karn_rule() raises:
    var s = Sender(1, MTU, 1000, 100, 60000)
    s.set_peer(1 << 20, True)
    _queue(s, 0, 10, False, -1)
    _ = _flush(s, 1000)
    _ack(s, 1, 1200)
    # First measurement R = 200: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR.
    assert_equal(s.rto.srtt(), 200)
    assert_equal(s.rto.rto(), 600)
    # A retransmitted chunk gives no measurement.
    _queue(s, 0, 10, False, -1)
    _ = _flush(s, 2000)
    s.on_t3_expired(2600)
    assert_equal(s.rto.rto(), 1200)
    var again = _flush(s, 2600)
    assert_equal(len(again.data), 1)
    _ack(s, 2, 2650)
    assert_equal(s.rto.srtt(), 200)
    assert_equal(s.rto.rto(), 1200)
    assert_equal(s.retransmits, 1)
    # The next clean measurement recomputes the timeout.
    _queue(s, 0, 10, False, -1)
    _ = _flush(s, 3000)
    _ack(s, 3, 3200)
    assert_equal(s.rto.srtt(), 200)
    assert_equal(s.rto.rto(), 200 + 4 * 75)


def test_t3_backoff_and_window_collapse() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 3 * FRAG, False, -1)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 3)
    var expected = 1000
    var now = 0
    for _ in range(8):
        now = s.t3.deadline
        s.on_t3_expired(now)
        expected *= 2
        if expected > 60000:
            expected = 60000
        assert_equal(s.rto.rto(), expected)
        assert_equal(s.cwnd(), 1200)
        # Only one packet's worth is retransmitted at once.
        var r = _flush(s, now)
        assert_equal(len(r.data), 1)
        assert_equal(r.data[0].tsn, 1)
        assert_equal(s.t3.deadline, now + expected)
    assert_equal(s.t3_expiries, 8)
    # The ack lets the next marked chunk out.
    _ack(s, 1, now + 5)
    var r = _flush(s, now + 5)
    assert_true(len(r.data) >= 1)
    assert_equal(r.data[0].tsn, 2)


def test_fast_retransmit_after_three_missing_reports() raises:
    var s = _sender(10, 1 << 20)
    for _ in range(8):
        _queue(s, 0, 500, False, -1)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 8)
    assert_equal(f.data[0].tsn, 10)
    # TSN 10 is lost; 11, 12, 13 arrive one by one.
    var sack = SackChunk(9, 1 << 20)
    sack.gaps.append(GapBlock(2, 2))
    assert_true(s.on_sack(sack, 20))
    assert_equal(s.fast_retransmits, 0)
    sack.gaps[0] = GapBlock(2, 3)
    assert_true(s.on_sack(sack, 21))
    assert_equal(s.fast_retransmits, 0)
    # A duplicate SACK that acks nothing new is not a missing report.
    assert_true(s.on_sack(sack, 21))
    assert_equal(s.fast_retransmits, 0)
    sack.gaps[0] = GapBlock(2, 4)
    assert_true(s.on_sack(sack, 22))
    assert_equal(s.fast_retransmits, 1)
    # ssthresh = max(cwnd / 2, 4 * MTU) and cwnd = ssthresh.
    assert_equal(s.cwnd(), 4800)
    var r = _flush(s, 22)
    assert_true(len(r.data) >= 1)
    assert_equal(r.data[0].tsn, 10)
    assert_equal(s.retransmits, 1)
    # Further reports for the same TSN do not retransmit it again.
    sack.gaps[0] = GapBlock(2, 5)
    assert_true(s.on_sack(sack, 23))
    assert_equal(s.fast_retransmits, 1)
    assert_equal(len(_flush(s, 23).data), 0)
    _ack(s, 17, 30)
    assert_equal(s.t3_expiries, 0)
    assert_true(s.is_drained())
    # The window was not reduced a second time during recovery.
    assert_equal(s.cwnd(), 4800)


def test_gap_acked_chunks_are_not_retransmitted_by_fast_retransmit() raises:
    var s = _sender(1, 1 << 20)
    for _ in range(4):
        _queue(s, 0, 500, False, -1)
    _ = _flush(s, 0)
    # Three missing reports, one newly acked TSN at a time.
    for upto in range(2, 5):
        var one = SackChunk(0, 1 << 20)
        one.gaps.append(GapBlock(2, UInt16(upto)))
        assert_true(s.on_sack(one, 10 + upto))
    var r = _flush(s, 20)
    assert_equal(len(r.data), 1)
    assert_equal(r.data[0].tsn, 1)
    # Malformed gap blocks are ignored, not trusted.
    var bad = SackChunk(0, 1 << 20)
    bad.gaps.append(GapBlock(0, 3))
    bad.gaps.append(GapBlock(900, 2000))
    bad.gaps.append(GapBlock(3, 2))
    assert_true(s.on_sack(bad, 30))
    _ack(s, 4, 40)
    assert_true(s.is_drained())


def test_sack_for_unsent_tsn_is_a_violation() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 10, False, -1)
    _ = _flush(s, 0)
    assert_false(s.on_sack(SackChunk(2, 1 << 20), 10))
    # An old cumulative ack is ignored.
    assert_true(s.on_sack(SackChunk(0xFFFFFFF0, 1 << 20), 10))
    assert_false(s.is_drained())
    assert_true(s.on_sack(SackChunk(1, 1 << 20), 10))
    assert_true(s.is_drained())
    assert_true(s.progress)
    assert_true(s.on_sack(SackChunk(1, 1 << 20), 10))
    assert_false(s.progress)


def test_tsn_wraparound() raises:
    var s = _sender(0xFFFFFFFE, 1 << 20)
    for _ in range(4):
        _queue(s, 0, 500, False, -1)
    var f = _flush(s, 0)
    assert_equal(f.data[0].tsn, 0xFFFFFFFE)
    assert_equal(f.data[1].tsn, 0xFFFFFFFF)
    assert_equal(f.data[2].tsn, 0)
    assert_equal(f.data[3].tsn, 1)
    var sack = SackChunk(0xFFFFFFFE, 1 << 20)
    sack.gaps.append(GapBlock(2, 3))
    assert_true(s.on_sack(sack, 10))
    # The gap-acked chunks stay buffered until the cumulative ack.
    assert_equal(s.buffered_amount(), 3 * 500)
    _ack(s, 1, 20)
    assert_true(s.is_drained())
    assert_equal(s.cumulative_ack(), 1)
    assert_equal(s.next_tsn(), 2)


def test_unreliable_message_is_abandoned_on_timeout() raises:
    var s = _sender(50, 1 << 20)
    _queue(s, 1, 100, False, -1)
    _queue(s, 2, 100, True, 0)
    _queue(s, 3, 100, False, 0)
    _queue(s, 1, 100, False, -1)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 4)
    _ack(s, 50, 10)
    s.on_t3_expired(1010)
    assert_equal(s.abandoned_chunks, 2)
    assert_equal(s.buffered_amount(), 100)
    var r = _flush(s, 1010)
    # FORWARD-TSN over the two abandoned TSNs; only the ordered stream is
    # listed, with the skipped sequence number.
    assert_equal(len(r.forwards), 1)
    assert_equal(r.forwards[0].new_cumulative_tsn, 52)
    assert_equal(len(r.forwards[0].stream_ids), 1)
    assert_equal(r.forwards[0].stream_ids[0], 3)
    assert_equal(r.forwards[0].ssns[0], 0)
    # The reliable chunk behind them is retransmitted.
    assert_equal(len(r.data), 1)
    assert_equal(r.data[0].tsn, 53)
    # The FORWARD-TSN is repeated on the next timeout until acknowledged.
    s.on_t3_expired(3010)
    var again = _flush(s, 3010)
    assert_equal(len(again.forwards), 1)
    _ack(s, 53, 3020)
    assert_true(s.is_drained())
    assert_false(s.t3.armed)
    assert_equal(len(_flush(s, 3030).forwards), 0)


def test_unreliable_message_is_abandoned_by_fast_retransmit() raises:
    var s = _sender(1, 1 << 20)
    for _ in range(4):
        _queue(s, 0, 500, True, 0)
    _ = _flush(s, 0)
    for upto in range(2, 5):
        var sack = SackChunk(0, 1 << 20)
        sack.gaps.append(GapBlock(2, UInt16(upto)))
        assert_true(s.on_sack(sack, 10 + upto))
    assert_equal(s.abandoned_chunks, 1)
    assert_equal(s.retransmits, 0)
    var r = _flush(s, 20)
    assert_equal(len(r.data), 0)
    assert_equal(len(r.forwards), 1)
    assert_equal(r.forwards[0].new_cumulative_tsn, 1)
    assert_equal(len(r.forwards[0].stream_ids), 0)
    _ack(s, 4, 30)
    assert_true(s.is_drained())


def test_limited_retransmissions_count() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 100, False, 2)
    _ = _flush(s, 0)
    var now: Int
    for _ in range(2):
        now = s.t3.deadline
        s.on_t3_expired(now)
        var r = _flush(s, now)
        assert_equal(len(r.data), 1)
        assert_equal(len(r.forwards), 0)
    now = s.t3.deadline
    s.on_t3_expired(now)
    var r = _flush(s, now)
    assert_equal(len(r.data), 0)
    assert_equal(len(r.forwards), 1)
    assert_equal(s.retransmits, 2)
    assert_equal(s.abandoned_chunks, 1)


def test_partially_sent_message_is_abandoned_whole() raises:
    var s = _sender(1, 1 << 20)
    # Ten fragments, of which the first flight carries three.
    _queue(s, 6, 10 * FRAG, False, 0)
    _queue(s, 6, 20, False, -1)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 3)
    s.on_t3_expired(1000)
    assert_equal(s.abandoned_chunks, 3)
    # The unsent rest is dropped from the queue.
    assert_equal(s.buffered_amount(), 20)
    var r = _flush(s, 1000)
    assert_equal(len(r.forwards), 1)
    # One extra TSN stands for the unsent rest, so that the peer cannot
    # pass it without processing the FORWARD-TSN.
    assert_equal(r.forwards[0].new_cumulative_tsn, 4)
    assert_equal(r.forwards[0].stream_ids[0], 6)
    assert_equal(r.forwards[0].ssns[0], 0)
    # The next message follows with a fresh TSN and the next ssn.
    assert_equal(len(r.data), 1)
    assert_equal(r.data[0].tsn, 5)
    assert_equal(r.data[0].ssn, 1)
    assert_true(r.data[0].beginning() and r.data[0].ending())
    _ack(s, 5, 1010)
    assert_true(s.is_drained())


def test_without_forward_tsn_support_everything_is_reliable() raises:
    var s = Sender(1, MTU, 1000, 1000, 60000)
    s.set_peer(1 << 20, False)
    _queue(s, 0, 100, True, 0)
    _ = _flush(s, 0)
    s.on_t3_expired(1000)
    var r = _flush(s, 1000)
    assert_equal(len(r.data), 1)
    assert_equal(len(r.forwards), 0)
    assert_equal(s.abandoned_chunks, 0)


def test_reset_markers_block_the_stream_until_finished() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 2, 100, False, -1)
    s.queue_reset(2)
    _queue(s, 2, 101, False, -1)
    _queue(s, 3, 102, False, -1)
    # Nothing is ready before the data ahead of the marker went out.
    assert_equal(len(s.take_reset_ready()), 0)
    var f = _flush(s, 0)
    assert_equal(len(f.data), 1)
    assert_equal(f.data[0].ssn, 0)
    var ready = s.take_reset_ready()
    assert_equal(len(ready), 1)
    assert_equal(ready[0], 2)
    assert_equal(len(s.take_reset_ready()), 0)
    # The stream is held back, and with it the queue behind it.
    assert_equal(len(_flush(s, 1).data), 0)
    assert_equal(s.next_tsn(), 2)
    var streams: List[UInt16] = [2]
    s.finish_reset(Span(streams), True)
    var g = _flush(s, 2)
    assert_equal(len(g.data), 2)
    # Sequence numbers restart at 0 after a performed reset.
    assert_equal(g.data[0].stream_id, 2)
    assert_equal(g.data[0].ssn, 0)
    assert_equal(g.data[1].stream_id, 3)
    # A denied reset keeps counting.
    s.queue_reset(3)
    var again = s.take_reset_ready()
    assert_equal(again[0], 3)
    var three: List[UInt16] = [3]
    s.finish_reset(Span(three), False)
    _queue(s, 3, 5, False, -1)
    var h = _flush(s, 3)
    assert_equal(h.data[0].ssn, 1)


def test_clear() raises:
    var s = _sender(1, 1 << 20)
    _queue(s, 0, 10 * FRAG, False, -1)
    _ = _flush(s, 0)
    assert_true(s.t3.armed)
    assert_true(s.has_sendable())
    s.clear()
    assert_equal(s.buffered_amount(), 0)
    assert_true(s.is_drained())
    assert_false(s.t3.armed)
    assert_false(s.has_sendable())
    assert_equal(s.inflight_count(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
