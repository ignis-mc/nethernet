from harness import (
    Net,
    Rng,
    count_kind,
    make_config,
    messages,
    new_net,
    pattern,
    same_bytes,
)
from nethernet.sctp.association import Association
from nethernet.sctp.chunk import decode_data
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SCTP_STATE_CLOSED,
    SCTP_STATE_ESTABLISHED,
    SCTP_STATE_SHUTDOWN_PENDING,
    SctpEvent,
)
from nethernet.sctp.packet import CHUNK_DATA, CHUNK_FORWARD_TSN, parse_packet
from nethernet.sctp.sender import fragment_size_for_mtu
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true


def _connect_both(mut net: Net) raises:
    net.a.connect(net.now)
    net.b.connect(net.now)
    net.run(120000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)


def _closed_reason(events: List[SctpEvent]) -> String:
    for i in range(len(events)):
        if events[i].kind == SCTP_EVENT_CLOSED:
            return events[i].reason
    return String("<not closed>")


def test_simultaneous_open() raises:
    var net = new_net(1)
    _connect_both(net)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_CONNECTED), 1)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_CONNECTED), 1)
    assert_true(net.max_packet <= 1200)


def test_simultaneous_open_with_loss_and_reordering() raises:
    for seed in range(20):
        var net = new_net(UInt64(100 + seed))
        net.loss_ab = 300
        net.loss_ba = 300
        net.reorder = 300
        net.duplicate = 100
        _connect_both(net)
        assert_equal(count_kind(net.a_events, SCTP_EVENT_CONNECTED), 1)
        assert_equal(count_kind(net.b_events, SCTP_EVENT_CONNECTED), 1)


def test_passive_open() raises:
    var net = new_net(2)
    net.a.connect(0)
    net.run(60000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_CONNECTED), 1)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_CONNECTED), 1)
    # INIT, INIT ACK, COOKIE ECHO, COOKIE ACK.
    assert_equal(net.packets_ab, 2)
    assert_equal(net.packets_ba, 2)


def test_passive_open_with_loss() raises:
    for seed in range(20):
        var net = new_net(UInt64(200 + seed))
        net.loss_ab = 300
        net.loss_ba = 300
        net.a.connect(0)
        net.run(300000)
        assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
        assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)


def test_send_before_established_is_queued() raises:
    var net = new_net(3)
    net.a.connect(0)
    var early = pattern(5000, 1)
    net.a.send(0, 53, Span(early), False, -1)
    # The passive side has no association yet.
    with assert_raises():
        net.b.send(0, 53, Span(early), False, -1)
    net.run(60000)
    var got = messages(net.b_events)
    assert_equal(len(got), 1)
    assert_true(same_bytes(got[0].payload, early))


def test_message_sizes() raises:
    var net = new_net(4)
    _connect_both(net)
    var frag = fragment_size_for_mtu(1200)
    assert_equal(frag, 1156)
    var sizes: List[Int] = [
        1, 2, frag - 1, frag, frag + 1, 1160, 1161, 2 * frag, 2 * frag + 1,
        65536, 262144,
    ]
    for i in range(len(sizes)):
        var m = pattern(sizes[i], i)
        net.a.send(1, 53, Span(m), False, -1)
    assert_true(net.a.buffered_amount() > 262144)
    net.run(600000)
    var got = messages(net.b_events)
    assert_equal(len(got), len(sizes))
    for i in range(len(sizes)):
        assert_equal(len(got[i].payload), sizes[i])
        assert_true(same_bytes(got[i].payload, pattern(sizes[i], i)))
        assert_equal(got[i].stream_id, 1)
        assert_equal(got[i].ppid, 53)
        assert_false(got[i].unordered)
    assert_equal(net.a.buffered_amount(), 0)
    assert_true(net.max_packet <= 1200)
    # Nothing was lost, so nothing was retransmitted.
    assert_equal(net.a.stats().retransmits, 0)
    assert_equal(net.a.stats().t3_expiries, 0)


def test_message_too_large_or_empty_is_rejected() raises:
    var net = new_net(5)
    _connect_both(net)
    var big = List[UInt8](length=262145, fill=1)
    with assert_raises():
        net.a.send(0, 53, Span(big), False, -1)
    with assert_raises():
        net.a.send(0, 53, Span(big)[0:0], False, -1)
    with assert_raises():
        net.a.send(65535, 53, Span(big)[0:1], False, -1)
    net.a.send(65534, 53, Span(big)[0:262144], False, -1)
    net.run(600000)
    assert_equal(len(messages(net.b_events)), 1)


def test_fragments_are_consecutive_and_never_interleaved() raises:
    var net = new_net(6)
    _connect_both(net)
    net.capture = True
    for i in range(12):
        var m = pattern(700 + 900 * i, i)
        net.a.send(UInt16(i % 3), 53, Span(m), i % 4 == 3, -1)
    net.run(600000)
    var expected_tsn = UInt32(0)
    var have_tsn = False
    var open_stream = -1
    var chunks = 0
    for p in range(len(net.captured)):
        var view = parse_packet(Span(net.captured[p]))
        assert_true(len(net.captured[p]) <= 1200)
        for c in view.chunks:
            if c.kind != CHUNK_DATA:
                continue
            var d = decode_data(
                Span(net.captured[p])[c.offset : c.offset + c.length], c.flags
            )
            chunks += 1
            if have_tsn:
                assert_equal(d.tsn, expected_tsn)
            have_tsn = True
            expected_tsn = d.tsn + 1
            if open_stream >= 0:
                # Inside a message: same stream, no new beginning.
                assert_equal(Int(d.stream_id), open_stream)
                assert_false(d.beginning())
            else:
                assert_true(d.beginning())
            open_stream = -1 if d.ending() else Int(d.stream_id)
    assert_true(chunks > 12)
    assert_equal(open_stream, -1)
    assert_equal(len(messages(net.b_events)), 12)


def test_interleaved_streams_keep_per_stream_order() raises:
    var net = new_net(7)
    _connect_both(net)
    net.reorder = 300
    var counts = List[Int](length=4, fill=0)
    for i in range(80):
        var stream = i % 4
        var m = pattern(50 + 37 * i, i)
        net.a.send(UInt16(stream), UInt32(50 + stream), Span(m), False, -1)
        var back = pattern(20 + 11 * i, 1000 + i)
        net.b.send(UInt16(stream), 53, Span(back), False, -1)
    net.run(600000)
    var got = messages(net.b_events)
    assert_equal(len(got), 80)
    for j in range(len(got)):
        var stream = Int(got[j].stream_id)
        var i = counts[stream] * 4 + stream
        counts[stream] += 1
        assert_equal(got[j].ppid, UInt32(50 + stream))
        assert_true(same_bytes(got[j].payload, pattern(50 + 37 * i, i)))
    var back_got = messages(net.a_events)
    assert_equal(len(back_got), 80)
    var back_counts = List[Int](length=4, fill=0)
    for j in range(len(back_got)):
        var stream = Int(back_got[j].stream_id)
        var i = back_counts[stream] * 4 + stream
        back_counts[stream] += 1
        assert_true(same_bytes(back_got[j].payload, pattern(20 + 11 * i, 1000 + i)))


def _reliable_under_loss(seed: UInt64, loss: Int, count: Int, max_size: Int) raises:
    var net = new_net(seed)
    _connect_both(net)
    net.loss_ab = loss
    net.loss_ba = loss
    net.reorder = 100
    net.duplicate = 50
    var rng = Rng(seed + 77)
    var sizes_ab = List[Int]()
    var sizes_ba = List[Int]()
    for i in range(count):
        sizes_ab.append(1 + rng.below(max_size))
        sizes_ba.append(1 + rng.below(max_size))
        var m = pattern(sizes_ab[i], i)
        net.a.send(UInt16(i % 2), 53, Span(m), False, -1)
        var n = pattern(sizes_ba[i], 5000 + i)
        net.b.send(UInt16(i % 2), 53, Span(n), False, -1)
    net.run(3600000)
    var got_b = messages(net.b_events)
    var got_a = messages(net.a_events)
    assert_equal(len(got_b), count)
    assert_equal(len(got_a), count)
    # In order within each stream, complete and uncorrupted.
    var next_b = List[Int](length=2, fill=0)
    for j in range(count):
        var stream = Int(got_b[j].stream_id)
        var i = next_b[stream] * 2 + stream
        next_b[stream] += 1
        assert_true(same_bytes(got_b[j].payload, pattern(sizes_ab[i], i)))
    var next_a = List[Int](length=2, fill=0)
    for j in range(count):
        var stream = Int(got_a[j].stream_id)
        var i = next_a[stream] * 2 + stream
        next_a[stream] += 1
        assert_true(same_bytes(got_a[j].payload, pattern(sizes_ba[i], 5000 + i)))
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.a.buffered_amount(), 0)
    assert_equal(net.b.buffered_amount(), 0)
    assert_equal(net.a.receive_buffered(), 0)
    assert_equal(net.b.receive_buffered(), 0)
    assert_true(net.lost > 0)
    assert_true(net.a.stats().retransmits > 0)
    assert_true(net.max_packet <= 1200)


def test_reliable_delivery_with_5_percent_loss() raises:
    for seed in range(4):
        _reliable_under_loss(UInt64(300 + seed), 50, 60, 20000)


def test_reliable_delivery_with_30_percent_loss() raises:
    for seed in range(4):
        _reliable_under_loss(UInt64(400 + seed), 300, 30, 8000)


def test_large_message_with_loss() raises:
    var net = new_net(8)
    _connect_both(net)
    net.loss_ab = 50
    net.loss_ba = 50
    var m = pattern(262144, 9)
    net.a.send(0, 53, Span(m), False, -1)
    net.run(3600000)
    var got = messages(net.b_events)
    assert_equal(len(got), 1)
    assert_true(same_bytes(got[0].payload, m))
    assert_true(net.a.stats().fast_retransmits > 0)


def test_unordered_delivery() raises:
    var net = new_net(9)
    _connect_both(net)
    net.loss_ab = 100
    net.loss_ba = 100
    net.reorder = 400
    var count = 60
    for i in range(count):
        var m = pattern(10 + 131 * i, i)
        net.a.send(2, 53, Span(m), True, -1)
    net.run(3600000)
    var got = messages(net.b_events)
    assert_equal(len(got), count)
    # Every message arrives exactly once, in any order.
    var seen = List[Bool](length=count, fill=False)
    var out_of_order = False
    var last = -1
    for j in range(count):
        assert_true(got[j].unordered)
        assert_equal(got[j].stream_id, 2)
        var i = (len(got[j].payload) - 10) // 131
        assert_true(i >= 0 and i < count)
        assert_false(seen[i])
        seen[i] = True
        assert_true(same_bytes(got[j].payload, pattern(10 + 131 * i, i)))
        if i < last:
            out_of_order = True
        last = i
    assert_true(out_of_order)


def test_unreliable_unordered_under_loss() raises:
    var net = new_net(10)
    _connect_both(net)
    net.loss_ab = 250
    net.loss_ba = 250
    net.capture = True
    var count = 120
    for i in range(count):
        var m = pattern(20 + 37 * i, i)
        net.a.send(2, 53, Span(m), True, 0)
        if i % 10 == 9:
            net.run_for(50)
    # A reliable message queued last must still get through.
    var tail = pattern(3000, 999)
    net.a.send(0, 53, Span(tail), False, -1)
    net.run(3600000)
    var got = messages(net.b_events)
    var seen = List[Bool](length=count, fill=False)
    var unreliable = 0
    var tail_seen = 0
    for j in range(len(got)):
        if got[j].stream_id == 0:
            assert_true(same_bytes(got[j].payload, tail))
            tail_seen += 1
            continue
        var i = (len(got[j].payload) - 20) // 37
        assert_true(i >= 0 and i < count)
        assert_false(seen[i])
        seen[i] = True
        assert_true(same_bytes(got[j].payload, pattern(20 + 37 * i, i)))
        unreliable += 1
    assert_equal(tail_seen, 1)
    # Some were lost for good, most arrived.
    assert_true(unreliable < count)
    assert_true(unreliable > count // 3)
    assert_true(net.a.stats().abandoned_chunks > 0)
    assert_true(net.a.stats().forward_tsns_out > 0)
    assert_equal(net.a.buffered_amount(), 0)
    assert_equal(net.b.receive_buffered(), 0)
    # No unreliable chunk was ever sent twice.
    var tsns = Dict[UInt32, Int]()
    for p in range(len(net.captured)):
        var view = parse_packet(Span(net.captured[p]))
        for c in view.chunks:
            if c.kind != CHUNK_DATA:
                continue
            var d = decode_data(
                Span(net.captured[p])[c.offset : c.offset + c.length], c.flags
            )
            if d.stream_id == 2:
                assert_false(d.tsn in tsns)
                tsns[d.tsn] = 1


def test_unreliable_ordered_keeps_delivering_after_holes() raises:
    var net = new_net(11)
    _connect_both(net)
    net.loss_ab = 200
    net.loss_ba = 200
    var count = 150
    for i in range(count):
        # Some messages span several fragments.
        var size = 30 + 7 * i
        if i % 9 == 4:
            size = 2500 + i
        var m = pattern(size, i)
        net.a.send(4, 53, Span(m), False, 0)
        if i % 5 == 4:
            net.run_for(40)
    net.run(3600000)
    var got = messages(net.b_events)
    assert_true(len(got) < count)
    assert_true(len(got) > count // 4)
    var last = -1
    for j in range(len(got)):
        var n = len(got[j].payload)
        var i = (n - 30) // 7
        if n >= 2500:
            i = n - 2500
        assert_true(i >= 0 and i < count)
        # Strictly increasing: in order, no duplicates.
        assert_true(i > last)
        last = i
        var size = 30 + 7 * i
        if i % 9 == 4:
            size = 2500 + i
        assert_true(same_bytes(got[j].payload, pattern(size, i)))
        assert_false(got[j].unordered)
    # The last messages were not stalled behind an earlier hole.
    assert_true(last >= count - 20)
    assert_equal(net.a.buffered_amount(), 0)
    assert_equal(net.b.receive_buffered(), 0)
    # A reliable message on the same stream afterwards is delivered.
    net.loss_ab = 0
    net.loss_ba = 0
    var final = pattern(100, 4242)
    net.a.send(4, 53, Span(final), False, -1)
    net.run(60000)
    var after = messages(net.b_events)
    assert_equal(len(after), len(got) + 1)
    assert_true(same_bytes(after[len(after) - 1].payload, final))


def test_limited_retransmissions_retry_before_giving_up() raises:
    var net = new_net(12)
    _connect_both(net)
    net.capture = True
    net.loss_ab = 1000
    var m = pattern(100, 1)
    net.a.send(0, 53, Span(m), False, 2)
    net.run_for(20000)
    net.loss_ab = 0
    net.run(60000)
    # One transmission and two retransmissions, then a FORWARD-TSN.
    var data = 0
    var forward = 0
    for p in range(len(net.captured)):
        var view = parse_packet(Span(net.captured[p]))
        for c in view.chunks:
            if c.kind == CHUNK_DATA:
                data += 1
            elif c.kind == CHUNK_FORWARD_TSN:
                forward += 1
    assert_equal(data, 3)
    assert_true(forward >= 1)
    assert_equal(len(messages(net.b_events)), 0)
    assert_equal(net.a.buffered_amount(), 0)
    assert_equal(net.a.stats().abandoned_chunks, 1)
    # The stream moves on.
    var next = pattern(50, 2)
    net.a.send(0, 53, Span(next), False, -1)
    net.run(60000)
    var got = messages(net.b_events)
    assert_equal(len(got), 1)
    assert_true(same_bytes(got[0].payload, next))


def test_window_exhaustion_and_recovery() raises:
    var cfg_b = make_config(1302)
    cfg_b.a_rwnd = 20000
    var net = Net(Association(make_config(1301)), Association(cfg_b), 13)
    _connect_both(net)
    # B's application stops reading.
    net.hold_b_events = True
    var count = 40
    for i in range(count):
        var m = pattern(3000, i)
        net.a.send(0, 53, Span(m), False, -1)
    net.run_for(30000)
    # The sender is stuck behind the closed window, still established.
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_true(net.a.buffered_amount() > 60000)
    assert_true(net.b.receive_buffered() <= 20000 + 3000 + 1200)
    assert_equal(len(messages(net.b_events)), 0)
    var stuck = net.a.buffered_amount()
    net.run_for(30000)
    assert_equal(net.a.buffered_amount(), stuck)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    # The application reads again: everything flows.
    net.hold_b_events = False
    net.run(3600000)
    var got = messages(net.b_events)
    assert_equal(len(got), count)
    for i in range(count):
        assert_true(same_bytes(got[i].payload, pattern(3000, i)))
    assert_equal(net.a.buffered_amount(), 0)


def test_window_exhaustion_survives_long_stall() raises:
    # A closed window must not trip the retransmission limit.
    var cfg_b = make_config(1402)
    cfg_b.a_rwnd = 6000
    var net = Net(Association(make_config(1401)), Association(cfg_b), 14)
    _connect_both(net)
    net.hold_b_events = True
    for i in range(10):
        var m = pattern(4000, i)
        net.a.send(0, 53, Span(m), False, -1)
    net.run_for(1800000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    net.hold_b_events = False
    net.run(3600000)
    assert_equal(len(messages(net.b_events)), 10)


def test_stream_reset_both_directions() raises:
    var net = new_net(15)
    _connect_both(net)
    for i in range(3):
        var m = pattern(2000 + i, i)
        net.a.send(3, 53, Span(m), False, -1)
        net.b.send(3, 53, Span(m), False, -1)
    # The reset is queued behind the three messages.
    net.a.reset_stream(3)
    net.run(60000)
    assert_equal(len(messages(net.b_events)), 3)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_STREAM_RESET), 1)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_STREAM_RESET), 0)
    var reset_at = -1
    for j in range(len(net.b_events)):
        if net.b_events[j].kind == SCTP_EVENT_STREAM_RESET:
            assert_equal(net.b_events[j].stream_id, 3)
            reset_at = j
    # The reset is reported after the data that preceded it.
    assert_equal(reset_at, len(net.b_events) - 1)
    # B answers by resetting its own direction, as a data channel close does.
    net.b.reset_stream(3)
    net.run(60000)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_STREAM_RESET), 1)
    # Sequence numbers restart at 0 on both sides: new messages deliver.
    net.capture = True
    var again = pattern(100, 77)
    net.a.send(3, 53, Span(again), False, -1)
    net.b.send(3, 53, Span(again), False, -1)
    net.run(60000)
    assert_equal(len(messages(net.b_events)), 4)
    assert_equal(len(messages(net.a_events)), 4)
    var found = False
    for p in range(len(net.captured)):
        var view = parse_packet(Span(net.captured[p]))
        for c in view.chunks:
            if c.kind == CHUNK_DATA:
                var d = decode_data(
                    Span(net.captured[p])[c.offset : c.offset + c.length],
                    c.flags,
                )
                assert_equal(d.ssn, 0)
                found = True
    assert_true(found)
    # Other streams were not disturbed.
    net.a.send(1, 53, Span(again), False, -1)
    net.run(60000)
    assert_equal(len(messages(net.b_events)), 5)


def test_stream_reset_with_loss() raises:
    for seed in range(6):
        var net = new_net(UInt64(1600 + seed))
        _connect_both(net)
        net.loss_ab = 300
        net.loss_ba = 300
        for i in range(5):
            var m = pattern(1500 + i, i)
            net.a.send(5, 53, Span(m), False, -1)
        net.a.reset_stream(5)
        net.a.reset_stream(6)
        net.b.reset_stream(5)
        net.run(3600000)
        assert_equal(len(messages(net.b_events)), 5)
        assert_equal(count_kind(net.b_events, SCTP_EVENT_STREAM_RESET), 2)
        assert_equal(count_kind(net.a_events, SCTP_EVENT_STREAM_RESET), 1)
        # Each reset is reported once despite retransmitted requests.
        var m = pattern(10, 1)
        net.a.send(5, 53, Span(m), False, -1)
        net.b.send(5, 53, Span(m), False, -1)
        net.run(3600000)
        assert_equal(len(messages(net.b_events)), 6)
        assert_equal(len(messages(net.a_events)), 1)
        assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)


def test_graceful_shutdown() raises:
    var net = new_net(17)
    _connect_both(net)
    net.loss_ab = 100
    net.loss_ba = 100
    for i in range(10):
        var m = pattern(5000, i)
        net.a.send(0, 53, Span(m), False, -1)
        net.b.send(0, 53, Span(m), False, -1)
    net.a.shutdown(net.now)
    assert_equal(net.a.state(), SCTP_STATE_SHUTDOWN_PENDING)
    var late = pattern(10, 1)
    with assert_raises():
        net.a.send(0, 53, Span(late), False, -1)
    net.run(3600000)
    # Everything queued before the shutdown was delivered, both ways.
    assert_equal(len(messages(net.b_events)), 10)
    assert_equal(len(messages(net.a_events)), 10)
    assert_equal(net.a.state(), SCTP_STATE_CLOSED)
    assert_equal(net.b.state(), SCTP_STATE_CLOSED)
    assert_equal(_closed_reason(net.a_events), "shutdown complete")
    assert_equal(_closed_reason(net.b_events), "shutdown complete")
    assert_equal(count_kind(net.a_events, SCTP_EVENT_CLOSED), 1)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_CLOSED), 1)
    assert_false(Bool(net.a.next_timeout()))
    assert_false(Bool(net.b.next_timeout()))
    with assert_raises():
        net.b.send(0, 53, Span(late), False, -1)


def test_simultaneous_shutdown() raises:
    var net = new_net(18)
    _connect_both(net)
    net.a.shutdown(net.now)
    net.b.shutdown(net.now)
    net.run(600000)
    assert_equal(net.a.state(), SCTP_STATE_CLOSED)
    assert_equal(net.b.state(), SCTP_STATE_CLOSED)
    assert_equal(_closed_reason(net.a_events), "shutdown complete")
    assert_equal(_closed_reason(net.b_events), "shutdown complete")


def test_abort() raises:
    var net = new_net(19)
    _connect_both(net)
    var m = pattern(50000, 1)
    net.a.send(0, 53, Span(m), False, -1)
    net.run_for(8)
    net.a.abort("bye")
    assert_equal(net.a.state(), SCTP_STATE_CLOSED)
    net.run(60000)
    assert_equal(net.b.state(), SCTP_STATE_CLOSED)
    assert_equal(_closed_reason(net.a_events), "bye")
    assert_equal(_closed_reason(net.b_events), "aborted by peer: bye")
    assert_equal(net.a.buffered_amount(), 0)
    assert_false(Bool(net.a.next_timeout()))
    assert_false(Bool(net.b.next_timeout()))
    # A closed association ignores everything and stays silent.
    net.b.connect(net.now)
    net.b.shutdown(net.now)
    net.b.abort("again")
    net.run(60000)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_CLOSED), 1)
    with assert_raises():
        net.a.send(0, 53, Span(m)[0:10], False, -1)


def test_retransmission_limit_when_peer_disappears() raises:
    var net = new_net(20)
    _connect_both(net)
    net.loss_ab = 1000
    net.loss_ba = 1000
    var m = pattern(3000, 1)
    net.a.send(0, 53, Span(m), False, -1)
    var start = net.now
    net.run(3600000)
    assert_equal(net.a.state(), SCTP_STATE_CLOSED)
    assert_equal(_closed_reason(net.a_events), "retransmission limit exceeded")
    # RTO 1 s doubling to the 60 s cap, 10 retransmissions:
    # 1+2+4+8+16+32+60*5 = 363 s.
    assert_equal(net.now - start, 363000)
    assert_equal(net.a.stats().t3_expiries, 10)
    assert_false(Bool(net.a.next_timeout()))
    # B never noticed and stays established.
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)


def test_handshake_gives_up_without_a_peer() raises:
    var net = new_net(21)
    net.loss_ab = 1000
    net.a.connect(0)
    net.run(3600000)
    assert_equal(net.a.state(), SCTP_STATE_CLOSED)
    assert_equal(_closed_reason(net.a_events), "handshake timed out")
    # INIT plus 8 retransmissions, 1 s doubling up to the 60 s cap.
    assert_equal(net.packets_ab, 9)
    assert_equal(net.now, 1000 + 2000 + 4000 + 8000 + 16000 + 32000 + 60000 * 3)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_CONNECTED), 0)


def test_duplicated_and_reordered_packets_do_not_duplicate_messages() raises:
    var net = new_net(22)
    _connect_both(net)
    net.duplicate = 500
    net.reorder = 500
    for i in range(100):
        var m = pattern(1 + 53 * i, i)
        net.a.send(UInt16(i % 3), 53, Span(m), i % 2 == 0, -1)
    net.run(600000)
    var got = messages(net.b_events)
    assert_equal(len(got), 100)
    assert_true(net.b.stats().duplicate_tsns > 0)
    var seen = List[Bool](length=100, fill=False)
    for j in range(100):
        var i = (len(got[j].payload) - 1) // 53
        assert_false(seen[i])
        seen[i] = True


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
