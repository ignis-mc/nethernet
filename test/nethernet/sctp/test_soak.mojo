"""Randomized sessions: many seeds, mixed traffic, every kind of impairment.

Each session picks its loss, duplication and reordering rates and a script
of sends and stream resets from a seed, runs it in both directions at once,
then lets the network settle and checks what must hold in every case.
"""

from harness import (
    Net,
    Rng,
    count_kind,
    make_config,
    messages,
    pattern,
    same_bytes,
)
from nethernet.sctp.association import Association
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SCTP_STATE_ESTABLISHED,
    SctpEvent,
)
from std.testing import TestSuite, assert_equal, assert_false, assert_true

# Streams 0 and 1: reliable ordered. 2: reliable unordered. 3: unordered,
# no retransmission. 4: ordered, no retransmission. 5: ordered, one
# retransmission. 6: only ever reset.
comptime STREAMS = 6


struct Sent(Copyable):
    var stream: Int
    var size: Int
    var seed: Int

    def __init__(out self, stream: Int, size: Int, seed: Int):
        self.stream = stream
        self.size = size
        self.seed = seed


def _random_size(mut rng: Rng) -> Int:
    var kind = rng.below(10)
    if kind < 5:
        return 1 + rng.below(200)
    if kind < 8:
        return 1 + rng.below(3000)
    if kind < 9:
        return 1150 + rng.below(20)
    return 1 + rng.below(40000)


def _check(sent: List[Sent], events: List[SctpEvent]) raises:
    """Checks one direction: what was sent against what was delivered."""
    var got = messages(events)
    # Index of the next expected message per stream, for ordered checks.
    var per_stream = List[List[Int]]()
    for _ in range(STREAMS):
        per_stream.append(List[Int]())
    for i in range(len(sent)):
        per_stream[sent[i].stream].append(i)
    var cursor = List[Int](length=STREAMS, fill=0)
    var seen = List[Bool](length=len(sent), fill=False)
    var delivered = List[Int](length=STREAMS, fill=0)
    for j in range(len(got)):
        var stream = Int(got[j].stream_id)
        assert_true(stream < STREAMS)
        assert_equal(got[j].ppid, UInt32(50 + stream))
        assert_equal(got[j].unordered, stream == 2 or stream == 3)
        # Find which sent message this is: the next one on the stream whose
        # contents match. Ordered streams may only move forward.
        var found = -1
        if stream == 2 or stream == 3:
            for k in range(len(per_stream[stream])):
                var i = per_stream[stream][k]
                if seen[i] or sent[i].size != len(got[j].payload):
                    continue
                if same_bytes(
                    got[j].payload, pattern(sent[i].size, sent[i].seed)
                ):
                    found = i
                    break
        else:
            var k = cursor[stream]
            while k < len(per_stream[stream]):
                var i = per_stream[stream][k]
                if sent[i].size == len(got[j].payload) and same_bytes(
                    got[j].payload, pattern(sent[i].size, sent[i].seed)
                ):
                    found = i
                    cursor[stream] = k + 1
                    break
                # Skipping is only allowed where messages may be lost.
                assert_true(stream == 4 or stream == 5)
                k += 1
        # Never corrupted, never duplicated, never out of order.
        assert_true(found >= 0)
        assert_false(seen[found])
        seen[found] = True
        delivered[stream] += 1
    # Reliable streams delivered everything.
    for stream in range(3):
        assert_equal(delivered[stream], len(per_stream[stream]))


def _session(seed: UInt64) raises:
    # Random loss of up to a third of all packets can, rarely, produce the
    # nine or ten silent rounds in a row that end a handshake or an
    # association. That outcome is legitimate but not what these sessions
    # are about, so the limits are raised out of reach.
    var cfg_a = make_config(seed * 2 + 1)
    var cfg_b = make_config(seed * 2 + 2)
    cfg_a.max_retransmits = 1000
    cfg_b.max_retransmits = 1000
    cfg_a.max_init_retransmits = 1000
    cfg_b.max_init_retransmits = 1000
    var net = Net(Association(cfg_a), Association(cfg_b), seed)
    var rng = Rng(seed * 31 + 5)
    net.a.connect(0)
    if rng.chance(500):
        net.b.connect(0)
    net.loss_ab = rng.below(350)
    net.loss_ba = rng.below(350)
    net.duplicate = rng.below(150)
    net.reorder = rng.below(400)
    net.delay_ms = 1 + rng.below(80)
    net.run(7200000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    var sent_a = List[Sent]()
    var sent_b = List[Sent]()
    var policies: List[Int] = [-1, -1, -1, 0, 0, 1]
    var resets_a = 0
    var resets_b = 0
    var steps = 40 + rng.below(80)
    for step in range(steps):
        var from_a = rng.chance(500)
        var action = rng.below(20)
        if action == 0:
            # Reset the stream nobody sends on.
            if from_a:
                net.a.reset_stream(6)
                resets_a += 1
            else:
                net.b.reset_stream(6)
                resets_b += 1
        else:
            var stream = rng.below(STREAMS)
            var size = _random_size(rng)
            var m = pattern(size, step)
            var unordered = stream == 2 or stream == 3
            if from_a:
                net.a.send(
                    UInt16(stream),
                    UInt32(50 + stream),
                    Span(m),
                    unordered,
                    policies[stream],
                )
                sent_a.append(Sent(stream, size, step))
            else:
                net.b.send(
                    UInt16(stream),
                    UInt32(50 + stream),
                    Span(m),
                    unordered,
                    policies[stream],
                )
                sent_b.append(Sent(stream, size, step))
        if rng.chance(300):
            net.run_for(rng.below(400))
    # Let everything settle. Loss stays on: reliability must not depend on
    # the network getting better.
    net.run(7200000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_CLOSED), 0)
    assert_equal(count_kind(net.b_events, SCTP_EVENT_CLOSED), 0)
    _check(sent_a, net.b_events)
    _check(sent_b, net.a_events)
    # Every reset request was reported exactly once.
    assert_equal(count_kind(net.b_events, SCTP_EVENT_STREAM_RESET), resets_a)
    assert_equal(count_kind(net.a_events, SCTP_EVENT_STREAM_RESET), resets_b)
    # Nothing is left queued, in flight or half reassembled.
    assert_equal(net.a.buffered_amount(), 0)
    assert_equal(net.b.buffered_amount(), 0)
    assert_equal(net.a.receive_buffered(), 0)
    assert_equal(net.b.receive_buffered(), 0)
    assert_false(Bool(net.a.next_timeout()))
    assert_false(Bool(net.b.next_timeout()))
    assert_true(net.max_packet <= 1200)
    # Both ends still work.
    net.loss_ab = 0
    net.loss_ba = 0
    var last = pattern(100, 31337)
    net.a.send(0, 50, Span(last), False, -1)
    net.b.send(0, 50, Span(last), False, -1)
    var before_a = len(messages(net.a_events))
    var before_b = len(messages(net.b_events))
    net.run(600000)
    assert_equal(len(messages(net.a_events)), before_a + 1)
    assert_equal(len(messages(net.b_events)), before_b + 1)


def test_random_sessions_1() raises:
    for seed in range(1000, 1025):
        _session(UInt64(seed))


def test_random_sessions_2() raises:
    for seed in range(2000, 2025):
        _session(UInt64(seed))


def test_random_sessions_3() raises:
    for seed in range(3000, 3025):
        _session(UInt64(seed))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
