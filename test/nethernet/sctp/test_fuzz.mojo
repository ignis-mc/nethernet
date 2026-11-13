"""Hostile input: mutated, truncated and random packets must be survivable.

`handle_packet()` must never crash or raise, and whatever arrives the
association may only hold a bounded amount of state and emit well-formed
packets of at most one MTU.
"""

from harness import Net, Rng, make_config, messages, new_net, pattern
from nethernet.sctp.association import Association
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_STATE_CLOSED,
    SCTP_STATE_ESTABLISHED,
    SCTP_STATE_SHUTDOWN_ACK_SENT,
    SctpConfig,
)
from nethernet.sctp.packet import (
    begin_chunk,
    begin_packet,
    end_chunk,
    finish_packet,
    parse_packet,
)
from nethernet.wire import hex_decode, put_bytes
from pion_vectors import pion_collision, pion_cs, pion_fwd, pion_loss
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _busy_session(seed: UInt64, capture: Bool) raises -> Net:
    """Runs a session that exercises most chunk types, A to B."""
    var net = new_net(seed)
    net.capture = capture
    net.a.connect(0)
    net.b.connect(0)
    net.run(10000)
    net.loss_ab = 150
    for i in range(30):
        var m = pattern(40 + 211 * i, i)
        net.a.send(
            UInt16(i % 3), 53, Span(m), i % 2 == 0, -1 if i % 3 != 0 else 0
        )
        net.b.send(1, 53, Span(m)[0:20], False, -1)
    net.a.reset_stream(2)
    net.run(60000)
    net.loss_ab = 0
    return net^


def _mutate(mut rng: Rng, original: List[UInt8]) -> List[UInt8]:
    var p = original.copy()
    var kind = rng.below(9)
    if kind == 0:
        # Flip a few bits anywhere.
        for _ in range(1 + rng.below(8)):
            var at = rng.below(len(p))
            p[at] ^= UInt8(1 << rng.below(8))
    elif kind == 1:
        # Truncate.
        var keep = rng.below(len(p) + 1)
        p = List[UInt8](Span(p)[0:keep])
    elif kind == 2:
        # Corrupt the length field of the first chunk.
        if len(p) >= 16:
            p[14] = UInt8(rng.below(256))
            p[15] = UInt8(rng.below(256))
    elif kind == 3:
        # Corrupt bytes after the first chunk header: counts, TSNs, lengths
        # of parameters.
        if len(p) > 16:
            for _ in range(1 + rng.below(4)):
                var at = 16 + rng.below(len(p) - 16)
                p[at] = UInt8(rng.below(256))
    elif kind == 4:
        # Append junk.
        for _ in range(1 + rng.below(40)):
            p.append(UInt8(rng.below(256)))
    elif kind == 5:
        # Change the type of the first chunk.
        if len(p) >= 13:
            p[12] = UInt8(rng.below(256))
    elif kind == 6:
        # Repeat everything after the common header.
        var body = List[UInt8](Span(p)[12 : len(p)])
        for _ in range(1 + rng.below(3)):
            p.extend(Span(body))
    elif kind == 7:
        # Set a 16-bit field somewhere to an extreme value.
        if len(p) >= 18:
            var at = 12 + rng.below(len(p) - 13)
            var v = UInt8(0xFF) if rng.chance(500) else UInt8(0)
            p[at] = v
            p[at + 1] = v
    else:
        # Zero-length chunk appended.
        p.append(UInt8(rng.below(256)))
        p.append(0)
        p.append(0)
        p.append(UInt8(rng.below(4)))
    # Mostly repair the checksum so that the mutation gets past it.
    if len(p) >= 12 and not rng.chance(100):
        finish_packet(p)
    return p^


def _random_packet(mut rng: Rng, tag: UInt32) -> List[UInt8]:
    """A well-framed packet of random chunks with random contents."""
    var p = List[UInt8]()
    begin_packet(p, 5000, 5000, tag if rng.chance(900) else UInt32(0))
    for _ in range(1 + rng.below(4)):
        # ABORT, SACK and SHUTDOWN with random contents end the association
        # almost at once, so they are drawn less often.
        var kinds: List[UInt8] = [
            0,
            1,
            2,
            4,
            5,
            8,
            9,
            10,
            11,
            14,
            130,
            192,
            64,
            15,
            0x84,
            0xC1,
        ]
        var kind = kinds[rng.below(len(kinds))]
        if rng.chance(30):
            kind = UInt8(rng.below(256))
        var start = begin_chunk(p, kind, UInt8(rng.below(16)))
        var body = rng.bytes(rng.below(48))
        put_bytes(p, Span(body))
        end_chunk(p, start)
    finish_packet(p)
    return p^


def _check_output(mut assoc: Association, now: Int, mtu: Int) raises:
    # Whatever comes out must be a valid packet of at most one MTU, and
    # there must not be an unbounded pile of it.
    var packets = 0
    while True:
        var p = assoc.poll_transmit(now)
        if not p:
            break
        packets += 1
        assert_true(packets < 400)
        assert_true(len(p.value()) <= mtu)
        var view = parse_packet(Span(p.value()))
        assert_true(len(view.chunks) >= 1)


def _drain_events(mut assoc: Association) -> Int:
    var n = 0
    while True:
        var e = assoc.poll_event()
        if not e:
            break
        n += 1
    return n


def _pion_corpus() raises -> List[List[UInt8]]:
    var corpus = List[List[UInt8]]()
    for lines in [pion_cs(), pion_collision(), pion_fwd(), pion_loss()]:
        for i in range(len(lines)):
            if lines[i].startswith("#"):
                continue
            corpus.append(hex_decode(String(lines[i].split(" ")[2])))
    return corpus^


def test_mutated_packets_into_established_association() raises:
    # Record a session, then replay an identical one and attack its
    # receiver with mutations of the recorded packets: their verification
    # tag, TSNs and sequence numbers are all plausible.
    var recorded = _busy_session(31, True)
    var corpus = recorded.captured.copy()
    assert_true(len(corpus) > 50)
    var rng = Rng(4711)
    var rounds = 0
    var closed = 0
    var total = 0
    while total < 6000:
        var net = _busy_session(31, False)
        assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
        rounds += 1
        var now = net.now
        for _ in range(600):
            total += 1
            now += rng.below(50)
            var p = _mutate(rng, corpus[rng.below(len(corpus))])
            net.b.handle_packet(Span(p), now)
            net.b.handle_timeout(now)
            _check_output(net.b, now, 1200)
            if rng.chance(700):
                _ = _drain_events(net.b)
            # Bounded state, whatever arrived.
            assert_true(net.b.receive_buffered() <= 1048576 + 262144 + 1200)
            assert_true(net.b.buffered_amount() >= 0)
            assert_true(net.b.state() >= 0 and net.b.state() <= 7)
            if net.b.state() == SCTP_STATE_CLOSED:
                closed += 1
                break
        assert_true(_drain_events(net.b) <= 4096 + 600)
    assert_true(rounds >= 10)


def test_mutated_pion_packets_in_every_handshake_state() raises:
    var corpus = _pion_corpus()
    assert_true(len(corpus) > 100)
    var rng = Rng(1234)
    for round in range(40):
        var secret = rng.bytes(16)
        # Use a tag from the recordings so that some packets pass the check.
        var tags: List[UInt32] = [
            0x6521BE70,
            0xAC060E97,
            0xAA764BE4,
            0x817B5835,
        ]
        var a = Association(
            SctpConfig(tags[round % 4], UInt32(rng.next() >> 32), Span(secret))
        )
        var now = 0
        if round % 2 == 1:
            a.connect(0)
        for _ in range(150):
            now += rng.below(400)
            var p = _mutate(rng, corpus[rng.below(len(corpus))])
            if rng.chance(300):
                p = corpus[rng.below(len(corpus))].copy()
            a.handle_packet(Span(p), now)
            a.handle_timeout(now)
            _check_output(a, now, 1200)
            assert_true(a.receive_buffered() <= 1048576 + 262144 + 1200)
        assert_true(_drain_events(a) <= 4096 + 150)


def test_random_chunks_with_valid_framing() raises:
    var rng = Rng(99)
    var handled = 0
    for round in range(150):
        var net = new_net(UInt64(500 + round))
        net.a.connect(0)
        net.b.connect(0)
        net.run(10000)
        if round % 4 == 1:
            net.b.shutdown(net.now)
        # B's tag is what A puts in its packets.
        net.capture = True
        var probe = pattern(10, 1)
        if round % 4 != 1:
            net.a.send(0, 53, Span(probe), False, -1)
        else:
            net.a.reset_stream(0)
        net.run(1000)
        assert_true(len(net.captured) >= 1)
        var tag = parse_packet(Span(net.captured[0])).verification_tag
        var now = net.now
        for _ in range(80):
            now += rng.below(100)
            var p = _random_packet(rng, tag)
            net.b.handle_packet(Span(p), now)
            net.b.handle_timeout(now)
            _check_output(net.b, now, 1200)
            assert_true(net.b.receive_buffered() <= 1048576 + 262144 + 1200)
            handled += 1
            if net.b.state() == SCTP_STATE_CLOSED:
                break
        assert_true(_drain_events(net.b) <= 4096 + 300)
    # Most rounds survive a good number of packets.
    assert_true(handled > 3000)


def test_garbage_and_tiny_inputs() raises:
    var rng = Rng(7)
    var net = new_net(77)
    net.a.connect(0)
    net.b.connect(0)
    net.run(10000)
    var before = net.b.stats().packets_dropped
    var empty = List[UInt8]()
    net.b.handle_packet(Span(empty), net.now)
    for n in range(1, 64):
        var junk = rng.bytes(n)
        net.b.handle_packet(Span(junk), net.now)
    var big = rng.bytes(70000)
    net.b.handle_packet(Span(big), net.now)
    assert_equal(net.b.stats().packets_dropped - before, 65)
    assert_equal(net.b.state(), SCTP_STATE_ESTABLISHED)
    _check_output(net.b, net.now, 1200)
    # Still fully functional.
    var m = pattern(5000, 3)
    net.a.send(0, 53, Span(m), False, -1)
    net.run(10000)
    assert_equal(len(messages(net.b_events)), 1)


def test_unread_events_are_bounded() raises:
    # A peer that floods a receiver whose application never reads.
    var cfg_b = make_config(802)
    cfg_b.max_queued_events = 100
    var net = Net(Association(make_config(801)), Association(cfg_b), 8)
    net.a.connect(0)
    net.b.connect(0)
    net.run(10000)
    net.hold_b_events = True
    for i in range(2000):
        var m = pattern(3, i)
        net.a.send(0, 53, Span(m), i % 2 == 0, -1)
    net.run_for(120000)
    assert_equal(net.a.state(), SCTP_STATE_ESTABLISHED)
    var queued = _drain_events(net.b)
    # At most the limit plus what one packet of tiny chunks can complete.
    assert_true(queued >= 100)
    assert_true(queued <= 100 + 1200 // 20)
    # Reading again lets the rest through.
    net.hold_b_events = False
    net.run(3600000)
    assert_equal(queued + len(messages(net.b_events)), 2000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
