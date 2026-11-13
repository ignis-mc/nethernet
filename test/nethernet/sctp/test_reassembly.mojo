from nethernet.sctp.chunk import (
    DATA_FLAG_BEGIN,
    DATA_FLAG_END,
    DATA_FLAG_UNORDERED,
    DataChunk,
)
from nethernet.sctp.reassembly import (
    CHUNK_BUFFER_OVERHEAD,
    REASSEMBLY_DISCARDED,
    REASSEMBLY_OK,
    REASSEMBLY_TOO_LARGE,
    TSN_DUPLICATE,
    TSN_NEW,
    TSN_OUT_OF_WINDOW,
    Reassembly,
    SctpMessage,
    TsnTracker,
)
from nethernet.wire import bytes_of, string_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true

comptime B = DATA_FLAG_BEGIN
comptime E = DATA_FLAG_END
comptime U = DATA_FLAG_UNORDERED


def _chunk(tsn: UInt32, stream: UInt16, ssn: UInt16, flags: UInt8, text: StringSpan) -> DataChunk:
    var payload = bytes_of(text)
    return DataChunk(tsn, stream, ssn, 53, flags, Span(payload))


def _texts(messages: List[SctpMessage]) -> String:
    """The delivered payloads joined with `|`."""
    var out = String("")
    for i in range(len(messages)):
        if i > 0:
            out += "|"
        out += string_of(Span(messages[i].payload))
    return out


def test_tracker_in_order() raises:
    var t = TsnTracker(99, 256)
    assert_equal(t.cumulative_tsn(), 99)
    assert_false(t.has_gaps())
    for tsn in range(100, 110):
        assert_equal(t.classify(UInt32(tsn)), TSN_NEW)
        t.mark(UInt32(tsn))
    assert_equal(t.cumulative_tsn(), 109)
    assert_equal(len(t.gap_blocks(16)), 0)
    assert_equal(t.classify(109), TSN_DUPLICATE)
    assert_equal(t.classify(50), TSN_DUPLICATE)


def test_tracker_gaps_and_duplicates() raises:
    var t = TsnTracker(9, 256)
    t.mark(12)
    t.mark(13)
    t.mark(15)
    t.mark(20)
    assert_equal(t.cumulative_tsn(), 9)
    assert_true(t.has_gaps())
    assert_equal(t.classify(13), TSN_DUPLICATE)
    assert_equal(t.classify(14), TSN_NEW)
    var blocks = t.gap_blocks(16)
    assert_equal(len(blocks), 3)
    assert_equal(blocks[0].start, 3)
    assert_equal(blocks[0].end, 4)
    assert_equal(blocks[1].start, 6)
    assert_equal(blocks[1].end, 6)
    assert_equal(blocks[2].start, 11)
    assert_equal(blocks[2].end, 11)
    # The limit keeps the lowest blocks.
    var two = t.gap_blocks(2)
    assert_equal(len(two), 2)
    assert_equal(two[1].start, 6)
    # Filling the first hole moves the cumulative TSN through the run.
    t.mark(10)
    t.mark(11)
    assert_equal(t.cumulative_tsn(), 13)
    blocks = t.gap_blocks(16)
    assert_equal(len(blocks), 2)
    assert_equal(blocks[0].start, 2)
    assert_equal(blocks[0].end, 2)
    assert_equal(blocks[1].start, 7)
    t.mark(14)
    assert_equal(t.cumulative_tsn(), 15)
    t.mark(16)
    t.mark(17)
    t.mark(18)
    t.mark(19)
    assert_equal(t.cumulative_tsn(), 20)
    assert_false(t.has_gaps())
    assert_equal(len(t.gap_blocks(16)), 0)


def test_tracker_window_limit() raises:
    var t = TsnTracker(0, 64)
    assert_equal(t.classify(63), TSN_NEW)
    assert_equal(t.classify(64), TSN_OUT_OF_WINDOW)
    assert_equal(t.classify(1000000), TSN_OUT_OF_WINDOW)
    # Half the number space away counts as old, not as far ahead.
    assert_equal(t.classify(0x90000000), TSN_DUPLICATE)
    t.mark(64)
    assert_equal(t.cumulative_tsn(), 0)
    assert_false(t.has_gaps())
    t.mark(63)
    assert_true(t.has_gaps())
    var blocks = t.gap_blocks(4)
    assert_equal(blocks[0].start, 63)
    assert_equal(blocks[0].end, 63)


def test_tracker_wraparound() raises:
    var t = TsnTracker(0xFFFFFFFD, 256)
    t.mark(0xFFFFFFFF)
    t.mark(1)
    t.mark(2)
    assert_equal(t.cumulative_tsn(), 0xFFFFFFFD)
    var blocks = t.gap_blocks(8)
    assert_equal(len(blocks), 2)
    assert_equal(blocks[0].start, 2)
    assert_equal(blocks[0].end, 2)
    assert_equal(blocks[1].start, 4)
    assert_equal(blocks[1].end, 5)
    t.mark(0xFFFFFFFE)
    assert_equal(t.cumulative_tsn(), 0xFFFFFFFF)
    t.mark(0)
    assert_equal(t.cumulative_tsn(), 2)
    assert_equal(t.classify(0xFFFFFFFF), TSN_DUPLICATE)
    assert_equal(t.classify(3), TSN_NEW)


def test_tracker_forward() raises:
    var t = TsnTracker(10, 256)
    t.mark(12)
    t.mark(15)
    t.mark(16)
    t.forward(13)
    # Skips 11..13, then runs on through nothing: 14 is still missing.
    assert_equal(t.cumulative_tsn(), 13)
    t.forward(14)
    assert_equal(t.cumulative_tsn(), 16)
    assert_false(t.has_gaps())
    # Behind or at the cumulative TSN: ignored.
    t.forward(12)
    t.forward(16)
    assert_equal(t.cumulative_tsn(), 16)
    # Far beyond the window.
    t.mark(18)
    t.forward(100000)
    assert_equal(t.cumulative_tsn(), 100000)
    assert_false(t.has_gaps())
    assert_equal(t.classify(100001), TSN_NEW)


def test_single_fragment_messages() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    assert_equal(r.insert(_chunk(1, 0, 0, B | E, "a"), 1, out), REASSEMBLY_OK)
    assert_equal(r.insert(_chunk(2, 0, 1, B | E, "b"), 2, out), REASSEMBLY_OK)
    assert_equal(r.insert(_chunk(3, 7, 0, B | E | U, "c"), 3, out), REASSEMBLY_OK)
    assert_equal(_texts(out), "a|b|c")
    assert_equal(out[0].stream_id, 0)
    assert_equal(out[0].ppid, 53)
    assert_false(out[0].unordered)
    assert_true(out[2].unordered)
    assert_equal(out[2].stream_id, 7)
    assert_equal(r.cost(), 0)
    assert_equal(r.fragment_count(), 0)


def test_fragments_in_any_order() raises:
    # TSNs 10..13 make one message; try every arrival order.
    var orders: List[List[Int]] = [
        [0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1], [0, 3, 1, 2],
        [3, 0, 2, 1], [1, 2, 0, 3], [2, 1, 3, 0],
    ]
    var parts: List[String] = ["he", "ll", "o ", "you"]
    for o in range(len(orders)):
        for unordered in [False, True]:
            var r = Reassembly(1000)
            var out = List[SctpMessage]()
            for k in range(4):
                var i = orders[o][k]
                var flags = UInt8(U) if unordered else UInt8(0)
                if i == 0:
                    flags |= B
                if i == 3:
                    flags |= E
                assert_equal(len(out), 0)
                var status = r.insert(
                    _chunk(UInt32(10 + i), 2, 0, flags, parts[i]), 9, out
                )
                assert_equal(status, REASSEMBLY_OK)
                if k < 3:
                    assert_equal(r.fragment_count(), k + 1)
            assert_equal(_texts(out), "hello you")
            assert_equal(out[0].unordered, unordered)
            assert_equal(r.cost(), 0)


def test_ordered_stream_waits_for_earlier_messages() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    _ = r.insert(_chunk(3, 1, 2, B | E, "third"), 0, out)
    _ = r.insert(_chunk(2, 1, 1, B | E, "second"), 0, out)
    # Another stream is not held up.
    _ = r.insert(_chunk(4, 2, 0, B | E, "other"), 0, out)
    assert_equal(_texts(out), "other")
    assert_equal(r.fragment_count(), 2)
    assert_equal(r.cost(), 11 + 2 * CHUNK_BUFFER_OVERHEAD)
    _ = r.insert(_chunk(1, 1, 0, B | E, "first"), 4, out)
    assert_equal(_texts(out), "other|first|second|third")
    assert_equal(r.cost(), 0)


def test_ordered_fragmented_messages_out_of_order() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    # Message ssn 1 (TSN 3..4) completes before message ssn 0 (TSN 1..2).
    _ = r.insert(_chunk(4, 0, 1, E, "D"), 0, out)
    _ = r.insert(_chunk(3, 0, 1, B, "C"), 0, out)
    assert_equal(len(out), 0)
    _ = r.insert(_chunk(2, 0, 0, E, "B"), 0, out)
    assert_equal(len(out), 0)
    _ = r.insert(_chunk(1, 0, 0, B, "A"), 4, out)
    assert_equal(_texts(out), "AB|CD")
    assert_equal(r.cost(), 0)


def test_adjacent_messages_do_not_merge() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    # Unordered: the end of one message next to the start of another.
    _ = r.insert(_chunk(11, 0, 0, U | E, "b"), 5, out)
    _ = r.insert(_chunk(12, 0, 0, U | B, "c"), 5, out)
    assert_equal(len(out), 0)
    assert_equal(r.fragment_count(), 2)
    _ = r.insert(_chunk(10, 0, 0, U | B, "a"), 5, out)
    _ = r.insert(_chunk(13, 0, 0, U | E, "d"), 5, out)
    assert_equal(_texts(out), "ab|cd")
    # Different streams with adjacent TSNs.
    _ = r.insert(_chunk(20, 1, 0, B, "x"), 5, out)
    _ = r.insert(_chunk(22, 1, 0, E, "z"), 5, out)
    _ = r.insert(_chunk(21, 1, 0, 0, "y"), 5, out)
    assert_equal(_texts(out), "ab|cd|xyz")
    assert_equal(r.cost(), 0)


def test_stale_and_duplicate_sequence_numbers_are_discarded() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    _ = r.insert(_chunk(1, 0, 0, B | E, "a"), 1, out)
    # An ssn that was already delivered.
    assert_equal(
        r.insert(_chunk(2, 0, 0, B | E, "again"), 2, out), REASSEMBLY_DISCARDED
    )
    # Two different messages claiming the same future ssn.
    assert_equal(r.insert(_chunk(3, 0, 5, B | E, "five"), 3, out), REASSEMBLY_OK)
    assert_equal(
        r.insert(_chunk(4, 0, 5, B | E, "five!"), 4, out), REASSEMBLY_DISCARDED
    )
    assert_equal(_texts(out), "a")
    assert_equal(r.fragment_count(), 1)


def test_message_size_limit() raises:
    var r = Reassembly(10)
    var out = List[SctpMessage]()
    assert_equal(
        r.insert(_chunk(1, 0, 0, B | E, "12345678901"), 1, out),
        REASSEMBLY_TOO_LARGE,
    )
    assert_equal(r.insert(_chunk(2, 0, 0, B, "123456"), 2, out), REASSEMBLY_OK)
    assert_equal(
        r.insert(_chunk(3, 0, 0, 0, "78901"), 3, out), REASSEMBLY_TOO_LARGE
    )
    var exact = Reassembly(10)
    _ = exact.insert(_chunk(2, 0, 0, B, "123456"), 2, out)
    assert_equal(exact.insert(_chunk(3, 0, 0, E, "7890"), 3, out), REASSEMBLY_OK)
    assert_equal(_texts(out), "1234567890")


def test_orphan_fragments_are_discarded() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    # A middle fragment whose predecessor was already passed over.
    assert_equal(
        r.insert(_chunk(5, 0, 0, U, "m"), 5, out), REASSEMBLY_DISCARDED
    )
    assert_equal(
        r.insert(_chunk(6, 0, 0, U | E, "e"), 6, out), REASSEMBLY_DISCARDED
    )
    assert_equal(r.fragment_count(), 0)
    # A partial message followed directly by the start of the next one can
    # never be completed and is dropped when that start arrives.
    _ = r.insert(_chunk(10, 0, 0, U | B, "p1"), 10, out)
    _ = r.insert(_chunk(11, 0, 0, U, "p2"), 11, out)
    assert_equal(r.fragment_count(), 2)
    _ = r.insert(_chunk(12, 0, 0, U | B | E, "next"), 12, out)
    assert_equal(_texts(out), "next")
    assert_equal(r.fragment_count(), 0)
    assert_equal(r.cost(), 0)
    # The same on the other side: an end fragment right before a tail.
    _ = r.insert(_chunk(22, 0, 0, U | E, "tail"), 12, out)
    assert_equal(r.fragment_count(), 1)
    _ = r.insert(_chunk(21, 0, 0, U | B | E, "whole"), 12, out)
    assert_equal(_texts(out), "next|whole")
    assert_equal(r.fragment_count(), 0)


def test_orphan_on_ordered_stream_releases_the_stream() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    # Message ssn 0 is only partly there when message ssn 1 starts right
    # after it: ssn 0 can never complete, so the stream moves on.
    _ = r.insert(_chunk(1, 3, 0, B, "lost"), 1, out)
    _ = r.insert(_chunk(2, 3, 1, B | E, "one"), 2, out)
    assert_equal(_texts(out), "one")
    _ = r.insert(_chunk(3, 3, 2, B | E, "two"), 3, out)
    assert_equal(_texts(out), "one|two")
    assert_equal(r.cost(), 0)


def test_forward_drops_partial_messages() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    var none = List[UInt16]()
    var none2 = List[UInt16]()
    # Unordered message 10..13 with 11 missing; complete one at 14.
    _ = r.insert(_chunk(10, 0, 0, U | B, "a"), 9, out)
    _ = r.insert(_chunk(12, 0, 0, U, "c"), 9, out)
    _ = r.insert(_chunk(13, 0, 0, U | E, "d"), 9, out)
    assert_equal(r.fragment_count(), 3)
    r.forward(13, 13, Span(none), Span(none2), out)
    assert_equal(r.fragment_count(), 0)
    assert_equal(len(out), 0)
    assert_equal(r.cost(), 0)
    # A partial message entirely above the new point survives.
    _ = r.insert(_chunk(20, 0, 0, U | B, "x"), 13, out)
    r.forward(15, 15, Span(none), Span(none2), out)
    assert_equal(r.fragment_count(), 1)
    _ = r.insert(_chunk(21, 0, 0, U | E, "y"), 15, out)
    assert_equal(_texts(out), "xy")
    # A tail whose head lies at or below the new point is dropped.
    _ = r.insert(_chunk(31, 0, 0, U | E, "t"), 21, out)
    assert_equal(r.fragment_count(), 1)
    r.forward(30, 31, Span(none), Span(none2), out)
    assert_equal(r.fragment_count(), 0)


def test_forward_releases_ordered_stream() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    # ssn 0 (TSN 1) and ssn 2 (TSN 3) are lost; 1, 3 and 4 arrived.
    _ = r.insert(_chunk(2, 5, 1, B | E, "one"), 0, out)
    _ = r.insert(_chunk(4, 5, 3, B | E, "three"), 0, out)
    _ = r.insert(_chunk(5, 5, 4, B | E, "four"), 0, out)
    # Another stream also waits, and is not named by the FORWARD-TSN.
    _ = r.insert(_chunk(6, 6, 1, B | E, "held"), 0, out)
    assert_equal(len(out), 0)
    var streams: List[UInt16] = [5]
    var ssns: List[UInt16] = [2]
    r.forward(3, 6, Span(streams), Span(ssns), out)
    # Everything up to the skipped ssn 2 is released, then the rest in order.
    assert_equal(_texts(out), "one|three|four")
    assert_equal(r.fragment_count(), 1)
    # The stream continues after the skipped sequence number.
    _ = r.insert(_chunk(7, 5, 5, B | E, "five"), 7, out)
    assert_equal(_texts(out), "one|three|four|five")
    # A stale FORWARD-TSN for the same stream changes nothing.
    r.forward(3, 7, Span(streams), Span(ssns), out)
    _ = r.insert(_chunk(8, 5, 6, B | E, "six"), 8, out)
    assert_equal(_texts(out), "one|three|four|five|six")


def test_forward_with_partial_ordered_message() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    _ = r.insert(_chunk(1, 0, 0, B, "frag"), 1, out)
    _ = r.insert(_chunk(4, 0, 1, B | E, "next"), 1, out)
    var streams: List[UInt16] = [0]
    var ssns: List[UInt16] = [0]
    r.forward(3, 4, Span(streams), Span(ssns), out)
    assert_equal(_texts(out), "next")
    assert_equal(r.cost(), 0)


def test_sequence_number_wraparound() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    var streams: List[UInt16] = [0]
    # Move the stream close to the wrap in steps of less than half the
    # sequence number space; a larger jump would look like an old value.
    for target in [30000, 60000, 65533]:
        var ssns: List[UInt16] = [UInt16(target)]
        r.forward(0, 0, Span(streams), Span(ssns), out)
    _ = r.insert(_chunk(3, 0, 0, B | E, "wrapped"), 0, out)
    _ = r.insert(_chunk(2, 0, 65535, B | E, "last"), 0, out)
    assert_equal(len(out), 0)
    _ = r.insert(_chunk(1, 0, 65534, B | E, "before"), 3, out)
    assert_equal(_texts(out), "before|last|wrapped")
    _ = r.insert(_chunk(4, 0, 1, B | E, "one"), 4, out)
    assert_equal(_texts(out), "before|last|wrapped|one")


def test_reset_stream() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    _ = r.insert(_chunk(1, 2, 0, B | E, "a"), 1, out)
    _ = r.insert(_chunk(2, 2, 1, B | E, "b"), 2, out)
    # Held data of the stream, a partial ordered message, an unordered
    # partial message and another stream.
    _ = r.insert(_chunk(4, 2, 3, B | E, "held"), 2, out)
    _ = r.insert(_chunk(6, 2, 4, B, "part"), 2, out)
    _ = r.insert(_chunk(8, 2, 0, U | B, "u1"), 2, out)
    _ = r.insert(_chunk(10, 3, 1, B | E, "other"), 2, out)
    assert_equal(r.fragment_count(), 4)
    r.reset_stream(2)
    assert_equal(r.fragment_count(), 2)
    # The stream starts again at 0.
    _ = r.insert(_chunk(11, 2, 0, B | E, "fresh"), 2, out)
    assert_equal(_texts(out), "a|b|fresh")
    _ = r.insert(_chunk(9, 2, 0, U | E, "u2"), 2, out)
    assert_equal(_texts(out), "a|b|fresh|u1u2")
    _ = r.insert(_chunk(12, 3, 0, B | E, "zero"), 2, out)
    assert_equal(_texts(out), "a|b|fresh|u1u2|zero|other")
    assert_equal(r.cost(), 0)
    r.reset_stream(99)


def test_clear() raises:
    var r = Reassembly(1000)
    var out = List[SctpMessage]()
    _ = r.insert(_chunk(5, 0, 3, B | E, "x"), 0, out)
    _ = r.insert(_chunk(7, 0, 0, U | B, "y"), 0, out)
    assert_true(r.cost() > 0)
    r.clear()
    assert_equal(r.cost(), 0)
    assert_equal(r.fragment_count(), 0)
    _ = r.insert(_chunk(1, 0, 0, B | E, "z"), 1, out)
    assert_equal(_texts(out), "z")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
