from nethernet.sctp.chunk import (
    DATA_FLAG_BEGIN,
    DATA_FLAG_END,
    DATA_FLAG_UNORDERED,
    DataChunk,
    ForwardTsnChunk,
)
from nethernet.sctp.reassembly import CHUNK_BUFFER_OVERHEAD, SctpMessage
from nethernet.sctp.receiver import (
    RECEIVE_DISCARDED,
    RECEIVE_DUPLICATE,
    RECEIVE_INVALID_STREAM,
    RECEIVE_OK,
    RECEIVE_REFUSED,
    RECEIVE_TOO_LARGE,
    Receiver,
)
from std.testing import TestSuite, assert_equal, assert_false, assert_true

comptime BE = DATA_FLAG_BEGIN | DATA_FLAG_END


def _receiver(window: UInt32) -> Receiver:
    var r = Receiver(window, 5000, 1200, 256, 65535)
    r.set_peer(100, 10)
    return r^


def _chunk(
    tsn: UInt32, stream: UInt16, ssn: UInt16, flags: UInt8, size: Int
) -> DataChunk:
    var payload = List[UInt8](length=size, fill=UInt8(tsn & 0xFF))
    return DataChunk(tsn, stream, ssn, 53, flags, Span(payload))


def test_in_order_data_and_sack() raises:
    var r = _receiver(100000)
    var out = List[SctpMessage]()
    assert_equal(r.cumulative_tsn(), 99)
    assert_equal(
        r.on_data(_chunk(100, 0, 0, BE, 10), 0, False, out), RECEIVE_OK
    )
    assert_equal(
        r.on_data(_chunk(101, 0, 1, BE, 20), 10, False, out), RECEIVE_OK
    )
    assert_equal(len(out), 2)
    assert_equal(r.cumulative_tsn(), 101)
    assert_equal(r.buffered(), 0)
    # 30 bytes are delivered but unread.
    var sack = r.build_sack(30)
    assert_equal(sack.cumulative_tsn, 101)
    assert_equal(sack.a_rwnd, 100000 - 30)
    assert_equal(len(sack.gaps), 0)
    assert_equal(len(sack.duplicates), 0)


def test_gaps_and_duplicates_in_sack() raises:
    var r = _receiver(100000)
    var out = List[SctpMessage]()
    assert_equal(
        r.on_data(_chunk(102, 0, 2, BE, 10), 0, False, out), RECEIVE_OK
    )
    assert_equal(
        r.on_data(_chunk(102, 0, 2, BE, 10), 0, False, out), RECEIVE_DUPLICATE
    )
    assert_equal(
        r.on_data(_chunk(50, 0, 0, BE, 10), 0, False, out), RECEIVE_DUPLICATE
    )
    assert_equal(len(out), 0)
    # Held for ordering: counts against the window with its overhead.
    assert_equal(r.buffered(), 10 + CHUNK_BUFFER_OVERHEAD)
    var sack = r.build_sack(0)
    assert_equal(sack.cumulative_tsn, 99)
    assert_equal(sack.a_rwnd, UInt32(100000 - 10 - CHUNK_BUFFER_OVERHEAD))
    assert_equal(len(sack.gaps), 1)
    assert_equal(sack.gaps[0].start, 3)
    assert_equal(sack.gaps[0].end, 3)
    assert_equal(len(sack.duplicates), 2)
    assert_equal(sack.duplicates[0], 102)
    assert_equal(sack.duplicates[1], 50)
    # Reported once, unless the SACK could not be sent.
    assert_equal(len(r.build_sack(0).duplicates), 0)
    r.keep_duplicates(sack)
    assert_equal(len(r.build_sack(0).duplicates), 2)
    # At most 16 duplicates are remembered.
    for _ in range(40):
        _ = r.on_data(_chunk(50, 0, 0, BE, 10), 0, False, out)
    assert_equal(len(r.build_sack(0).duplicates), 16)


def test_window_enforcement() raises:
    var r = _receiver(3000)
    var out = List[SctpMessage]()
    # Out-of-order data fills the window; more of it is refused.
    assert_equal(
        r.on_data(_chunk(102, 0, 2, BE, 1400), 0, False, out), RECEIVE_OK
    )
    assert_equal(
        r.on_data(_chunk(103, 0, 3, BE, 1400), 0, False, out), RECEIVE_OK
    )
    assert_equal(
        r.on_data(_chunk(104, 0, 4, BE, 1400), 0, False, out), RECEIVE_REFUSED
    )
    assert_equal(
        r.build_sack(0).a_rwnd,
        UInt32(3000 - 2 * (1400 + CHUNK_BUFFER_OVERHEAD)),
    )
    # The chunk that fills the hole is taken although the window is full.
    assert_equal(
        r.on_data(_chunk(100, 0, 0, BE, 1400), 0, False, out), RECEIVE_OK
    )
    assert_equal(len(out), 1)
    # 1400 bytes are now unread; with 2 x 1464 still held the next expected
    # chunk gets the extra room too.
    assert_equal(
        r.on_data(_chunk(101, 0, 1, BE, 1400), 1400, False, out), RECEIVE_OK
    )
    assert_equal(len(out), 4)
    assert_equal(r.buffered(), 0)
    # Unread messages alone fill the window: nothing more is accepted,
    # not even the next expected TSN.
    assert_equal(
        r.on_data(_chunk(104, 0, 4, BE, 100), 3000, False, out), RECEIVE_REFUSED
    )
    assert_equal(r.build_sack(3000).a_rwnd, 0)
    assert_equal(r.build_sack(5000).a_rwnd, 0)
    # A full event queue refuses data as well.
    assert_equal(
        r.on_data(_chunk(104, 0, 4, BE, 100), 0, True, out), RECEIVE_REFUSED
    )
    assert_equal(
        r.on_data(_chunk(104, 0, 4, BE, 100), 0, False, out), RECEIVE_OK
    )
    # Too far ahead of the cumulative TSN to track.
    assert_equal(
        r.on_data(_chunk(105 + 256, 0, 9, BE, 1), 0, False, out),
        RECEIVE_REFUSED,
    )


def test_window_update() raises:
    var r = _receiver(4000)
    var out = List[SctpMessage]()
    assert_false(r.window_update_due(0))
    _ = r.on_data(_chunk(100, 0, 0, BE, 3500), 0, False, out)
    # The SACK advertises 500 bytes: less than a quarter.
    assert_equal(r.build_sack(3500).a_rwnd, 500)
    assert_false(r.window_update_due(3500))
    assert_false(r.window_update_due(2600))
    # A quarter of the window became free since.
    assert_true(r.window_update_due(2500))
    assert_true(r.window_update_due(0))
    _ = r.build_sack(0)
    assert_false(r.window_update_due(0))


def test_invalid_stream_too_large_and_discarded() raises:
    var r = _receiver(100000)
    var out = List[SctpMessage]()
    # Ten inbound streams were negotiated.
    assert_equal(
        r.on_data(_chunk(100, 10, 0, BE, 5), 0, False, out),
        RECEIVE_INVALID_STREAM,
    )
    assert_equal(r.cumulative_tsn(), 100)
    assert_equal(len(out), 0)
    # A fragment whose predecessor was passed over.
    assert_equal(
        r.on_data(_chunk(101, 0, 0, DATA_FLAG_END, 5), 0, False, out),
        RECEIVE_DISCARDED,
    )
    assert_equal(r.cumulative_tsn(), 101)
    # A message beyond the 5000-byte limit.
    assert_equal(
        r.on_data(_chunk(102, 0, 0, DATA_FLAG_BEGIN, 3000), 0, False, out),
        RECEIVE_OK,
    )
    assert_equal(
        r.on_data(_chunk(103, 0, 0, 0, 3000), 0, False, out), RECEIVE_TOO_LARGE
    )


def test_forward_tsn_and_reset() raises:
    var r = _receiver(100000)
    var out = List[SctpMessage]()
    _ = r.on_data(_chunk(100, 0, 0, DATA_FLAG_BEGIN, 50), 0, False, out)
    _ = r.on_data(_chunk(103, 0, 1, BE, 60), 0, False, out)
    assert_true(r.buffered() > 0)
    var fwd = ForwardTsnChunk(102)
    fwd.stream_ids.append(0)
    fwd.ssns.append(0)
    r.on_forward_tsn(fwd, out)
    assert_equal(r.cumulative_tsn(), 103)
    assert_equal(len(out), 1)
    assert_equal(len(out[0].payload), 60)
    assert_equal(r.buffered(), 0)
    # Stream reset: sequence numbers start over.
    r.reset_stream(0)
    assert_equal(r.on_data(_chunk(104, 0, 0, BE, 7), 0, False, out), RECEIVE_OK)
    assert_equal(len(out), 2)
    _ = r.on_data(_chunk(106, 0, 5, BE, 7), 0, False, out)
    assert_true(r.buffered() > 0)
    r.clear()
    assert_equal(r.buffered(), 0)


def test_set_peer_starts_over() raises:
    var r = Receiver(100000, 5000, 1200, 256, 65535)
    r.set_peer(0, 65535)
    assert_equal(r.cumulative_tsn(), 0xFFFFFFFF)
    var out = List[SctpMessage]()
    assert_equal(
        r.on_data(_chunk(0, 0, 0, BE | DATA_FLAG_UNORDERED, 3), 0, False, out),
        RECEIVE_OK,
    )
    assert_equal(r.cumulative_tsn(), 0)
    assert_true(out[0].unordered)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
