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
    outgoing_reset_request,
)
from nethernet.sctp.sender import Sender
from nethernet.sctp.stream_reset import (
    RESET_RESPONSE_FINAL,
    RESET_RESPONSE_IGNORED,
    RESET_RESPONSE_IN_PROGRESS,
    StreamReset,
)
from std.testing import TestSuite, assert_equal, assert_false, assert_true

comptime LOCAL_TSN = 1000
comptime PEER_TSN = 7000


def _sender() -> Sender:
    var s = Sender(LOCAL_TSN, 1200, 1000, 1000, 60000)
    s.set_peer(1 << 20, True)
    return s^


def _reset() -> StreamReset:
    var r = StreamReset(LOCAL_TSN)
    r.set_peer(PEER_TSN)
    return r^


def _only(chunk: List[UInt8]) raises -> ReconfigParam:
    """The single parameter of an encoded RE-CONFIG chunk."""
    assert_true(len(chunk) >= 4)
    assert_equal(chunk[0], 130)
    var params = decode_reconfig(Span(chunk)[4 : len(chunk)])
    assert_equal(len(params), 1)
    return params[0].copy()


def _request(seq: UInt32, last_tsn: UInt32, stream: UInt16) -> ReconfigParam:
    var streams: List[UInt16] = [stream]
    return outgoing_reset_request(seq, 0, last_tsn, Span(streams))


def test_outgoing_request_lifecycle() raises:
    var s = _sender()
    var r = _reset()
    # Nothing to do yet.
    assert_false(r.start_request(s, True))
    s.queue_reset(3)
    s.queue_reset(4)
    assert_true(r.start_request(s, True))
    var req = _only(r.request_chunk())
    assert_true(req.kind == PARAM_OUTGOING_RESET)
    assert_equal(req.request_seq, LOCAL_TSN)
    assert_equal(req.response_seq, PEER_TSN - 1)
    # No DATA was sent yet: the last assigned TSN is one before the first.
    assert_equal(req.last_tsn, LOCAL_TSN - 1)
    assert_equal(len(req.streams), 2)
    assert_equal(req.streams[0], 3)
    assert_equal(req.streams[1], 4)
    # While it is open, further resets wait and the chunk stays the same.
    s.queue_reset(5)
    assert_false(r.start_request(s, True))
    assert_equal(_only(r.request_chunk()).request_seq, LOCAL_TSN)
    # Responses for other sequence numbers are ignored.
    assert_equal(
        r.on_response(LOCAL_TSN + 9, RECONFIG_RESULT_PERFORMED, s),
        RESET_RESPONSE_IGNORED,
    )
    assert_false(r.in_progress)
    assert_equal(
        r.on_response(LOCAL_TSN, RECONFIG_RESULT_IN_PROGRESS, s),
        RESET_RESPONSE_IN_PROGRESS,
    )
    assert_true(r.in_progress)
    r.timer.start(500)
    assert_equal(
        r.on_response(LOCAL_TSN, RECONFIG_RESULT_PERFORMED, s),
        RESET_RESPONSE_FINAL,
    )
    assert_false(r.in_progress)
    assert_false(r.timer.armed)
    # A repeated response no longer matches.
    assert_equal(
        r.on_response(LOCAL_TSN, RECONFIG_RESULT_PERFORMED, s),
        RESET_RESPONSE_IGNORED,
    )
    # The waiting stream goes into the next request, with the next number.
    assert_true(r.start_request(s, True))
    var next = _only(r.request_chunk())
    assert_equal(next.request_seq, LOCAL_TSN + 1)
    assert_equal(len(next.streams), 1)
    assert_equal(next.streams[0], 5)


def test_peer_without_reconfig_support() raises:
    var s = _sender()
    var r = _reset()
    s.queue_reset(3)
    assert_false(r.start_request(s, False))
    # The stream is released at once: data on it flows.
    var payload: List[UInt8] = [1, 2, 3]
    s.queue_message(3, 53, Span(payload), False, -1)
    var out = List[UInt8]()
    assert_equal(s.fill(out, 1200, 0), 1)


def test_incoming_outgoing_reset_request() raises:
    var s = _sender()
    var r = _reset()
    var streams = List[UInt16]()
    # All data up to the request's last TSN has arrived.
    var resp = _only(
        r.on_request(_request(PEER_TSN, 50, 4), 50, True, True, s, streams)
    )
    assert_true(resp.kind == PARAM_RECONFIG_RESPONSE)
    assert_equal(resp.request_seq, PEER_TSN)
    assert_true(resp.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 1)
    assert_equal(streams[0], 4)
    # The same request again: same answer, nothing reset twice.
    streams.clear()
    var again = _only(
        r.on_request(_request(PEER_TSN, 50, 4), 50, True, True, s, streams)
    )
    assert_true(again.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 0)
    # An older sequence number.
    var old = _only(
        r.on_request(_request(PEER_TSN - 5, 50, 4), 50, True, True, s, streams)
    )
    assert_equal(old.request_seq, PEER_TSN - 5)
    assert_true(old.result == RECONFIG_RESULT_BAD_SEQUENCE)
    assert_equal(len(streams), 0)
    # Our own next request names the peer's request as the last one seen.
    s.queue_reset(1)
    assert_true(r.start_request(s, True))
    assert_equal(_only(r.request_chunk()).response_seq, PEER_TSN)


def test_incoming_request_waits_for_data() raises:
    var s = _sender()
    var r = _reset()
    var streams = List[UInt16]()
    var first = _only(
        r.on_request(_request(PEER_TSN, 60, 4), 50, True, True, s, streams)
    )
    assert_true(first.result == RECONFIG_RESULT_IN_PROGRESS)
    assert_equal(len(streams), 0)
    # Still missing data: nothing happens.
    assert_equal(len(r.on_cumulative_tsn(59, True, streams)), 0)
    # No room to report it: wait.
    assert_equal(len(r.on_cumulative_tsn(60, False, streams)), 0)
    assert_equal(len(streams), 0)
    var done = _only(r.on_cumulative_tsn(60, True, streams))
    assert_equal(done.request_seq, PEER_TSN)
    assert_true(done.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 1)
    # Completed once.
    streams.clear()
    assert_equal(len(r.on_cumulative_tsn(61, True, streams)), 0)
    assert_equal(len(streams), 0)
    # A retransmitted copy of the request gets the final answer.
    var again = _only(
        r.on_request(_request(PEER_TSN, 60, 4), 61, True, True, s, streams)
    )
    assert_true(again.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 0)


def test_request_without_room_to_report_is_not_answered() raises:
    var s = _sender()
    var r = _reset()
    var streams = List[UInt16]()
    assert_equal(
        len(
            r.on_request(_request(PEER_TSN, 50, 4), 50, False, True, s, streams)
        ),
        0,
    )
    assert_equal(len(streams), 0)
    # The peer retransmits and there is room now.
    var resp = _only(
        r.on_request(_request(PEER_TSN, 50, 4), 50, True, True, s, streams)
    )
    assert_true(resp.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 1)


def test_other_request_kinds() raises:
    var s = _sender()
    var r = _reset()
    var streams = List[UInt16]()
    # Incoming SSN Reset Request: our stream 8 gets a reset queued.
    var incoming = ReconfigParam(PARAM_INCOMING_RESET, PEER_TSN)
    incoming.streams = [8]
    var resp = _only(r.on_request(incoming, 0, True, True, s, streams))
    assert_true(resp.result == RECONFIG_RESULT_PERFORMED)
    assert_equal(len(streams), 0)
    assert_true(r.start_request(s, True))
    assert_equal(_only(r.request_chunk()).streams[0], 8)
    # Not allowed while shutting down.
    var late = ReconfigParam(PARAM_INCOMING_RESET, PEER_TSN + 1)
    late.streams = [9]
    var denied = _only(r.on_request(late, 0, True, False, s, streams))
    assert_true(denied.result == RECONFIG_RESULT_DENIED)
    # Adding streams is refused.
    var add = ReconfigParam(PARAM_ADD_OUTGOING_STREAMS, PEER_TSN + 2)
    var refused = _only(r.on_request(add, 0, True, True, s, streams))
    assert_true(refused.result == RECONFIG_RESULT_DENIED)
    # A response or unknown parameter is not a request.
    var unknown = ReconfigParam(99, PEER_TSN + 3)
    assert_equal(len(r.on_request(unknown, 0, True, True, s, streams)), 0)
    var response = ReconfigParam(PARAM_RECONFIG_RESPONSE, PEER_TSN + 3)
    assert_equal(len(r.on_request(response, 0, True, True, s, streams)), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
