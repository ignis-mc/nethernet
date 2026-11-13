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
    SCTP_STATE_SHUTDOWN_PENDING,
    SCTP_STATE_SHUTDOWN_RECEIVED,
    SCTP_STATE_SHUTDOWN_SENT,
    SctpConfig,
    SctpEvent,
    SctpStats,
)
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def test_constants_match_the_public_contract() raises:
    assert_equal(SCTP_STATE_CLOSED, 0)
    assert_equal(SCTP_STATE_COOKIE_WAIT, 1)
    assert_equal(SCTP_STATE_COOKIE_ECHOED, 2)
    assert_equal(SCTP_STATE_ESTABLISHED, 3)
    assert_equal(SCTP_STATE_SHUTDOWN_PENDING, 4)
    assert_equal(SCTP_STATE_SHUTDOWN_SENT, 5)
    assert_equal(SCTP_STATE_SHUTDOWN_RECEIVED, 6)
    assert_equal(SCTP_STATE_SHUTDOWN_ACK_SENT, 7)
    assert_equal(SCTP_EVENT_CONNECTED, 1)
    assert_equal(SCTP_EVENT_MESSAGE, 2)
    assert_equal(SCTP_EVENT_STREAM_RESET, 3)
    assert_equal(SCTP_EVENT_CLOSED, 4)


def test_config_defaults() raises:
    var secret: List[UInt8] = [1, 2, 3]
    var c = SctpConfig(0xDEADBEEF, 42, Span(secret))
    assert_equal(c.local_port, 5000)
    assert_equal(c.remote_port, 5000)
    assert_equal(c.local_tag, 0xDEADBEEF)
    assert_equal(c.initial_tsn, 42)
    assert_equal(len(c.cookie_secret), 3)
    assert_equal(c.a_rwnd, 1048576)
    assert_equal(c.mtu, 1200)
    assert_true(c.max_message_size >= 262144)
    assert_equal(c.num_outbound_streams, 65535)
    assert_equal(c.num_inbound_streams, 65535)
    assert_equal(c.rto_initial_ms, 1000)
    assert_equal(c.rto_min_ms, 1000)
    assert_equal(c.rto_max_ms, 60000)
    assert_equal(c.max_init_retransmits, 8)
    # The secret is copied, not borrowed.
    secret[0] = 9
    assert_equal(c.cookie_secret[0], 1)
    var d = c.copy()
    d.mtu = 500
    assert_equal(c.mtu, 1200)


def test_event_and_stats_start_empty() raises:
    var e = SctpEvent(SCTP_EVENT_MESSAGE)
    assert_equal(e.kind, SCTP_EVENT_MESSAGE)
    assert_equal(e.stream_id, 0)
    assert_equal(e.ppid, 0)
    assert_false(e.unordered)
    assert_equal(len(e.payload), 0)
    assert_equal(e.reason, "")
    var s = SctpStats()
    assert_equal(s.packets_in, 0)
    assert_equal(s.retransmits, 0)
    assert_equal(s.abandoned_chunks, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
