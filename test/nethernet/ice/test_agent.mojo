from nethernet.ice.agent import (
    ICE_DISCONNECT_MS,
    ICE_FAILED_MS,
    ICE_STATE_CHECKING,
    ICE_STATE_CONNECTED,
    ICE_STATE_DISCONNECTED,
    ICE_STATE_FAILED,
    ICE_STATE_NEW,
    IceAgent,
)
from nethernet.os.addr import SocketAddr
from nethernet.stun.message import (
    STUN_ATTR_USE_CANDIDATE,
    STUN_BINDING_REQUEST,
    STUN_BINDING_SUCCESS,
    StunBuilder,
    parse_stun,
    verify_fingerprint,
    verify_message_integrity,
)
from nethernet.wire import bytes_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _addr_a() -> SocketAddr:
    return SocketAddr.v4(10, 0, 0, 1, 1000)


def _addr_b() -> SocketAddr:
    return SocketAddr.v4(10, 0, 0, 2, 2000)


def _make(controlling: Bool, ufrag: StringSpan, pwd: StringSpan, tie: UInt64) -> IceAgent:
    return IceAgent(controlling, ufrag, pwd, tie, tie * 7919 + 13)


def _pump(mut a: IceAgent, mut b: IceAgent, now_ms: Int, drop_a_to_b: Bool = False) -> Int:
    """Delivers queued datagrams both ways until quiet; returns the count."""
    var total = 0
    var progress = True
    while progress:
        progress = False
        while True:
            var t = a.poll_transmit()
            if t is None:
                break
            var tx = t.take()
            total += 1
            progress = True
            if not drop_a_to_b:
                b.handle_packet(Span(tx.payload), _addr_a(), now_ms)
        while True:
            var t = b.poll_transmit()
            if t is None:
                break
            var tx = t.take()
            total += 1
            progress = True
            a.handle_packet(Span(tx.payload), _addr_b(), now_ms)
    return total


def _run(mut a: IceAgent, mut b: IceAgent, start_ms: Int, duration_ms: Int, drop_a_to_b: Bool = False) -> Int:
    var now = start_ms
    while now <= start_ms + duration_ms:
        a.handle_timeout(now)
        b.handle_timeout(now)
        _ = _pump(a, b, now, drop_a_to_b)
        now += 10
    return now


def test_controlling_and_controlled_connect() raises:
    var a = _make(True, "ufragA", "passwordA-passwordA-passwordA", 100)
    var b = _make(False, "ufragB", "passwordB-passwordB-passwordB", 200)
    a.set_remote_credentials("ufragB", "passwordB-passwordB-passwordB")
    b.set_remote_credentials("ufragA", "passwordA-passwordA-passwordA")
    a.add_remote_candidate(_addr_b(), 0)
    b.add_remote_candidate(_addr_a(), 0)
    assert_equal(a.state(), ICE_STATE_NEW)
    a.start(0)
    b.start(0)
    assert_equal(a.state(), ICE_STATE_CHECKING)
    _ = _run(a, b, 0, 100)
    assert_equal(a.state(), ICE_STATE_CONNECTED)
    assert_equal(b.state(), ICE_STATE_CONNECTED)
    assert_true(a.selected().value() == _addr_b())
    assert_true(b.selected().value() == _addr_a())
    assert_true(a.rtt_ms() >= 0)
    assert_true(a.is_controlling())
    assert_false(b.is_controlling())


def test_controlled_learns_peer_reflexive() raises:
    # The answerer knows no remote candidates yet (trickle) but still
    # answers checks and selects the pair the offerer nominates.
    var a = _make(True, "ufragA", "pwdA", 100)
    var b = _make(False, "ufragB", "pwdB", 200)
    a.set_remote_credentials("ufragB", "pwdB")
    b.set_remote_credentials("ufragA", "pwdA")
    a.add_remote_candidate(_addr_b(), 0)
    a.start(0)
    b.start(0)
    _ = _run(a, b, 0, 300)
    assert_equal(a.state(), ICE_STATE_CONNECTED)
    assert_equal(b.state(), ICE_STATE_CONNECTED)
    assert_true(b.selected().value() == _addr_a())


def test_request_format() raises:
    var a = _make(True, "ufragA", "pwdA", 100)
    a.set_remote_credentials("ufragB", "pwdB")
    a.add_remote_candidate(_addr_b(), 0)
    a.start(0)
    a.handle_timeout(0)
    var first = a.poll_transmit()
    var tx = first.take()
    assert_true(tx.dest == _addr_b())
    var key = bytes_of("pwdB")
    assert_true(verify_message_integrity(Span(tx.payload), Span(key)))
    assert_true(verify_fingerprint(Span(tx.payload)))
    var msg = parse_stun(Span(tx.payload))
    assert_equal(msg.msg_type, STUN_BINDING_REQUEST)
    assert_equal(msg.username().value(), "ufragB:ufragA")
    assert_equal(msg.ice_controlling().value(), 100)
    assert_true(msg.priority() is not None)
    assert_false(msg.has(STUN_ATTR_USE_CANDIDATE))
    assert_true(a.poll_transmit() is None)
    # Not re-sent before the check interval.
    a.handle_timeout(100)
    assert_true(a.poll_transmit() is None)
    a.handle_timeout(200)
    assert_true(a.poll_transmit() is not None)


def test_responds_before_start() raises:
    # A request may arrive before the answer was processed.
    var b = _make(False, "ufragB", "pwdB", 200)
    var tid = Array[UInt8, 12](fill=9)
    var req = StunBuilder(STUN_BINDING_REQUEST, tid)
    req.add_username("ufragB:ufragA")
    req.add_ice_controlling(5)
    req.add_priority(1)
    var key = bytes_of("pwdB")
    var raw = req.finish(Span(key))
    b.handle_packet(Span(raw), _addr_a(), 0)
    var first = b.poll_transmit()
    var tx = first.take()
    var msg = parse_stun(Span(tx.payload))
    assert_equal(msg.msg_type, STUN_BINDING_SUCCESS)
    assert_true(msg.xor_mapped_address().value() == _addr_a())
    assert_true(verify_message_integrity(Span(tx.payload), Span(key)))
    assert_equal(b.state(), ICE_STATE_NEW)


def test_rejects_bad_integrity_and_username() raises:
    var b = _make(False, "ufragB", "pwdB", 200)
    var tid = Array[UInt8, 12](fill=9)
    var req = StunBuilder(STUN_BINDING_REQUEST, tid)
    req.add_username("ufragB:ufragA")
    var wrong = bytes_of("not-the-password")
    var raw = req.finish(Span(wrong))
    b.handle_packet(Span(raw), _addr_a(), 0)
    assert_true(b.poll_transmit() is None)

    var req2 = StunBuilder(STUN_BINDING_REQUEST, tid)
    req2.add_username("someoneElse:ufragA")
    var key = bytes_of("pwdB")
    var raw2 = req2.finish(Span(key))
    b.handle_packet(Span(raw2), _addr_a(), 0)
    assert_true(b.poll_transmit() is None)

    var junk: List[UInt8] = [0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3]
    b.handle_packet(Span(junk), _addr_a(), 0)
    assert_true(b.poll_transmit() is None)


def test_role_conflict_resolves() raises:
    # Both sides believe they are controlling; the larger tie-breaker wins.
    var a = _make(True, "ufragA", "pwdA", 900)
    var b = _make(True, "ufragB", "pwdB", 100)
    a.set_remote_credentials("ufragB", "pwdB")
    b.set_remote_credentials("ufragA", "pwdA")
    a.add_remote_candidate(_addr_b(), 0)
    b.add_remote_candidate(_addr_a(), 0)
    a.start(0)
    b.start(0)
    _ = _run(a, b, 0, 1000)
    assert_true(a.is_controlling())
    assert_false(b.is_controlling())
    assert_equal(a.state(), ICE_STATE_CONNECTED)
    assert_equal(b.state(), ICE_STATE_CONNECTED)


def test_keepalive_and_liveness() raises:
    var a = _make(True, "ufragA", "pwdA", 100)
    var b = _make(False, "ufragB", "pwdB", 200)
    a.set_remote_credentials("ufragB", "pwdB")
    b.set_remote_credentials("ufragA", "pwdA")
    a.add_remote_candidate(_addr_b(), 0)
    b.add_remote_candidate(_addr_a(), 0)
    a.start(0)
    b.start(0)
    var now = _run(a, b, 0, 100)
    # Stays connected for a long time while keepalives flow.
    now = _run(a, b, now, 20000)
    assert_equal(a.state(), ICE_STATE_CONNECTED)
    assert_equal(b.state(), ICE_STATE_CONNECTED)
    # Then the path from A to B dies: B hears nothing.
    var cut = now
    now = _run(a, b, now, ICE_DISCONNECT_MS + 100, drop_a_to_b=True)
    assert_equal(b.state(), ICE_STATE_DISCONNECTED)
    now = _run(a, b, now, ICE_FAILED_MS, drop_a_to_b=True)
    assert_equal(b.state(), ICE_STATE_FAILED)
    assert_true(now - cut > ICE_FAILED_MS)


def test_activity_refreshes_liveness() raises:
    var a = _make(True, "ufragA", "pwdA", 100)
    var b = _make(False, "ufragB", "pwdB", 200)
    a.set_remote_credentials("ufragB", "pwdB")
    b.set_remote_credentials("ufragA", "pwdA")
    a.add_remote_candidate(_addr_b(), 0)
    b.add_remote_candidate(_addr_a(), 0)
    a.start(0)
    b.start(0)
    var now = _run(a, b, 0, 100)
    # No STUN gets through to B, but data packets do.
    while now < 20000:
        a.handle_timeout(now)
        b.handle_timeout(now)
        _ = _pump(a, b, now, drop_a_to_b=True)
        b.note_activity(_addr_a(), now)
        now += 100
    assert_equal(b.state(), ICE_STATE_CONNECTED)


def test_checking_fails_without_peer() raises:
    var a = _make(True, "ufragA", "pwdA", 100)
    a.set_remote_credentials("ufragB", "pwdB")
    a.add_remote_candidate(_addr_b(), 0)
    a.start(0)
    var now = 0
    var sent = 0
    while now <= ICE_FAILED_MS + 100:
        a.handle_timeout(now)
        while a.poll_transmit() is not None:
            sent += 1
        now += 50
    assert_equal(a.state(), ICE_STATE_FAILED)
    assert_true(sent > 100)
    assert_true(a.selected() is None)


def test_next_timeout() raises:
    var a = _make(True, "ufragA", "pwdA", 100)
    assert_true(a.next_timeout() > 1_000_000_000)
    a.set_remote_credentials("ufragB", "pwdB")
    a.add_remote_candidate(_addr_b(), 50)
    a.start(50)
    assert_equal(a.next_timeout(), 50)
    a.handle_timeout(50)
    assert_equal(a.next_timeout(), 250)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
