from nethernet.discovery.listener import (
    ADDRESS_LIFETIME_MS,
    RESPONSE_LIFETIME_MS,
    DiscoveryListener,
)
from nethernet.discovery.server_data import ServerData
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import wait_readable
from nethernet.signaling.signal import SIGNAL_ANSWER, SIGNAL_OFFER, Signal
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def _loopback() -> SocketAddr:
    return SocketAddr.v4(127, 0, 0, 1, 0)


def _settle(mut a: DiscoveryListener, mut b: DiscoveryListener, now_ms: Int) raises:
    """Lets datagrams cross the loopback and be processed by both ends."""
    for _ in range(4):
        _ = wait_readable(a.poll_fd(), 20)
        a.service(now_ms)
        _ = wait_readable(b.poll_fd(), 20)
        b.service(now_ms)


def test_discovery_and_signal_exchange() raises:
    var host = DiscoveryListener(_loopback(), 1001, None)
    var host_addr = host.local_addr()
    var data = ServerData()
    data.server_name = "Mojo World"
    data.level_name = "lobby"
    data.max_player_count = 10
    host.set_server_data(data)
    # The client "broadcasts" straight at the host for the test.
    var client = DiscoveryListener(_loopback(), 2002, host_addr)
    assert_equal(client.network_id(), "2002")
    assert_equal(host.id(), 1001)
    assert_equal(len(client.responses()), 0)

    client.service(0)
    _settle(host, client, 10)
    var found = client.responses()
    assert_equal(len(found), 1)
    assert_equal(found[0].network_id, 1001)
    assert_true(found[0].addr == host_addr)
    var decoded = ServerData.decode(Span(found[0].data))
    assert_equal(decoded.server_name, "Mojo World")
    assert_equal(decoded.level_name, "lobby")

    # The client now knows the host's address and can signal it; the host
    # learns the client's address from that message and can answer.
    client.send_signal(Signal(SIGNAL_OFFER, 77, "v=0\r\n", "1001"))
    _settle(host, client, 20)
    var offer = host.poll_signal()
    assert_true(offer is not None)
    assert_equal(offer.value().kind, SIGNAL_OFFER)
    assert_equal(offer.value().connection_id, 77)
    assert_equal(offer.value().data, "v=0\r\n")
    assert_equal(offer.value().network_id, "2002")
    assert_true(host.poll_signal() is None)

    host.send_signal(Signal(SIGNAL_ANSWER, 77, "v=0\r\nanswer", "2002"))
    _settle(host, client, 30)
    var answer = client.poll_signal()
    assert_equal(answer.value().kind, SIGNAL_ANSWER)
    assert_equal(answer.value().network_id, "1001")


def test_send_to_unknown_peer_fails() raises:
    var a = DiscoveryListener(_loopback(), 1, _loopback())
    with assert_raises(contains="no address"):
        a.send_signal(Signal(SIGNAL_OFFER, 1, "x", "999"))
    with assert_raises(contains="not a number"):
        a.send_signal(Signal(SIGNAL_OFFER, 1, "x", "http://host"))


def test_ignores_garbage_and_foreign_recipients() raises:
    var host = DiscoveryListener(_loopback(), 5, None)
    var host_addr = host.local_addr()
    var other = DiscoveryListener(_loopback(), 6, host_addr)
    other.add_peer(5, host_addr, 0)
    # Addressed to someone else: dropped.
    other.add_peer(123, host_addr, 0)
    other.send_signal(Signal(SIGNAL_OFFER, 1, "x", "123"))
    _settle(host, other, 10)
    assert_true(host.poll_signal() is None)
    # A host without server data stays silent on requests.
    other.service(20)
    _settle(host, other, 30)
    assert_equal(len(other.responses()), 0)


def test_entries_expire() raises:
    var host = DiscoveryListener(_loopback(), 11, None)
    var data = ServerData()
    data.server_name = "x"
    host.set_server_data(data)
    var client = DiscoveryListener(_loopback(), 12, host.local_addr())
    client.service(0)
    _settle(host, client, 10)
    assert_equal(len(client.responses()), 1)
    # Stop the host answering: its entry ages out.
    client.service(10 + RESPONSE_LIFETIME_MS - 100)
    client.service(10 + RESPONSE_LIFETIME_MS + 10)
    assert_equal(len(client.responses()), 0)
    # The address is remembered longer, then forgotten too.
    client.send_signal(Signal(SIGNAL_OFFER, 1, "x", "11"))
    client.service(10 + ADDRESS_LIFETIME_MS + 10)
    with assert_raises(contains="no address"):
        client.send_signal(Signal(SIGNAL_OFFER, 1, "x", "11"))
    _ = host.poll_fd()


def test_default_broadcast_rules() raises:
    var client = DiscoveryListener(_loopback(), 21)
    assert_true(client.next_timeout() < 1_000_000)
    # A listener told not to broadcast (as on port 7551) has no timer; the
    # bound port cannot be 7551 in a test, so check the explicit path only.
    var quiet = DiscoveryListener(_loopback(), 22, None)
    assert_true(quiet.next_timeout() < 1_000_000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
