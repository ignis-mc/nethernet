from nethernet.conn import RELIABLE, UNRELIABLE, Conn
from nethernet.crypto.p384 import p384_private_key_from_bytes, p384_public_key
from nethernet.dialer import DialAttempt, DialConfig
from nethernet.discovery.listener import DiscoveryListener
from nethernet.discovery.server_data import ServerData
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet
from nethernet.os.random import random_bytes
from nethernet.os.time import monotonic_ms, unix_time_s
from nethernet.signaling.identity import Identity
from nethernet.wire import bytes_of, hex_encode, string_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

comptime LOOPBACK = 0x7F000001


def _listener() raises -> Listener[DiscoveryListener]:
    var discovery = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    discovery.disable_broadcast()
    var data = ServerData()
    data.server_name = "loopback"
    discovery.set_server_data(data)
    var config = ListenConfig()
    config.conn.bind_ip = LOOPBACK
    return Listener[DiscoveryListener](discovery^, config)


struct Pair(Movable):
    """Both ends of one connection."""

    var dialer: Conn
    var acceptor: Conn

    def __init__(out self, var dialer: Conn, var acceptor: Conn):
        self.dialer = dialer^
        self.acceptor = acceptor^


def _connect(
    mut listener: Listener[DiscoveryListener],
    mut client: DiscoveryListener,
    var config: DialConfig = DialConfig(),
) raises -> Pair:
    """Dials the listener from `client` and returns both ends."""
    var host_id = listener.signaling().id()
    client.add_peer(host_id, listener.signaling().local_addr(), monotonic_ms())
    config.conn.bind_ip = LOOPBACK
    config.timeout_ms = 10000
    var attempt = DialAttempt(client, String(host_id), config)
    var accepted: Optional[Conn] = None
    var deadline = monotonic_ms() + 10000
    while monotonic_ms() < deadline:
        var now = monotonic_ms()
        attempt.poll(client, now)
        listener.poll(now)
        if accepted is None:
            accepted = listener.try_accept()
        if attempt.is_done() and accepted is not None:
            break
        var set = PollSet()
        _ = set.add(attempt.fd())
        _ = set.add(client.poll_fd())
        _ = set.add(listener.signaling().poll_fd())
        _ = set.wait(5)
    var dialer_conn = attempt^.finish()
    assert_true(accepted is not None)
    return Pair(dialer_conn^, accepted.take())


def _pump(mut a: Conn, mut b: Conn, ms: Int) raises:
    var deadline = monotonic_ms() + ms
    while monotonic_ms() < deadline:
        var now = monotonic_ms()
        a.poll(now)
        b.poll(now)
        var set = PollSet()
        _ = set.add(a.fd())
        _ = set.add(b.fd())
        _ = set.wait(2)


def _receive(
    mut conn: Conn,
    mut other: Conn,
    timeout_ms: Int,
    reliability: Int = RELIABLE,
) raises -> List[UInt8]:
    var deadline = monotonic_ms() + timeout_ms
    while monotonic_ms() < deadline:
        var now = monotonic_ms()
        conn.poll(now)
        other.poll(now)
        var got = conn.receive(reliability)
        if got is not None:
            return got.take()
        var set = PollSet()
        _ = set.add(conn.fd())
        _ = set.add(other.fd())
        _ = set.wait(2)
    raise Error("no message arrived")


def test_dial_accept_and_exchange() raises:
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client)
    assert_true(pair.dialer.is_open())
    assert_true(pair.acceptor.is_open())
    assert_equal(pair.dialer.connection_id(), pair.acceptor.connection_id())
    assert_equal(pair.acceptor.remote_network_id(), client.network_id())
    assert_true(pair.dialer.remote_addr().value() == pair.acceptor.local_addr())

    var hello = bytes_of("hello from the dialer")
    pair.dialer.send(Span(hello))
    var got = _receive(pair.acceptor, pair.dialer, 5000)
    assert_equal(string_of(Span(got)), "hello from the dialer")

    var reply = bytes_of("hello from the listener")
    pair.acceptor.send(Span(reply))
    var got2 = _receive(pair.dialer, pair.acceptor, 5000)
    assert_equal(string_of(Span(got2)), "hello from the listener")

    # An empty message is not sent at all.
    var empty = List[UInt8]()
    pair.dialer.send(Span(empty))
    _pump(pair.dialer, pair.acceptor, 50)
    assert_true(pair.acceptor.receive() is None)

    # Unreliable channel.
    var datagram = bytes_of("best effort")
    pair.dialer.send(Span(datagram), UNRELIABLE)
    var got3 = _receive(pair.acceptor, pair.dialer, 5000, UNRELIABLE)
    assert_equal(string_of(Span(got3)), "best effort")

    # Messages keep their order and boundaries.
    for i in range(200):
        var msg = List[UInt8](length=1 + (i * 37) % 900, fill=UInt8(i))
        pair.dialer.send(Span(msg))
    for i in range(200):
        var m = _receive(pair.acceptor, pair.dialer, 5000)
        assert_equal(len(m), 1 + (i * 37) % 900)
        assert_equal(m[0], UInt8(i))
    assert_true(pair.dialer.latency_ms() >= 0)


def test_large_message_is_segmented() raises:
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client)
    # Larger than one segment (262143 bytes): three segments.
    var size = 600_000
    var big = List[UInt8](capacity=size)
    for i in range(size):
        big.append(UInt8((i * 7 + i // 251) & 0xFF))
    pair.acceptor.send(Span(big))
    var got = _receive(pair.dialer, pair.acceptor, 30000)
    assert_equal(len(got), size)
    var same = True
    for i in range(size):
        if got[i] != big[i]:
            same = False
    assert_true(same)
    # 600000 bytes need at least 600000 / 1156 DATA chunks each way.
    var sent = pair.acceptor.sctp_stats()
    var received = pair.dialer.sctp_stats()
    assert_true(sent.data_chunks_out >= 519)
    assert_true(received.data_chunks_in >= 519)
    assert_equal(received.messages_in, sent.messages_out)


def test_close_is_seen_by_peer() raises:
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client)
    var last = bytes_of("last words")
    pair.dialer.send(Span(last))
    _pump(pair.dialer, pair.acceptor, 100)
    pair.dialer.close(0)
    assert_true(pair.dialer.is_closed())
    _pump(pair.dialer, pair.acceptor, 200)
    assert_true(pair.acceptor.is_closed())
    # Data received before the close is still readable.
    var got = pair.acceptor.receive()
    assert_equal(string_of(Span(got.value())), "last words")
    var raised = False
    try:
        pair.acceptor.send(Span(last))
    except:
        raised = True
    assert_true(raised)


def test_two_connections_at_once() raises:
    var listener = _listener()
    var client_a = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client_a.disable_broadcast()
    var client_b = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client_b.disable_broadcast()
    var pair_a = _connect(listener, client_a)
    var pair_b = _connect(listener, client_b)
    var msg_a = bytes_of("from a")
    var msg_b = bytes_of("from b")
    pair_a.dialer.send(Span(msg_a))
    pair_b.dialer.send(Span(msg_b))
    var got_a = _receive(pair_a.acceptor, pair_a.dialer, 5000)
    var got_b = _receive(pair_b.acceptor, pair_b.dialer, 5000)
    assert_equal(string_of(Span(got_a)), "from a")
    assert_equal(string_of(Span(got_b)), "from b")
    assert_false(
        pair_a.acceptor.remote_network_id()
        == pair_b.acceptor.remote_network_id()
    )
    assert_equal(listener.pending_count(), 0)


def test_identities_are_exchanged_and_checked() raises:
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client)
    # Each side learned the other's P-384 identity key; the dialer's view is
    # the key the listener signs every answer with.
    var seen_by_dialer = pair.dialer.peer_public_key()
    var seen_by_listener = pair.acceptor.peer_public_key()
    assert_equal(len(seen_by_dialer), 97)
    assert_equal(len(seen_by_listener), 97)
    var expected = p384_public_key(Span(listener.identity_key()))
    assert_equal(hex_encode(Span(seen_by_dialer)), hex_encode(Span(expected)))
    assert_false(
        hex_encode(Span(seen_by_listener)) == hex_encode(Span(expected))
    )


def test_dial_with_an_issued_identity_token() raises:
    # A token issued elsewhere (here: minted separately, as the Minecraft
    # multiplayer token would be) is presented instead of a self-signed one.
    var key = p384_private_key_from_bytes(Span(random_bytes(56)))
    var issued = Identity.self_signed(
        Span(key), "https://issuer.example/", unix_time_s(), False
    )
    var config = DialConfig()
    config.identity_key = List[UInt8](Span(key))
    config.identity_token = issued.token
    config.identity_domain = "https://issuer.example/"
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client, config^)
    assert_equal(
        hex_encode(Span(pair.acceptor.peer_public_key())),
        hex_encode(Span(p384_public_key(Span(key)))),
    )


def test_identity_token_needs_a_key() raises:
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    client.add_peer(7, SocketAddr(LOOPBACK, 1), monotonic_ms())
    var config = DialConfig()
    config.identity_token = "a.b.c"
    with assert_raises(contains="needs identity_key"):
        _ = DialAttempt(client, "7", config)


def test_anonymous_offer_is_rejected() raises:
    var listener = _listener()
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var host_id = listener.signaling().id()
    client.add_peer(host_id, listener.signaling().local_addr(), monotonic_ms())
    var config = DialConfig()
    config.conn.bind_ip = LOOPBACK
    config.anonymous = True
    var attempt = DialAttempt(client, String(host_id), config)
    var deadline = monotonic_ms() + 5000
    while not attempt.is_done() and monotonic_ms() < deadline:
        var now = monotonic_ms()
        attempt.poll(client, now)
        listener.poll(now)
        var set = PollSet()
        _ = set.add(client.poll_fd())
        _ = set.add(listener.signaling().poll_fd())
        _ = set.wait(5)
    assert_true(attempt.is_done())
    var reason = String()
    try:
        var unexpected = attempt^.finish()
        unexpected.abort()
    except e:
        reason = String(e)
    assert_true("error code 37" in reason)
    assert_equal(listener.pending_count(), 0)
    assert_true(listener.try_accept() is None)


def test_dial_fails_when_the_peer_is_unknown() raises:
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var config = DialConfig()
    config.conn.bind_ip = LOOPBACK
    var raised = False
    try:
        var attempt = DialAttempt(client, "424242", config)
        _ = attempt.is_done()
    except e:
        raised = "no address" in String(e)
    assert_true(raised)


def test_unread_data_is_bounded() raises:
    var discovery = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    discovery.disable_broadcast()
    var listen_config = ListenConfig()
    listen_config.conn.bind_ip = LOOPBACK
    listen_config.conn.max_buffered_bytes = 100_000
    var listener = Listener[DiscoveryListener](discovery^, listen_config)
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()
    var pair = _connect(listener, client)
    # The acceptor never reads; the dialer keeps sending.
    var chunk = List[UInt8](length=20_000, fill=7)
    for _ in range(10):
        pair.dialer.send(Span(chunk))
    _pump(pair.dialer, pair.acceptor, 500)
    assert_true(pair.acceptor.is_closed())
    assert_true("overflow" in pair.acceptor.close_reason())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
