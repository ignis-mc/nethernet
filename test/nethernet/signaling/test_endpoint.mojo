from nethernet.conn import Conn
from nethernet.dialer import DialAttempt, DialConfig
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet, wait_readable
from nethernet.os.tcp import TcpStream
from nethernet.os.time import monotonic_ms
from nethernet.signaling.endpoint import (
    EndpointClient,
    EndpointServer,
    EndpointStatus,
)
from nethernet.signaling.signal import (
    SIGNAL_ANSWER,
    SIGNAL_CANDIDATE,
    SIGNAL_ERROR,
    SIGNAL_OFFER,
    Signal,
)
from nethernet.wire import bytes_of, string_of
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

comptime LOOPBACK = 0x7F000001


def _request(
    mut server: EndpointServer, request: StringSpan, settle_ms: Int = 200
) raises -> String:
    """Sends raw bytes to the server and returns everything it answers."""
    var stream = TcpStream.connect(server.local_addr(), 1000)
    stream.write_all(request.as_bytes(), 1000)
    var out = List[UInt8]()
    var chunk = List[UInt8](length=4096, fill=0)
    var deadline = monotonic_ms() + settle_ms
    while monotonic_ms() < deadline:
        server.service(monotonic_ms())
        var n = stream.read(Span(chunk))
        if n == 0:
            break
        if n > 0:
            out.extend(Span(chunk)[0:n])
        else:
            _ = wait_readable(stream.fd(), 5)
    return string_of(Span(out))


def test_probe() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    var empty = _request(server, "GET /v1/join HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true(empty.startswith("HTTP/1.1 200 OK\r\n"))
    assert_true(
        empty.endswith("Content-Length: 0\r\nConnection: close\r\n\r\n")
    )

    var status = EndpointStatus()
    status.name = 'Mojo "server"'
    status.version = "1.26.50"
    status.level = "world"
    status.players = 1
    status.max_players = 8
    status.game_type = 2
    server.set_status(status)
    var with_status = _request(
        server, "GET /v1/join?version=1&protocol=2 HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert_true("Content-Type: application/json\r\n" in with_status)
    assert_true(
        with_status.endswith(
            '{"name":"Mojo'
            ' \\"server\\"","protocol":0,"version":"1.26.50","level":"world","players":1,"maxPlayers":8,"gameType":2}'
        )
    )

    var client = EndpointClient(server.local_addr())
    assert_equal(
        client.url(), String(t"http://127.0.0.1:{server.local_addr().port}")
    )


def test_rejects_bad_requests() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    # A TLS ClientHello is dropped at once, without a response.
    var tls = List[UInt8]()
    tls.append(0x16)
    tls.append(0x03)
    tls.append(0x01)
    assert_equal(_request(server, string_of(Span(tls))), "")
    assert_true(
        _request(server, "GET /nope HTTP/1.1\r\n\r\n").startswith(
            "HTTP/1.1 404"
        )
    )
    assert_true(
        _request(
            server, "PUT /v1/join/1 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
        ).startswith("HTTP/1.1 405")
    )
    assert_true(
        _request(
            server, "POST /v1/join HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
        ).startswith("HTTP/1.1 405")
    )
    assert_true(
        _request(
            server, "POST /v1/join/abc HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
        ).startswith("HTTP/1.1 400")
    )
    assert_true(
        _request(
            server,
            (
                "POST /v1/join/99999999999999999999999"
                " HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
            ),
        ).startswith("HTTP/1.1 400")
    )
    assert_true(
        _request(
            server, "POST /v1/join/5 HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
        ).startswith("HTTP/1.1 400")
    )
    assert_true(
        _request(server, "POST /v1/join/5 HTTP/1.1\r\n\r\n").startswith(
            "HTTP/1.1 411"
        )
    )
    assert_true(
        _request(
            server,
            "POST /v1/join/5 HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n",
        ).startswith("HTTP/1.1 413")
    )
    assert_true(_request(server, "garbage\r\n\r\n").startswith(""))
    assert_true(server.poll_signal() is None)
    assert_equal(server.pending_requests(), 0)


def test_offer_answer_round_trip() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    var client = EndpointClient(server.local_addr())
    client.send_signal(
        Signal(SIGNAL_OFFER, 77, "v=0\r\noffer\r\n", client.url())
    )
    with assert_raises(contains="already in flight"):
        client.send_signal(Signal(SIGNAL_OFFER, 78, "x", client.url()))
    with assert_raises(contains="only offers"):
        client.send_signal(
            Signal(SIGNAL_CANDIDATE, 77, "candidate:1", client.url())
        )

    var offer: Optional[Signal] = None
    for _ in range(100):
        server.service(monotonic_ms())
        offer = server.poll_signal()
        if offer is not None:
            break
        _ = wait_readable(server.poll_fd(), 5)
    assert_true(offer is not None)
    var got = offer.take()
    assert_equal(got.kind, SIGNAL_OFFER)
    assert_equal(got.data, "v=0\r\noffer\r\n")
    assert_equal(got.network_id, client.network_id())
    assert_equal(server.pending_requests(), 1)

    with assert_raises(contains="only answers"):
        server.send_signal(
            Signal(SIGNAL_CANDIDATE, got.connection_id, "c", got.network_id)
        )
    with assert_raises(contains="no pending request"):
        server.send_signal(
            Signal(SIGNAL_ANSWER, got.connection_id + 1, "x", got.network_id)
        )
    server.send_signal(
        Signal(
            SIGNAL_ANSWER,
            got.connection_id,
            "v=0\r\nanswer\r\n",
            got.network_id,
        )
    )
    assert_equal(server.pending_requests(), 0)

    var answer: Optional[Signal] = None
    for _ in range(100):
        client.service(monotonic_ms())
        answer = client.poll_signal()
        if answer is not None:
            break
        _ = wait_readable(client.poll_fd(), 5)
    var reply = answer.take()
    assert_equal(reply.kind, SIGNAL_ANSWER)
    # The client reports its own connection ID and the URL as the sender.
    assert_equal(reply.connection_id, 77)
    assert_equal(reply.network_id, client.url())
    assert_equal(reply.data, "v=0\r\nanswer\r\n")
    assert_equal(client.poll_fd(), -1)


def test_error_code_response() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    var client = EndpointClient(server.local_addr())
    client.send_signal(Signal(SIGNAL_OFFER, 5, "offer", client.url()))
    var offer: Optional[Signal] = None
    for _ in range(100):
        server.service(monotonic_ms())
        offer = server.poll_signal()
        if offer is not None:
            break
        _ = wait_readable(server.poll_fd(), 5)
    var got = offer.take()
    server.send_signal(
        Signal(SIGNAL_ERROR, got.connection_id, "37", got.network_id)
    )
    var answer: Optional[Signal] = None
    for _ in range(100):
        client.service(monotonic_ms())
        answer = client.poll_signal()
        if answer is not None:
            break
        _ = wait_readable(client.poll_fd(), 5)
    var reply = answer.take()
    assert_equal(reply.kind, SIGNAL_ERROR)
    assert_equal(reply.error_code(), 37)
    # Error signals from the client have nowhere to go and are dropped.
    client.send_signal(Signal(SIGNAL_ERROR, 5, "9", client.url()))
    assert_equal(client.poll_fd(), -1)


def test_unreachable_server() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    var addr = server.local_addr()
    _ = server^
    var client = EndpointClient(addr)
    with assert_raises():
        client.send_signal(Signal(SIGNAL_OFFER, 5, "offer", client.url()))
    with assert_raises():
        _ = client.probe(500)


def test_full_connection_over_http_signaling() raises:
    var server = EndpointServer(SocketAddr(LOOPBACK, 0))
    var addr = server.local_addr()
    var listen_config = ListenConfig()
    listen_config.conn.bind_ip = LOOPBACK
    var listener = Listener[EndpointServer](server^, listen_config)
    var client = EndpointClient(addr)
    var dial_config = DialConfig()
    dial_config.conn.bind_ip = LOOPBACK
    var attempt = DialAttempt(client, client.url(), dial_config)
    var accepted: Optional[Conn] = None
    var deadline = monotonic_ms() + 10000
    while monotonic_ms() < deadline:
        var now = monotonic_ms()
        listener.poll(now)
        attempt.poll(client, now)
        if accepted is None:
            accepted = listener.try_accept()
        if attempt.is_done() and accepted is not None:
            break
        var set = PollSet()
        _ = set.add(attempt.fd())
        _ = set.add(listener.signaling().poll_fd())
        _ = set.wait(5)
    var dialer_conn = attempt^.finish()
    assert_true(accepted is not None)
    var acceptor = accepted.take()
    assert_true(dialer_conn.is_open())
    assert_true(acceptor.is_open())
    # The answer carried the listener's identity, which the dialer checked.
    assert_equal(len(dialer_conn.peer_public_key()), 97)
    assert_equal(len(acceptor.peer_public_key()), 97)
    assert_false(acceptor.remote_network_id() == "")

    var msg = bytes_of("over http signaling")
    dialer_conn.send(Span(msg))
    var got: Optional[List[UInt8]] = None
    for _ in range(500):
        var now = monotonic_ms()
        dialer_conn.poll(now)
        acceptor.poll(now)
        got = acceptor.receive()
        if got is not None:
            break
        var set = PollSet()
        _ = set.add(dialer_conn.fd())
        _ = set.add(acceptor.fd())
        _ = set.wait(5)
    assert_equal(string_of(Span(got.value())), "over http signaling")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
