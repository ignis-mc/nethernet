from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet, wait_readable
from nethernet.os.random import random_bytes, random_u64
from nethernet.os.tcp import TcpListener, TcpStream
from nethernet.os.time import monotonic_ms, monotonic_ns, unix_time_s
from nethernet.os.udp import UdpSocket, default_local_ip
from nethernet.wire import bytes_of, string_of
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true


def test_socket_addr_parse_and_format() raises:
    var a = SocketAddr.v4(192, 168, 1, 10, 7551)
    assert_equal(String(a), "192.168.1.10:7551")
    assert_equal(a.ip_string(), "192.168.1.10")
    assert_equal(SocketAddr.parse_ip("192.168.1.10"), a.ip)
    var b = SocketAddr.parse("127.0.0.1:19132")
    assert_true(b.is_loopback())
    assert_equal(b.port, 19132)
    assert_true(a == SocketAddr.parse("192.168.1.10:7551"))
    assert_false(a == b)
    for bad in ["1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1..2.3", "", "1.2.3.4."]:
        with assert_raises(contains="invalid IPv4"):
            _ = SocketAddr.parse_ip(bad)
    with assert_raises():
        _ = SocketAddr.parse("1.2.3.4")
    with assert_raises():
        _ = SocketAddr.parse("1.2.3.4:70000")


def test_clocks() raises:
    var a = monotonic_ns()
    var b = monotonic_ns()
    assert_true(b >= a)
    assert_true(monotonic_ms() > 0)
    # After 2024-01-01.
    assert_true(unix_time_s() > 1_704_067_200)


def test_random() raises:
    var a = random_bytes(32)
    var b = random_bytes(32)
    assert_equal(len(a), 32)
    var same = True
    for i in range(32):
        if a[i] != b[i]:
            same = False
    assert_false(same)
    assert_true(random_u64() != random_u64())


def test_udp_loopback() raises:
    var a = UdpSocket(SocketAddr.v4(127, 0, 0, 1, 0))
    var b = UdpSocket(SocketAddr.v4(127, 0, 0, 1, 0))
    var addr_a = a.local_addr()
    var addr_b = b.local_addr()
    assert_true(addr_a.port != 0)
    var buf = List[UInt8](length=1500, fill=0)
    var src = SocketAddr(0, 0)
    assert_equal(b.recv_from(Span(buf), src), -1)
    assert_false(wait_readable(b.fd(), 10))
    var msg = bytes_of("hello over udp")
    assert_true(a.send_to(Span(msg), addr_b))
    assert_true(wait_readable(b.fd(), 1000))
    var n = b.recv_from(Span(buf), src)
    assert_equal(n, len(msg))
    assert_equal(string_of(Span(buf)[0:n]), "hello over udp")
    assert_true(src == addr_a)


def test_poll_set_multiple() raises:
    var a = UdpSocket(SocketAddr.v4(127, 0, 0, 1, 0))
    var b = UdpSocket(SocketAddr.v4(127, 0, 0, 1, 0))
    var c = UdpSocket(SocketAddr.v4(127, 0, 0, 1, 0))
    var msg = bytes_of("x")
    _ = c.send_to(Span(msg), b.local_addr())
    var set = PollSet()
    var ia = set.add(a.fd())
    var ib = set.add(b.fd())
    assert_equal(len(set), 2)
    assert_equal(set.wait(1000), 1)
    assert_false(set.readable(ia))
    assert_true(set.readable(ib))
    var t0 = monotonic_ms()
    set.clear()
    _ = set.add(a.fd())
    assert_equal(set.wait(30), 0)
    assert_true(monotonic_ms() - t0 >= 25)
    # Mojo destroys a value after its last use, which would close the
    # sockets before `wait()`; touch them here to keep them open.
    _ = a.fd()
    _ = b.fd()


def test_tcp_loopback() raises:
    var listener = TcpListener(SocketAddr.v4(127, 0, 0, 1, 0))
    var addr = listener.local_addr()
    assert_true(listener.accept() is None)
    var client = TcpStream.connect(addr, 1000)
    assert_true(wait_readable(listener.fd(), 1000))
    var accepted = listener.accept()
    assert_true(accepted is not None)
    var server = accepted.take()
    var req = bytes_of("GET /v1/join HTTP/1.1\r\n\r\n")
    client.write_all(Span(req), 1000)
    assert_true(wait_readable(server.fd(), 1000))
    var buf = List[UInt8](length=256, fill=0)
    var n = server.read(Span(buf))
    assert_equal(string_of(Span(buf)[0:n]), "GET /v1/join HTTP/1.1\r\n\r\n")
    assert_equal(client.read(Span(buf)), -1)
    var resp = bytes_of("HTTP/1.1 200 OK\r\n\r\n")
    server.write_all(Span(resp), 1000)
    assert_true(wait_readable(client.fd(), 1000))
    n = client.read(Span(buf))
    assert_equal(n, len(resp))


def test_tcp_connect_refused() raises:
    var listener = TcpListener(SocketAddr.v4(127, 0, 0, 1, 0))
    var addr = listener.local_addr()
    _ = listener^
    with assert_raises(contains="connect"):
        _ = TcpStream.connect(addr, 500)


def test_default_local_ip() raises:
    var ip = UInt32(1)
    try:
        ip = default_local_ip()
    except e:
        # A host without a default route is acceptable.
        print("no default route:", e)
    assert_true(ip != 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
