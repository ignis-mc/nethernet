from nethernet.crypto.p256 import p256_private_key_from_bytes
from nethernet.crypto.sha256 import sha256
from nethernet.crypto.x509 import self_signed_certificate
from nethernet.dtls.conn import (
    DTLS_STATE_CLOSED,
    DTLS_STATE_CONNECTED,
    DTLS_STATE_FAILED,
    DTLS_STATE_HANDSHAKING,
    DtlsConfig,
    DtlsConn,
)
from nethernet.wire import bytes_of, string_of
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _seed(tag: UInt8, n: Int) -> List[UInt8]:
    """Deterministic pseudo-random bytes for tests."""
    var out = List[UInt8]()
    var x = UInt32(tag) * 2654435761 + 12345
    for _ in range(n):
        x = x * 1664525 + 1013904223
        out.append(UInt8((x >> 24) & 0xFF))
    return out^


struct Identity(Copyable):
    var key: List[UInt8]
    var cert: List[UInt8]

    def __init__(out self, tag: UInt8) raises:
        var seed = _seed(tag, 40)
        var key = p256_private_key_from_bytes(Span(seed))
        self.key = List[UInt8](Span(key))
        var serial = _seed(tag + 100, 8)
        self.cert = self_signed_certificate(
            Span(self.key),
            Span(serial),
            1_700_000_000,
            1_900_000_000,
            "nethernet",
        )


def _make(is_client: Bool, id: Identity, tag: UInt8) -> DtlsConn:
    var random = _seed(tag, 72)
    var config = DtlsConfig(
        is_client, Span(id.cert), Span(id.key), Span(random)
    )
    return DtlsConn(config)


def _fingerprint(id: Identity) -> List[UInt8]:
    var digest = sha256(Span(id.cert))
    return List[UInt8](Span(digest))


struct Link:
    """Shuttles datagrams between two connections with optional loss."""

    var loss_percent: Int
    var rng: UInt32
    var delivered: Int

    def __init__(out self, loss_percent: Int = 0, seed: UInt32 = 1):
        self.loss_percent = loss_percent
        self.rng = seed
        self.delivered = 0

    def _should_drop(mut self) -> Bool:
        self.rng = self.rng * 1664525 + 1013904223
        return Int((self.rng >> 16) % 100) < self.loss_percent

    def pump(mut self, mut a: DtlsConn, mut b: DtlsConn, now_ms: Int):
        var progress = True
        while progress:
            progress = False
            while True:
                var d = a.poll_transmit()
                if d is None:
                    break
                var datagram = d.take()
                progress = True
                if not self._should_drop():
                    self.delivered += 1
                    b.handle_datagram(Span(datagram), now_ms)
            while True:
                var d = b.poll_transmit()
                if d is None:
                    break
                var datagram = d.take()
                progress = True
                if not self._should_drop():
                    self.delivered += 1
                    a.handle_datagram(Span(datagram), now_ms)

    def run(
        mut self, mut a: DtlsConn, mut b: DtlsConn, duration_ms: Int
    ) -> Int:
        var now = 0
        a.start(now)
        b.start(now)
        while now <= duration_ms:
            a.handle_timeout(now)
            b.handle_timeout(now)
            self.pump(a, b, now)
            if (
                a.state() != DTLS_STATE_HANDSHAKING
                and b.state() != DTLS_STATE_HANDSHAKING
            ):
                break
            now += 50
        return now


def test_handshake_and_application_data() raises:
    var cid = Identity(1)
    var sid = Identity(2)
    var client = _make(True, cid, 11)
    var server = _make(False, sid, 12)
    var link = Link()
    _ = link.run(client, server, 1000)
    assert_equal(client.state(), DTLS_STATE_CONNECTED)
    assert_equal(server.state(), DTLS_STATE_CONNECTED)
    # Each side saw the other's certificate.
    var seen_by_client = client.peer_certificate()
    var seen_by_server = server.peer_certificate()
    assert_equal(len(seen_by_client), len(sid.cert))
    assert_equal(len(seen_by_server), len(cid.cert))
    assert_true(client.srtp_profile() != 0)
    assert_equal(client.srtp_profile(), server.srtp_profile())

    var ping = bytes_of("ping from client")
    client.send_app_data(Span(ping))
    var pong = bytes_of("pong from server")
    server.send_app_data(Span(pong))
    link.pump(client, server, 2000)
    var got_ping = server.poll_app_data()
    assert_equal(string_of(Span(got_ping.value())), "ping from client")
    var got_pong = client.poll_app_data()
    assert_equal(string_of(Span(got_pong.value())), "pong from server")
    assert_true(server.poll_app_data() is None)

    # Many records, including large ones.
    for i in range(50):
        var payload = List[UInt8](length=1 + i * 23, fill=UInt8(i))
        client.send_app_data(Span(payload))
    link.pump(client, server, 3000)
    for i in range(50):
        var rec = server.poll_app_data()
        assert_equal(len(rec.value()), 1 + i * 23)
        assert_equal(rec.value()[0], UInt8(i))


def test_fingerprint_is_enforced() raises:
    var cid = Identity(3)
    var sid = Identity(4)
    var other = Identity(5)
    var crandom = _seed(31, 72)
    var cconfig = DtlsConfig(True, Span(cid.cert), Span(cid.key), Span(crandom))
    cconfig.remote_fingerprint = _fingerprint(other)
    var client = DtlsConn(cconfig)
    var server = _make(False, sid, 32)
    var link = Link()
    _ = link.run(client, server, 1000)
    assert_equal(client.state(), DTLS_STATE_FAILED)
    assert_true("fingerprint" in client.failure_reason())
    assert_equal(server.state(), DTLS_STATE_FAILED)

    # With the right fingerprint on both sides the handshake completes.
    var crandom2 = _seed(33, 72)
    var cconfig2 = DtlsConfig(
        True, Span(cid.cert), Span(cid.key), Span(crandom2)
    )
    cconfig2.remote_fingerprint = _fingerprint(sid)
    var srandom2 = _seed(34, 72)
    var sconfig2 = DtlsConfig(
        False, Span(sid.cert), Span(sid.key), Span(srandom2)
    )
    sconfig2.remote_fingerprint = _fingerprint(cid)
    var client2 = DtlsConn(cconfig2)
    var server2 = DtlsConn(sconfig2)
    var link2 = Link()
    _ = link2.run(client2, server2, 1000)
    assert_equal(client2.state(), DTLS_STATE_CONNECTED)
    assert_equal(server2.state(), DTLS_STATE_CONNECTED)


def test_server_rejects_wrong_client_fingerprint() raises:
    var cid = Identity(6)
    var sid = Identity(7)
    var other = Identity(8)
    var srandom = _seed(41, 72)
    var sconfig = DtlsConfig(
        False, Span(sid.cert), Span(sid.key), Span(srandom)
    )
    sconfig.remote_fingerprint = _fingerprint(other)
    var server = DtlsConn(sconfig)
    var client = _make(True, cid, 42)
    var link = Link()
    _ = link.run(client, server, 1000)
    assert_equal(server.state(), DTLS_STATE_FAILED)
    assert_equal(client.state(), DTLS_STATE_FAILED)


def test_handshake_survives_loss() raises:
    var cid = Identity(9)
    var sid = Identity(10)
    for trial in range(12):
        var loss = 10 + 5 * (trial % 9)
        var client = _make(True, cid, UInt8(50 + trial))
        var server = _make(False, sid, UInt8(70 + trial))
        var link = Link(loss, UInt32(trial * 977 + 3))
        var took = link.run(client, server, 120_000)
        if (
            client.state() != DTLS_STATE_CONNECTED
            or server.state() != DTLS_STATE_CONNECTED
        ):
            print(
                "loss",
                loss,
                "trial",
                trial,
                "client:",
                client.failure_reason(),
                "server:",
                server.failure_reason(),
            )
        assert_equal(client.state(), DTLS_STATE_CONNECTED)
        assert_equal(server.state(), DTLS_STATE_CONNECTED)
        assert_true(took < 120_000)
        # The session keys agree: data flows after the lossy handshake.
        link.loss_percent = 0
        var msg = bytes_of("after loss")
        client.send_app_data(Span(msg))
        link.pump(client, server, took + 10)
        var got = server.poll_app_data()
        assert_equal(string_of(Span(got.value())), "after loss")


def test_small_mtu_fragments_handshake() raises:
    var cid = Identity(13)
    var sid = Identity(14)
    var crandom = _seed(71, 72)
    var cconfig = DtlsConfig(True, Span(cid.cert), Span(cid.key), Span(crandom))
    cconfig.mtu = 200
    var srandom = _seed(72, 72)
    var sconfig = DtlsConfig(
        False, Span(sid.cert), Span(sid.key), Span(srandom)
    )
    sconfig.mtu = 200
    var client = DtlsConn(cconfig)
    var server = DtlsConn(sconfig)
    var link = Link()
    _ = link.run(client, server, 1000)
    assert_equal(client.state(), DTLS_STATE_CONNECTED)
    assert_equal(server.state(), DTLS_STATE_CONNECTED)
    # The certificate did not fit one datagram, so fragmentation happened.
    assert_true(link.delivered > 8)


def test_close_notify() raises:
    var cid = Identity(15)
    var sid = Identity(16)
    var client = _make(True, cid, 81)
    var server = _make(False, sid, 82)
    var link = Link()
    _ = link.run(client, server, 1000)
    client.close()
    assert_equal(client.state(), DTLS_STATE_CLOSED)
    link.pump(client, server, 2000)
    assert_equal(server.state(), DTLS_STATE_CLOSED)
    var msg = bytes_of("too late")
    var raised = False
    try:
        server.send_app_data(Span(msg))
    except:
        raised = True
    assert_true(raised)


def test_tampered_and_replayed_records_are_dropped() raises:
    var cid = Identity(17)
    var sid = Identity(18)
    var client = _make(True, cid, 91)
    var server = _make(False, sid, 92)
    var link = Link()
    _ = link.run(client, server, 1000)
    var msg = bytes_of("authentic")
    client.send_app_data(Span(msg))
    var d = client.poll_transmit()
    var datagram = d.take()
    var tampered = datagram.copy()
    tampered[len(tampered) - 1] ^= 1
    server.handle_datagram(Span(tampered), 2000)
    assert_true(server.poll_app_data() is None)
    server.handle_datagram(Span(datagram), 2000)
    assert_true(server.poll_app_data() is not None)
    # The same record again is a replay.
    server.handle_datagram(Span(datagram), 2000)
    assert_true(server.poll_app_data() is None)
    assert_equal(server.state(), DTLS_STATE_CONNECTED)
    # Garbage does not disturb the connection.
    var junk = List[UInt8](length=40, fill=0x17)
    server.handle_datagram(Span(junk), 2000)
    var short: List[UInt8] = [22, 0xFE, 0xFD]
    server.handle_datagram(Span(short), 2000)
    assert_equal(server.state(), DTLS_STATE_CONNECTED)


def test_handshake_times_out_without_peer() raises:
    var cid = Identity(19)
    var client = _make(True, cid, 99)
    client.start(0)
    var now = 0
    var datagrams = 0
    while now < 200_000 and client.state() == DTLS_STATE_HANDSHAKING:
        client.handle_timeout(now)
        while client.poll_transmit() is not None:
            datagrams += 1
        now += 100
    assert_equal(client.state(), DTLS_STATE_FAILED)
    assert_true(datagrams >= 10)
    assert_true("timed out" in client.failure_reason())


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
