"""Hostile-input tests: every parser and state machine that reads bytes from
the network must reject mutated input without crashing."""

from nethernet.crypto.p256 import p256_private_key_from_bytes
from nethernet.crypto.p384 import p384_private_key_from_bytes
from nethernet.crypto.x509 import certificate_public_key, self_signed_certificate
from nethernet.datachannel.dcep import ChannelOpen
from nethernet.discovery.packet import DiscoveryPacket, marshal_packet, unmarshal_packet
from nethernet.discovery.server_data import ServerData
from nethernet.dtls.conn import (
    DTLS_STATE_CONNECTED,
    DTLS_STATE_FAILED,
    DTLS_STATE_HANDSHAKING,
    DtlsConfig,
    DtlsConn,
)
from nethernet.ice.agent import IceAgent
from nethernet.ice.candidate import parse_candidate
from nethernet.os.addr import SocketAddr
from nethernet.sdp.description import Description, parse_description
from nethernet.signaling.identity import IDENTITY_DOMAIN_SERVER, Identity, RemoteIdentity
from nethernet.signaling.signal import parse_signal
from nethernet.stun.message import STUN_BINDING_REQUEST, StunBuilder, parse_stun
from nethernet.wire import bytes_of, string_of
from std.testing import TestSuite, assert_true


struct Rng:
    var state: UInt32

    def __init__(out self, seed: UInt32):
        self.state = seed

    def next(mut self) -> Int:
        self.state = self.state * 1664525 + 1013904223
        return Int(self.state >> 8)

    def mutate(mut self, data: List[UInt8]) -> List[UInt8]:
        """Returns a copy with a few random edits: flips, truncation, growth."""
        var out = data.copy()
        var kind = self.next() % 6
        if len(out) == 0:
            out.append(UInt8(self.next() & 0xFF))
            return out^
        if kind == 0:
            out[self.next() % len(out)] ^= UInt8(1 << (self.next() % 8))
        elif kind == 1:
            for _ in range(1 + self.next() % 8):
                out[self.next() % len(out)] = UInt8(self.next() & 0xFF)
        elif kind == 2:
            out.shrink(self.next() % len(out))
        elif kind == 3:
            for _ in range(1 + self.next() % 32):
                out.append(UInt8(self.next() & 0xFF))
        elif kind == 4:
            var at = self.next() % len(out)
            out[at] = 0xFF
            if at + 1 < len(out):
                out[at + 1] = 0xFF
        else:
            var at = self.next() % len(out)
            out[at] = 0
        return out^


def _seed(tag: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var x = UInt32(tag) * 2654435761 + 99
    for _ in range(n):
        x = x * 1664525 + 1013904223
        out.append(UInt8((x >> 24) & 0xFF))
    return out^


struct Credentials(Copyable):
    var key: List[UInt8]
    var cert: List[UInt8]

    def __init__(out self, tag: UInt8) raises:
        var seed = _seed(tag, 40)
        var key = p256_private_key_from_bytes(Span(seed))
        self.key = List[UInt8](Span(key))
        var serial = _seed(tag + 1, 8)
        self.cert = self_signed_certificate(
            Span(self.key), Span(serial), 1_700_000_000, 1_900_000_000, "t"
        )


def _dtls(is_client: Bool, creds: Credentials, tag: UInt8) -> DtlsConn:
    var random = _seed(tag, 72)
    return DtlsConn(DtlsConfig(is_client, Span(creds.cert), Span(creds.key), Span(random)))


def _drain(mut conn: DtlsConn) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    while True:
        var d = conn.poll_transmit()
        if d is None:
            break
        out.append(d.take())
    return out^


def test_dtls_server_survives_mutated_client_hello() raises:
    var creds = Credentials(1)
    var client = _dtls(True, creds, 10)
    client.start(0)
    var hello = _drain(client)
    assert_true(len(hello) == 1)
    var rng = Rng(7)
    for _ in range(1500):
        var server = _dtls(False, creds, 20)
        server.start(0)
        var bad = rng.mutate(hello[0])
        server.handle_datagram(Span(bad), 0)
        assert_true(
            server.state() == DTLS_STATE_HANDSHAKING
            or server.state() == DTLS_STATE_FAILED
        )
        _ = _drain(server)


def test_dtls_client_survives_mutated_server_flight() raises:
    var creds = Credentials(2)
    var client = _dtls(True, creds, 30)
    var server = _dtls(False, creds, 31)
    client.start(0)
    server.start(0)
    for d in _drain(client):
        server.handle_datagram(Span(d), 0)
    var flight = _drain(server)
    assert_true(len(flight) >= 1)
    var rng = Rng(11)
    for _ in range(600):
        var victim = _dtls(True, creds, 30)
        victim.start(0)
        _ = _drain(victim)
        for d in flight:
            var bad = rng.mutate(d)
            victim.handle_datagram(Span(bad), 0)
        # A corrupted flight must never complete the handshake.
        assert_true(victim.state() != DTLS_STATE_CONNECTED)
        _ = _drain(victim)


def test_dtls_established_connection_survives_garbage() raises:
    var creds = Credentials(3)
    var client = _dtls(True, creds, 40)
    var server = _dtls(False, creds, 41)
    client.start(0)
    server.start(0)
    for _ in range(10):
        for d in _drain(client):
            server.handle_datagram(Span(d), 0)
        for d in _drain(server):
            client.handle_datagram(Span(d), 0)
    assert_true(client.state() == DTLS_STATE_CONNECTED)
    assert_true(server.state() == DTLS_STATE_CONNECTED)
    var payload = bytes_of("record")
    client.send_app_data(Span(payload))
    var record = _drain(client)
    var rng = Rng(13)
    var delivered = 0
    for _ in range(3000):
        var bad = rng.mutate(record[0])
        server.handle_datagram(Span(bad), 0)
        while True:
            var got = server.poll_app_data()
            if got is None:
                break
            # Anything that decrypts must be the authentic payload.
            assert_true(string_of(Span(got.value())) == "record")
            delivered += 1
        _ = _drain(server)
    # Appending bytes after a record leaves the record itself intact, so at
    # most one mutated copy can be accepted before the replay window drops
    # the rest; the connection must still be up.
    assert_true(delivered <= 1)
    assert_true(server.state() == DTLS_STATE_CONNECTED)


def test_stun_and_ice_survive_mutation() raises:
    var tid = Array[UInt8, 12](fill=3)
    var b = StunBuilder(STUN_BINDING_REQUEST, tid)
    b.add_username("local:remote")
    b.add_priority(5)
    b.add_ice_controlling(9)
    b.add_use_candidate()
    var key = bytes_of("local-password")
    var valid = b.finish(Span(key))
    var rng = Rng(17)
    var agent = IceAgent(False, "local", "local-password", 1, 2)
    agent.set_remote_credentials("remote", "remote-password")
    agent.start(0)
    var src = SocketAddr.v4(10, 0, 0, 9, 9)
    var answered = 0
    for i in range(4000):
        var bad = rng.mutate(valid)
        try:
            _ = parse_stun(Span(bad))
        except:
            pass
        agent.handle_packet(Span(bad), src, i)
        while agent.poll_transmit() is not None:
            answered += 1
    # Only messages whose integrity still verifies get an answer, and a
    # mutation almost always breaks it.
    assert_true(answered < 400)


def test_discovery_survives_mutation() raises:
    var data = ServerData()
    data.server_name = "name"
    data.level_name = "level"
    var encoded = data.encode()
    var packets = List[List[UInt8]]()
    packets.append(marshal_packet(DiscoveryPacket.request(1)))
    packets.append(marshal_packet(DiscoveryPacket.response(2, Span(encoded))))
    packets.append(marshal_packet(DiscoveryPacket.message(3, 4, "CONNECTREQUEST 1 v=0")))
    var rng = Rng(19)
    var accepted = 0
    for i in range(3000):
        var bad = rng.mutate(packets[i % 3])
        try:
            _ = unmarshal_packet(Span(bad))
            accepted += 1
        except:
            pass
        var bad_data = rng.mutate(encoded)
        try:
            _ = ServerData.decode(Span(bad_data))
        except:
            pass
    # The HMAC covers the whole payload: only appended bytes that leave the
    # padding valid can slip through, which is next to never.
    assert_true(accepted < 30)


def test_text_parsers_survive_mutation() raises:
    var d = Description()
    d.ice_ufrag = "ufragufragufrag"
    d.ice_pwd = "passwordpasswordpasswordpassword"
    d.fingerprint = "AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD:AA:BB:CC:DD"
    d.candidates.append("1 1 udp 2130706431 10.0.0.1 1000 typ host generation 0 ufrag x network-id 0 network-cost 0")
    var seed = _seed(9, 56)
    var p384_key = p384_private_key_from_bytes(Span(seed))
    var identity = Identity.self_signed(Span(p384_key), IDENTITY_DOMAIN_SERVER, 1_800_000_000, True)
    d.identity = identity.sign("sha-256", d.fingerprint)
    var sdp = bytes_of(d.encode())
    var candidate = bytes_of("candidate:1 1 udp 2130706431 10.0.0.1 1000 typ srflx raddr 10.0.0.2 rport 5 generation 0")
    var signal = bytes_of("CONNECTERROR 12345 37")
    var assertion = bytes_of(d.identity)
    var rng = Rng(23)
    for _ in range(2500):
        var bad_sdp = rng.mutate(sdp)
        try:
            var parsed = parse_description(string_of(Span(bad_sdp)))
            _ = parsed.fingerprint_bytes()
        except:
            pass
        var bad_candidate = rng.mutate(candidate)
        try:
            _ = parse_candidate(string_of(Span(bad_candidate)))
        except:
            pass
        var bad_signal = rng.mutate(signal)
        try:
            var s = parse_signal(string_of(Span(bad_signal)), "n")
            _ = s.error_code()
        except:
            pass
    for _ in range(400):
        var bad_assertion = rng.mutate(assertion)
        try:
            var remote = RemoteIdentity.parse(string_of(Span(bad_assertion)))
            var key = remote.public_key(True, 1_800_000_000)
            remote.verify("sha-256", d.fingerprint, Span(key))
        except:
            pass


def test_binary_parsers_survive_mutation() raises:
    var creds = Credentials(5)
    var open = List[UInt8]()
    ChannelOpen.reliable().encode(open)
    var rng = Rng(29)
    for _ in range(3000):
        var bad_cert = rng.mutate(creds.cert)
        try:
            _ = certificate_public_key(Span(bad_cert))
        except:
            pass
        var bad_open = rng.mutate(open)
        try:
            _ = ChannelOpen.decode(Span(bad_open))
        except:
            pass


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
