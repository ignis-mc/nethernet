from nethernet.discovery.packet import (
    PACKET_MESSAGE,
    PACKET_REQUEST,
    PACKET_RESPONSE,
    DiscoveryPacket,
    discovery_key,
    marshal_packet,
    unmarshal_packet,
)
from nethernet.discovery.server_data import GAME_TYPE_ADVENTURE, ServerData
from nethernet.wire import bytes_of, hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true


def test_key() raises:
    var key = discovery_key()
    assert_equal(
        hex_encode(Span(key)),
        "eed4c37861936c6ebb91ab9d195c1b489de46362d3bb8e30d8aab08bf217e6f3",
    )


def test_request_layout() raises:
    var pk = DiscoveryPacket.request(0x1122334455667788)
    var payload = pk.encode_payload()
    # 20 bytes: length 20, ID 0, sender LE, 8 zero bytes.
    assert_equal(
        hex_encode(Span(payload)),
        "1400000088776655443322110000000000000000",
    )
    var datagram = marshal_packet(pk)
    # 32-byte HMAC plus two AES blocks.
    assert_equal(len(datagram), 64)
    var back = unmarshal_packet(Span(datagram))
    assert_equal(back.kind, PACKET_REQUEST)
    assert_equal(back.sender_id, 0x1122334455667788)


def test_response_round_trip() raises:
    var app = hex_decode("0706736572766572")
    var pk = DiscoveryPacket.response(42, Span(app))
    var payload = pk.encode_payload()
    # Header (20) + u32 hex length + lowercase ASCII hex.
    assert_equal(len(payload), 20 + 4 + 16)
    assert_equal(hex_encode(Span(payload)[20:24]), "10000000")
    assert_equal(hex_encode(Span(payload)[24:40]), hex_encode(Span(bytes_of("0706736572766572"))))
    var back = unmarshal_packet(Span(marshal_packet(pk)))
    assert_equal(back.kind, PACKET_RESPONSE)
    assert_equal(back.sender_id, 42)
    assert_equal(hex_encode(Span(back.application_data)), "0706736572766572")


def test_message_round_trip_and_declared_length() raises:
    var pk = DiscoveryPacket.message(7, 9, "CONNECTREQUEST 1 v=0")
    var payload = pk.encode_payload()
    assert_equal(len(payload), 32 + 20)
    # Declared length covers the 32-byte header plus the data.
    assert_equal(hex_encode(Span(payload)[0:2]), "3400")
    assert_equal(hex_encode(Span(payload)[20:28]), "0900000000000000")
    assert_equal(hex_encode(Span(payload)[28:32]), "14000000")
    var back = unmarshal_packet(Span(marshal_packet(pk)))
    assert_equal(back.kind, PACKET_MESSAGE)
    assert_equal(back.sender_id, 7)
    assert_equal(back.recipient_id, 9)
    assert_equal(back.data, "CONNECTREQUEST 1 v=0")

    # Data longer than 1140 bytes: the declared lengths are capped but the
    # whole signal still travels.
    var long = String()
    for _ in range(300):
        long += "0123456789"
    var big = DiscoveryPacket.message(7, 9, long)
    var big_payload = big.encode_payload()
    assert_equal(len(big_payload), 32 + 3000)
    assert_equal(hex_encode(Span(big_payload)[0:2]), "9404")
    assert_equal(hex_encode(Span(big_payload)[28:32]), "74040000")
    var big_back = unmarshal_packet(Span(marshal_packet(big)))
    assert_equal(big_back.data.byte_length(), 3000)
    assert_true(big_back.data == long)


def test_rejects_tampering() raises:
    var pk = DiscoveryPacket.message(7, 9, "CONNECTERROR 1 5")
    var datagram = marshal_packet(pk)
    var bad_mac = datagram.copy()
    bad_mac[0] ^= 1
    with assert_raises(contains="checksum"):
        _ = unmarshal_packet(Span(bad_mac))
    var bad_body = datagram.copy()
    bad_body[40] ^= 1
    with assert_raises():
        _ = unmarshal_packet(Span(bad_body))
    with assert_raises(contains="too short"):
        _ = unmarshal_packet(Span(datagram)[0:31])
    with assert_raises():
        _ = unmarshal_packet(Span(datagram)[0:40])
    var unknown = DiscoveryPacket(9, 1)
    with assert_raises(contains="unknown packet ID"):
        _ = unmarshal_packet(Span(marshal_packet(unknown)))


def test_server_data_vector() raises:
    # go-nethernet discovery/server_data_test.go
    var d = ServerData()
    d.server_name = "server"
    d.protocol = 2181
    d.version = "1.26.50"
    d.level_name = "world"
    d.player_count = 1
    d.max_player_count = 8
    d.game_type = GAME_TYPE_ADVENTURE
    d.editor_world = False
    d.hardcore = True
    d.accepts_online_auth = True
    d.accepts_self_signed_auth = True
    d.nonce = "nonce"
    d.connection_type = 4
    var expected = String("0706") + hex_encode(Span(bytes_of("server"))) + "8a2207" + hex_encode(Span(bytes_of("1.26.50"))) + "05" + hex_encode(Span(bytes_of("world"))) + "0210040001010105" + hex_encode(Span(bytes_of("nonce"))) + "08"
    var encoded = d.encode()
    assert_equal(hex_encode(Span(encoded)), expected)
    var back = ServerData.decode(Span(encoded))
    assert_equal(back.server_name, "server")
    assert_equal(back.protocol, 2181)
    assert_equal(back.version, "1.26.50")
    assert_equal(back.level_name, "world")
    assert_equal(back.player_count, 1)
    assert_equal(back.max_player_count, 8)
    assert_equal(back.game_type, GAME_TYPE_ADVENTURE)
    assert_false(back.editor_world)
    assert_true(back.hardcore)
    assert_true(back.accepts_online_auth)
    assert_true(back.accepts_self_signed_auth)
    assert_equal(back.nonce, "nonce")
    assert_equal(back.connection_type, 4)


def test_server_data_rejects_malformed() raises:
    var d = ServerData()
    d.server_name = "x"
    var encoded = d.encode()
    var trailing = encoded.copy()
    trailing.append(0)
    with assert_raises(contains="trailing"):
        _ = ServerData.decode(Span(trailing))
    with assert_raises():
        _ = ServerData.decode(Span(encoded)[0 : len(encoded) - 1])
    var wrong_version = encoded.copy()
    wrong_version[0] = 6
    with assert_raises(contains="version"):
        _ = ServerData.decode(Span(wrong_version))
    # Negative numbers survive the zigzag encoding.
    var neg = ServerData()
    neg.protocol = -5
    neg.player_count = -2147483648
    var back = ServerData.decode(Span(neg.encode()))
    assert_equal(back.protocol, -5)
    assert_equal(back.player_count, -2147483648)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
