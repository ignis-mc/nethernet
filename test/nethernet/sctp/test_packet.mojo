from nethernet.sctp.packet import (
    CHUNK_COOKIE_ACK,
    CHUNK_DATA,
    CHUNK_INIT,
    CHUNK_SACK,
    begin_chunk,
    begin_packet,
    end_chunk,
    finish_packet,
    packet_checksum,
    pad4,
    parse_packet,
    stored_checksum,
)
from nethernet.wire import hex_decode, hex_encode, put_bytes
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true

# Packets recorded from pion/sctp v1.12.0 (two associations over a pipe).
comptime PION_INIT = "1388138800000000638d94c90100001cac060e9700100000ffffffff2816389d8008000882c040c2"
comptime PION_INIT_NO_IDATA = "1388138800000000e2679aec0100001aaa764be400100000ffffffff61f569f48008000682c00000"
comptime PION_COOKIE_ACK = "13881388ac060e970634aa160b000004"
comptime PION_TWO_DATA = "13881388cf80eb67df3ffd6e0003001ac1763265000000020000003501080f161d242b323940000000030024c17632660000000300000035020910171e252c333a41484f565d646b72798087"
comptime PION_SACK = "13881388ac060e97f191e4dc03000010281638a4000fffec00000000"


def test_pad4() raises:
    assert_equal(pad4(0), 0)
    assert_equal(pad4(1), 4)
    assert_equal(pad4(4), 4)
    assert_equal(pad4(5), 8)
    assert_equal(pad4(1161), 1164)


def test_checksum_matches_pion() raises:
    for text in [PION_INIT, PION_INIT_NO_IDATA, PION_COOKIE_ACK, PION_TWO_DATA, PION_SACK]:
        var p = hex_decode(text)
        assert_equal(packet_checksum(Span(p)), stored_checksum(Span(p)))
    # The checksum is stored least significant byte first: e2 67 9a ec.
    var p = hex_decode(PION_INIT_NO_IDATA)
    assert_equal(packet_checksum(Span(p)), 0xEC9A67E2)


def test_parse_pion_init() raises:
    var p = hex_decode(PION_INIT)
    var view = parse_packet(Span(p))
    assert_equal(view.source_port, 5000)
    assert_equal(view.destination_port, 5000)
    assert_equal(view.verification_tag, 0)
    assert_equal(len(view.chunks), 1)
    assert_true(view.chunks[0].kind == CHUNK_INIT)
    assert_equal(view.chunks[0].flags, 0)
    assert_equal(view.chunks[0].offset, 16)
    assert_equal(view.chunks[0].length, 24)


def test_parse_unpadded_length_and_bundle() raises:
    # INIT with chunk length 26: two bytes of padding follow the value.
    var p = hex_decode(PION_INIT_NO_IDATA)
    var view = parse_packet(Span(p))
    assert_equal(len(view.chunks), 1)
    assert_equal(view.chunks[0].length, 22)
    # Two DATA chunks bundled; the first is 26 bytes padded to 28.
    var q = hex_decode(PION_TWO_DATA)
    var bundle = parse_packet(Span(q))
    assert_equal(bundle.verification_tag, 0xCF80EB67)
    assert_equal(len(bundle.chunks), 2)
    assert_true(bundle.chunks[0].kind == CHUNK_DATA)
    assert_equal(bundle.chunks[0].flags, 3)
    assert_equal(bundle.chunks[0].offset, 16)
    assert_equal(bundle.chunks[0].length, 22)
    assert_equal(bundle.chunks[1].offset, 44)
    assert_equal(bundle.chunks[1].length, 32)


def test_build_reproduces_pion_bytes() raises:
    var p = hex_decode(PION_INIT_NO_IDATA)
    var out = List[UInt8]()
    begin_packet(out, 5000, 5000, 0)
    var start = begin_chunk(out, CHUNK_INIT, 0)
    put_bytes(out, Span(p)[16:38])
    end_chunk(out, start)
    finish_packet(out)
    assert_equal(hex_encode(Span(out)), PION_INIT_NO_IDATA)

    var ack = List[UInt8]()
    begin_packet(ack, 5000, 5000, 0xAC060E97)
    var s2 = begin_chunk(ack, CHUNK_COOKIE_ACK, 0)
    end_chunk(ack, s2)
    finish_packet(ack)
    assert_equal(hex_encode(Span(ack)), PION_COOKIE_ACK)


def test_header_only_packet_has_no_chunks() raises:
    var out = List[UInt8]()
    begin_packet(out, 1, 2, 3)
    finish_packet(out)
    var view = parse_packet(Span(out))
    assert_equal(len(view.chunks), 0)
    assert_equal(view.source_port, 1)
    assert_equal(view.destination_port, 2)
    assert_equal(view.verification_tag, 3)


def test_last_chunk_may_omit_padding() raises:
    var out = List[UInt8]()
    begin_packet(out, 5000, 5000, 7)
    var start = begin_chunk(out, CHUNK_SACK, 0)
    out.append(0xAA)
    end_chunk(out, start)
    # Drop the three padding bytes again.
    for _ in range(3):
        _ = out.pop()
    finish_packet(out)
    var view = parse_packet(Span(out))
    assert_equal(len(view.chunks), 1)
    assert_equal(view.chunks[0].length, 1)


def _fix(mut p: List[UInt8]):
    finish_packet(p)


def test_rejects_malformed_framing() raises:
    var good = hex_decode(PION_SACK)
    # Short header.
    with assert_raises():
        _ = parse_packet(Span(good)[0:11])
    # Bad checksum.
    var bad = good.copy()
    bad[20] ^= 0x01
    with assert_raises():
        _ = parse_packet(Span(bad))
    # Chunk length below 4.
    var short = good.copy()
    short[14] = 0
    short[15] = 3
    _fix(short)
    with assert_raises():
        _ = parse_packet(Span(short))
    # Zero-length chunk.
    var zero = good.copy()
    zero[15] = 0
    _fix(zero)
    with assert_raises():
        _ = parse_packet(Span(zero))
    # Chunk length past the end.
    var long = good.copy()
    long[15] = 0x14
    _fix(long)
    with assert_raises():
        _ = parse_packet(Span(long))
    # Trailing bytes too short for a chunk header.
    var trail = good.copy()
    trail.append(0)
    trail.append(0)
    _fix(trail)
    with assert_raises():
        _ = parse_packet(Span(trail))
    # Truncation in the middle of a chunk, checksum recomputed.
    var cut = List[UInt8](Span(good)[0:20])
    _fix(cut)
    with assert_raises():
        _ = parse_packet(Span(cut))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
