from nethernet.sctp.chunk import (
    CAUSE_USER_INITIATED_ABORT,
    DATA_FLAG_BEGIN,
    DATA_FLAG_END,
    DATA_FLAG_UNORDERED,
    PARAM_INCOMING_RESET,
    PARAM_OUTGOING_RESET,
    PARAM_RECONFIG_RESPONSE,
    RECONFIG_RESULT_PERFORMED,
    DataChunk,
    ErrorCause,
    ForwardTsnChunk,
    GapBlock,
    InitChunk,
    ReconfigParam,
    SackChunk,
    decode_causes,
    decode_data,
    decode_forward_tsn,
    decode_init,
    decode_reconfig,
    decode_sack,
    decode_shutdown,
    encode_abort,
    encode_cookie_ack,
    encode_cookie_echo,
    encode_error,
    encode_heartbeat,
    encode_reconfig,
    encode_shutdown,
    encode_shutdown_ack,
    encode_shutdown_complete,
    outgoing_reset_request,
    parse_tlvs,
    reconfig_response,
)
from nethernet.sctp.packet import (
    CHUNK_ABORT,
    CHUNK_COOKIE_ECHO,
    CHUNK_DATA,
    CHUNK_FORWARD_TSN,
    CHUNK_HEARTBEAT_ACK,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_RECONFIG,
    CHUNK_SACK,
    parse_packet,
)
from nethernet.wire import bytes_of, hex_decode, hex_encode, string_of
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true

# Packets recorded from pion/sctp v1.12.0. "A" is a default pion client (as
# pion/webrtc creates it); "B" is a pion client without I-DATA support.
comptime A_INIT = "1388138800000000638d94c90100001cac060e9700100000ffffffff2816389d8008000882c040c2"
comptime B_INIT = "1388138800000000e2679aec0100001aaa764be400100000ffffffff61f569f48008000682c00000"
comptime B_INIT_ACK = "13881388ac060e97625faa620200003eaa764be400100000ffffffff61f569f400070024c7e39cf3a08013b9570486a6f7346fb0741e3dcde810142782778b335df83cba8008000682c00000"
comptime A_INIT_ACK = "13881388aa764be490f40eb402000040ac060e9700100000ffffffff2816389d000700244cfcd0e495d6fb4f7afa4867f105a57ed9dc3fcfe7897a9d2d9e3c061ef267768008000882c040c2"
comptime A_COOKIE_ECHO = "13881388aa764be48f086ac50a000024c7e39cf3a08013b9570486a6f7346fb0741e3dcde810142782778b335df83cba"
comptime A_DCEP_OPEN = "13881388aa764be43969edb10003002f2816389d000000000000003203000100000000000013000052656c6961626c65446174614368616e6e656c00"
comptime A_UNORDERED = "13881388aa764be4e9e4d92400070074281638a200020001000000350910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7be"
comptime B_SACK = "13881388ac060e97f191e4dc03000010281638a4000fffec00000000"
comptime B_SACK_GAP = "138813886f0b57a2734f10cf0300001429705da5000ff8d00001000000020002"
comptime A_FORWARD_TSN = "13881388cf80eb67e1f9c901c0000008c1763264"
comptime A_RESET_REQUEST = "13881388aa764be4d04d463a82000016000d00122816389d00000000281638a400020000"
comptime B_RESET_RESPONSE = "13881388ac060e97472ab677820000100010000c2816389d00000001"
comptime A_ABORT = "13881388aa764be4a9a60bbd0600000b000c000762796500"


def _chunk(packet: List[UInt8], index: Int) raises -> List[UInt8]:
    """Returns chunk `index` of a packet: header, value and padding."""
    var view = parse_packet(Span(packet))
    var ref_ = view.chunks[index]
    var end = ref_.offset + ref_.length
    while end % 4 != 0 and end < len(packet):
        end += 1
    return List[UInt8](Span(packet)[ref_.offset - 4 : end])


def _value(packet: List[UInt8], index: Int) raises -> List[UInt8]:
    var view = parse_packet(Span(packet))
    var ref_ = view.chunks[index]
    return List[UInt8](Span(packet)[ref_.offset : ref_.offset + ref_.length])


def test_decode_pion_init() raises:
    var p = hex_decode(A_INIT)
    var v = _value(p, 0)
    var init = decode_init(Span(v))
    assert_equal(init.initiate_tag, 0xAC060E97)
    assert_equal(init.a_rwnd, 1048576)
    assert_equal(init.num_outbound_streams, 65535)
    assert_equal(init.num_inbound_streams, 65535)
    assert_equal(init.initial_tsn, 0x2816389D)
    assert_equal(len(init.cookie), 0)
    assert_false(init.forward_tsn_supported)
    assert_equal(hex_encode(Span(init.extensions)), "82c040c2")
    assert_true(init.supports_extension(0xC0))
    assert_true(init.supports_extension(0x82))
    assert_true(init.supports_extension(0x40))
    assert_false(init.supports_extension(0x0F))
    assert_equal(len(init.unrecognized), 0)


def test_init_round_trips_pion_bytes() raises:
    for text in [A_INIT, B_INIT]:
        var p = hex_decode(text)
        var v = _value(p, 0)
        var init = decode_init(Span(v))
        var out = List[UInt8]()
        init.encode(out, CHUNK_INIT)
        assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))


def test_init_ack_round_trips_pion_bytes() raises:
    for text in [A_INIT_ACK, B_INIT_ACK]:
        var p = hex_decode(text)
        var v = _value(p, 0)
        var ack = decode_init(Span(v))
        assert_equal(len(ack.cookie), 32)
        var out = List[UInt8]()
        ack.encode(out, CHUNK_INIT_ACK)
        assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))
    var p = hex_decode(B_INIT_ACK)
    var ack = decode_init(Span(_value(p, 0)))
    assert_equal(ack.initiate_tag, 0xAA764BE4)
    assert_equal(ack.initial_tsn, 0x61F569F4)
    assert_equal(
        hex_encode(Span(ack.cookie)),
        "c7e39cf3a08013b9570486a6f7346fb0741e3dcde810142782778b335df83cba",
    )
    assert_equal(hex_encode(Span(ack.extensions)), "82c0")


def test_init_with_forward_tsn_parameter() raises:
    var init = InitChunk(1, 1048576, 65535, 65535, 2)
    init.forward_tsn_supported = True
    init.extensions = [0x82, 0xC0]
    var out = List[UInt8]()
    init.encode(out, CHUNK_INIT)
    assert_equal(
        hex_encode(Span(out)),
        "0100001e0000000100100000ffffffff00000002c00000048008000682c00000",
    )
    var back = decode_init(Span(out)[4:30])
    assert_true(back.forward_tsn_supported)
    assert_equal(hex_encode(Span(back.extensions)), "82c0")


def test_init_unknown_parameters() raises:
    # 0x0030: stop, no report. 0x4031: stop and report. 0x8032: skip.
    # 0xC033: skip and report.
    var fixed = "0000000100100000ffffffff00000002"
    var skip = hex_decode(fixed + "80320005aa000000" + "c0000004")
    var a = decode_init(Span(skip))
    assert_true(a.forward_tsn_supported)
    assert_equal(len(a.unrecognized), 0)
    var skip_report = hex_decode(fixed + "c0330006aabb0000" + "c0000004")
    var b = decode_init(Span(skip_report))
    assert_true(b.forward_tsn_supported)
    assert_equal(hex_encode(Span(b.unrecognized)), "c0330006aabb0000")
    var stop = hex_decode(fixed + "00300004" + "c0000004")
    var c = decode_init(Span(stop))
    assert_false(c.forward_tsn_supported)
    assert_equal(len(c.unrecognized), 0)
    var stop_report = hex_decode(fixed + "40310004" + "c0000004")
    var d = decode_init(Span(stop_report))
    assert_false(d.forward_tsn_supported)
    assert_equal(hex_encode(Span(d.unrecognized)), "40310004")
    # Reported parameters come back inside Unrecognized Parameter (type 8).
    var out = List[UInt8]()
    b.encode(out, CHUNK_INIT_ACK)
    assert_equal(
        hex_encode(Span(out)),
        "020000220000000100100000ffffffff00000002c00000040008000ac0330006aabb0000",
    )
    # Address and adaptation-layer parameters are ignored silently.
    var ignored = hex_decode(fixed + "000500087f000001" + "c00600080000000a" + "c0000004")
    var e = decode_init(Span(ignored))
    assert_true(e.forward_tsn_supported)
    assert_equal(len(e.unrecognized), 0)


def test_init_rejects_truncation() raises:
    var p = hex_decode(A_INIT_ACK)
    var v = _value(p, 0)
    with assert_raises():
        _ = decode_init(Span(v)[0:15])
    with assert_raises():
        _ = decode_init(Span(v)[0:18])
    with assert_raises():
        _ = decode_init(Span(v)[0:30])
    var zero_len = hex_decode("0000000100100000ffffffff0000000200070000")
    with assert_raises():
        _ = decode_init(Span(zero_len))


def test_cookie_echo_matches_pion() raises:
    var ack_packet = hex_decode(B_INIT_ACK)
    var ack = decode_init(Span(_value(ack_packet, 0)))
    var out = List[UInt8]()
    encode_cookie_echo(out, Span(ack.cookie))
    var echo = hex_decode(A_COOKIE_ECHO)
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(echo, 0))))
    var ack_out = List[UInt8]()
    encode_cookie_ack(ack_out)
    assert_equal(hex_encode(Span(ack_out)), "0b000004")


def test_data_matches_pion() raises:
    var p = hex_decode(A_DCEP_OPEN)
    var view = parse_packet(Span(p))
    var d = decode_data(Span(_value(p, 0)), view.chunks[0].flags)
    assert_equal(d.tsn, 0x2816389D)
    assert_equal(d.stream_id, 0)
    assert_equal(d.ssn, 0)
    assert_equal(d.ppid, 50)
    assert_true(d.beginning())
    assert_true(d.ending())
    assert_false(d.unordered())
    assert_equal(len(d.payload), 31)
    assert_equal(
        hex_encode(Span(d.payload)),
        "03000100000000000013000052656c6961626c65446174614368616e6e656c",
    )
    var out = List[UInt8]()
    d.encode(out)
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))

    var u = hex_decode(A_UNORDERED)
    var uview = parse_packet(Span(u))
    var ud = decode_data(Span(_value(u, 0)), uview.chunks[0].flags)
    assert_true(ud.unordered())
    assert_equal(ud.stream_id, 2)
    assert_equal(ud.ppid, 53)
    assert_equal(len(ud.payload), 100)
    for i in range(100):
        assert_equal(ud.payload[i], UInt8((i * 7 + 9) & 0xFF))
    var uout = List[UInt8]()
    ud.encode(uout)
    assert_equal(hex_encode(Span(uout)), hex_encode(Span(_chunk(u, 0))))


def test_data_flags_and_truncation() raises:
    var payload = bytes_of("x")
    var d = DataChunk(
        7, 3, 9, 53, DATA_FLAG_BEGIN | DATA_FLAG_UNORDERED, Span(payload)
    )
    var out = List[UInt8]()
    d.encode(out)
    assert_equal(hex_encode(Span(out)), "00060011000000070003000900000035" + "78000000")
    var back = decode_data(Span(out)[4:17], out[1])
    assert_true(back.beginning())
    assert_false(back.ending())
    assert_true(back.unordered())
    assert_equal(back.ssn, 9)
    with assert_raises():
        _ = decode_data(Span(out)[4:15], 0)
    # An empty payload decodes; the association treats it as an error.
    var empty = decode_data(Span(out)[4:16], 3)
    assert_equal(len(empty.payload), 0)


def test_sack_matches_pion() raises:
    var p = hex_decode(B_SACK)
    var s = decode_sack(Span(_value(p, 0)))
    assert_equal(s.cumulative_tsn, 0x281638A4)
    assert_equal(s.a_rwnd, 0x000FFFEC)
    assert_equal(len(s.gaps), 0)
    assert_equal(len(s.duplicates), 0)
    var out = List[UInt8]()
    s.encode(out)
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))
    assert_equal(s.encoded_size(), 16)

    var g = hex_decode(B_SACK_GAP)
    var gs = decode_sack(Span(_value(g, 0)))
    assert_equal(gs.cumulative_tsn, 0x29705DA5)
    assert_equal(len(gs.gaps), 1)
    assert_equal(gs.gaps[0].start, 2)
    assert_equal(gs.gaps[0].end, 2)
    var gout = List[UInt8]()
    gs.encode(gout)
    assert_equal(hex_encode(Span(gout)), hex_encode(Span(_chunk(g, 0))))
    assert_equal(gs.encoded_size(), 20)


def test_sack_duplicates_and_truncation() raises:
    var s = SackChunk(100, 5000)
    s.gaps.append(GapBlock(2, 3))
    s.gaps.append(GapBlock(5, 5))
    s.duplicates.append(99)
    var out = List[UInt8]()
    s.encode(out)
    assert_equal(
        hex_encode(Span(out)),
        "0300001c0000006400001388000200010002000300050005" + "00000063",
    )
    var back = decode_sack(Span(out)[4:28])
    assert_equal(len(back.gaps), 2)
    assert_equal(back.gaps[1].start, 5)
    assert_equal(back.duplicates[0], 99)
    with assert_raises():
        _ = decode_sack(Span(out)[4:24])
    with assert_raises():
        _ = decode_sack(Span(out)[4:10])
    # Absurd counts with no blocks behind them.
    var absurd = hex_decode("0000006400001388ffffffff")
    with assert_raises():
        _ = decode_sack(Span(absurd))


def test_forward_tsn_matches_pion() raises:
    var p = hex_decode(A_FORWARD_TSN)
    var f = decode_forward_tsn(Span(_value(p, 0)))
    assert_equal(f.new_cumulative_tsn, 0xC1763264)
    assert_equal(len(f.stream_ids), 0)
    var out = List[UInt8]()
    f.encode(out)
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))

    var g = ForwardTsnChunk(10)
    g.stream_ids.append(1)
    g.ssns.append(7)
    g.stream_ids.append(4)
    g.ssns.append(65535)
    var gout = List[UInt8]()
    g.encode(gout)
    assert_equal(hex_encode(Span(gout)), "c00000100000000a000100070004ffff")
    var back = decode_forward_tsn(Span(gout)[4:16])
    assert_equal(len(back.stream_ids), 2)
    assert_equal(back.stream_ids[1], 4)
    assert_equal(back.ssns[1], 65535)
    with assert_raises():
        _ = decode_forward_tsn(Span(gout)[4:14])
    with assert_raises():
        _ = decode_forward_tsn(Span(gout)[4:6])


def test_reconfig_matches_pion() raises:
    var p = hex_decode(A_RESET_REQUEST)
    var params = decode_reconfig(Span(_value(p, 0)))
    assert_equal(len(params), 1)
    assert_true(params[0].kind == PARAM_OUTGOING_RESET)
    assert_equal(params[0].request_seq, 0x2816389D)
    assert_equal(params[0].response_seq, 0)
    assert_equal(params[0].last_tsn, 0x281638A4)
    assert_equal(len(params[0].streams), 1)
    assert_equal(params[0].streams[0], 2)
    var out = List[UInt8]()
    encode_reconfig(out, Span(params))
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))

    var r = hex_decode(B_RESET_RESPONSE)
    var rparams = decode_reconfig(Span(_value(r, 0)))
    assert_equal(len(rparams), 1)
    assert_true(rparams[0].kind == PARAM_RECONFIG_RESPONSE)
    assert_equal(rparams[0].request_seq, 0x2816389D)
    assert_true(rparams[0].result == RECONFIG_RESULT_PERFORMED)
    var rout = List[UInt8]()
    var built: List[ReconfigParam] = []
    built.append(reconfig_response(0x2816389D, RECONFIG_RESULT_PERFORMED))
    encode_reconfig(rout, Span(built))
    assert_equal(hex_encode(Span(rout)), hex_encode(Span(_chunk(r, 0))))


def test_reconfig_two_parameters_and_errors() raises:
    var streams: List[UInt16] = [1, 2, 3]
    var params: List[ReconfigParam] = []
    params.append(outgoing_reset_request(10, 20, 30, Span(streams)))
    params.append(reconfig_response(40, 6))
    var out = List[UInt8]()
    encode_reconfig(out, Span(params))
    # The first parameter is 22 bytes and is padded because another follows.
    assert_equal(
        hex_encode(Span(out)),
        "82000028000d00160000000a000000140000001e00010002000300000010000c0000002800000006",
    )
    var back = decode_reconfig(Span(out)[4 : len(out)])
    assert_equal(len(back), 2)
    assert_equal(len(back[0].streams), 3)
    assert_equal(back[1].result, 6)
    # Incoming reset request.
    var incoming = hex_decode("000e000c0000000500070009")
    var inc = decode_reconfig(Span(incoming))
    assert_true(inc[0].kind == PARAM_INCOMING_RESET)
    assert_equal(inc[0].request_seq, 5)
    assert_equal(inc[0].streams[1], 9)
    # Truncated request, odd stream list, unknown type.
    var short = hex_decode("000d000800000005")
    with assert_raises():
        _ = decode_reconfig(Span(short))
    var odd = hex_decode("000e0009000000050007")
    with assert_raises():
        _ = decode_reconfig(Span(odd))
    var unknown = hex_decode("00630004")
    var unk = decode_reconfig(Span(unknown))
    assert_equal(len(unk), 1)
    assert_equal(unk[0].kind, 0x63)


def test_abort_matches_pion() raises:
    var p = hex_decode(A_ABORT)
    var causes = decode_causes(Span(_value(p, 0)))
    assert_equal(len(causes), 1)
    assert_true(causes[0].code == CAUSE_USER_INITIATED_ABORT)
    assert_equal(string_of(Span(causes[0].info)), "bye")
    var out = List[UInt8]()
    encode_abort(out, False, Span(causes))
    assert_equal(hex_encode(Span(out)), hex_encode(Span(_chunk(p, 0))))
    var reflected = List[UInt8]()
    var none = List[ErrorCause]()
    encode_abort(reflected, True, Span(none))
    assert_equal(hex_encode(Span(reflected)), "06010004")
    # pion's Stop(): an ABORT with one empty user-initiated cause.
    var stop = hex_decode("000c0004")
    var sc = decode_causes(Span(stop))
    assert_equal(len(sc), 1)
    assert_equal(len(sc[0].info), 0)
    var bad = hex_decode("000c0009aabb")
    with assert_raises():
        _ = decode_causes(Span(bad))


def test_simple_chunks() raises:
    var out = List[UInt8]()
    encode_shutdown(out, 0x01020304)
    assert_equal(hex_encode(Span(out)), "0700000801020304")
    assert_equal(decode_shutdown(Span(out)[4:8]), 0x01020304)
    with assert_raises():
        _ = decode_shutdown(Span(out)[4:7])
    var ack = List[UInt8]()
    encode_shutdown_ack(ack)
    assert_equal(hex_encode(Span(ack)), "08000004")
    var done = List[UInt8]()
    encode_shutdown_complete(done, True)
    assert_equal(hex_encode(Span(done)), "0e010004")
    var hb = List[UInt8]()
    var info = hex_decode("00010007aabbcc")
    encode_heartbeat(hb, CHUNK_HEARTBEAT_ACK, Span(info))
    assert_equal(hex_encode(Span(hb)), "0500000b00010007aabbcc00")
    var err = List[UInt8]()
    var causes: List[ErrorCause] = []
    var unrec = hex_decode("40000004")
    causes.append(ErrorCause(6, Span(unrec)))
    encode_error(err, Span(causes))
    assert_equal(hex_encode(Span(err)), "0900000c0006000840000004")


def test_parse_tlvs_bounds() raises:
    var two = hex_decode("00010005aa0000000002000400")
    with assert_raises():
        _ = parse_tlvs(Span(two), 0)
    var ok = hex_decode("00010005aa00000000020004")
    var items = parse_tlvs(Span(ok), 0)
    assert_equal(len(items), 2)
    assert_equal(items[0].length, 1)
    assert_equal(items[1].offset, 12)
    with assert_raises():
        _ = parse_tlvs(Span(ok), 13)
    var past = hex_decode("0001ffff")
    with assert_raises():
        _ = parse_tlvs(Span(past), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
