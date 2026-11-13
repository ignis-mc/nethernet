from nethernet.sctp.packet import parse_packet
from nethernet.sctp.reconfig import (
    PARAM_INCOMING_RESET,
    PARAM_OUTGOING_RESET,
    PARAM_RECONFIG_RESPONSE,
    RECONFIG_RESULT_PERFORMED,
    ReconfigParam,
    decode_reconfig,
    encode_reconfig,
    outgoing_reset_request,
    reconfig_response,
)
from nethernet.wire import hex_decode, hex_encode
from std.testing import TestSuite, assert_equal, assert_raises, assert_true

# Packets recorded from pion/sctp v1.12.0 (two associations over a pipe).
comptime A_RESET_REQUEST = (
    "13881388aa764be4d04d463a82000016000d00122816389d00000000281638a400020000"
)
comptime B_RESET_RESPONSE = (
    "13881388ac060e97472ab677820000100010000c2816389d00000001"
)


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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
