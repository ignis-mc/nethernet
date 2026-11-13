from nethernet.wire import (
    Reader,
    bytes_equal,
    bytes_of,
    get_u16,
    get_u32,
    hex_decode,
    hex_encode,
    put_bytes,
    put_u16,
    put_u16_le,
    put_u24,
    put_u32,
    put_u32_le,
    put_u48,
    put_u64,
    put_u64_le,
    put_u8,
    put_zeros,
    set_u16,
    set_u24,
    set_u32,
    string_of,
)
from std.testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true


def test_put_and_read_big_endian() raises:
    var out = List[UInt8]()
    put_u8(out, 0x01)
    put_u16(out, 0x0203)
    put_u24(out, 0x040506)
    put_u32(out, 0x0708090A)
    put_u48(out, 0x0B0C0D0E0F10)
    put_u64(out, 0x1112131415161718)
    assert_equal(hex_encode(Span(out)), "0102030405060708090a0b0c0d0e0f101112131415161718")
    var r = Reader(Span(out))
    assert_equal(r.u8(), 0x01)
    assert_equal(r.u16(), 0x0203)
    assert_equal(r.u24(), 0x040506)
    assert_equal(r.u32(), 0x0708090A)
    assert_equal(r.u48(), 0x0B0C0D0E0F10)
    assert_equal(r.u64(), 0x1112131415161718)
    assert_true(r.at_end())


def test_little_endian() raises:
    var out = List[UInt8]()
    put_u16_le(out, 0x0102)
    put_u32_le(out, 0x03040506)
    put_u64_le(out, 0x0708090A0B0C0D0E)
    assert_equal(hex_encode(Span(out)), "0201060504030e0d0c0b0a090807")
    var r = Reader(Span(out))
    assert_equal(r.u16_le(), 0x0102)
    assert_equal(r.u32_le(), 0x03040506)
    assert_equal(r.u64_le(), 0x0708090A0B0C0D0E)


def test_reader_bounds() raises:
    var data: List[UInt8] = [1, 2, 3]
    var r = Reader(Span(data))
    assert_equal(r.remaining(), 3)
    with assert_raises(contains="short read"):
        _ = r.u32()
    assert_equal(r.u16(), 0x0102)
    with assert_raises(contains="short read"):
        _ = r.bytes(2)
    with assert_raises(contains="short read"):
        _ = r.bytes(-1)
    var rest = r.rest()
    assert_equal(len(rest), 1)
    assert_equal(rest[0], 3)
    assert_true(r.at_end())
    with assert_raises(contains="short read"):
        _ = r.u8()


def test_bytes_and_skip() raises:
    var data: List[UInt8] = [1, 2, 3, 4, 5]
    var r = Reader(Span(data))
    r.skip(1)
    var two = r.bytes(2)
    assert_equal(two[0], 2)
    assert_equal(two[1], 3)
    assert_equal(r.remaining(), 2)


def test_set_and_get() raises:
    var out = List[UInt8]()
    put_zeros(out, 10)
    set_u16(out, 0, 0xABCD)
    set_u24(out, 2, 0x123456)
    set_u32(out, 5, 0xDEADBEEF)
    assert_equal(hex_encode(Span(out)), "abcd123456deadbeef00")
    assert_equal(get_u16(Span(out), 0), 0xABCD)
    assert_equal(get_u32(Span(out), 5), 0xDEADBEEF)


def test_hex_round_trip() raises:
    var data = hex_decode("00ff10Ab")
    assert_equal(len(data), 4)
    assert_equal(data[1], 0xFF)
    assert_equal(data[3], 0xAB)
    assert_equal(hex_encode(Span(data)), "00ff10ab")
    with assert_raises(contains="odd length"):
        _ = hex_decode("abc")
    with assert_raises(contains="invalid hex"):
        _ = hex_decode("zz")


def test_bytes_equal_and_strings() raises:
    var a = bytes_of("abc")
    var b = bytes_of("abc")
    var c = bytes_of("abd")
    assert_true(bytes_equal(Span(a), Span(b)))
    assert_false(bytes_equal(Span(a), Span(c)))
    assert_false(bytes_equal(Span(a), Span(c)[0:2]))
    var out = List[UInt8]()
    put_bytes(out, Span(a))
    assert_equal(string_of(Span(out)), "abc")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
