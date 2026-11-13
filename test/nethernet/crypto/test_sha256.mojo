from nethernet.crypto.sha256 import Sha256, sha256
from nethernet.wire import bytes_of, hex_encode
from std.testing import TestSuite, assert_equal


def _hex(text: StringSpan) -> String:
    var data = bytes_of(text)
    var digest = sha256(Span(data))
    return hex_encode(Span(digest))


def test_empty() raises:
    assert_equal(
        _hex(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_abc() raises:
    assert_equal(
        _hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )


def test_two_blocks() raises:
    assert_equal(
        _hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )


def test_million_a() raises:
    var h = Sha256()
    var chunk = List[UInt8](length=1000, fill=0x61)
    for _ in range(1000):
        h.update(Span(chunk))
    var digest = h.finish()
    assert_equal(
        hex_encode(Span(digest)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


def test_streaming_matches_one_shot() raises:
    var data = List[UInt8]()
    for i in range(300):
        data.append(UInt8(i % 251))
    var expected = sha256(Span(data))
    for split in [0, 1, 55, 56, 63, 64, 65, 127, 128, 299, 300]:
        var h = Sha256()
        h.update(Span(data)[0:split])
        h.update(Span(data)[split:300])
        var got = h.finish()
        assert_equal(hex_encode(Span(got)), hex_encode(Span(expected)))


def test_discovery_key() raises:
    # go-nethernet discovery key: SHA-256 of 0xdeadbeef as a little-endian u64.
    var seed: List[UInt8] = [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]
    var digest = sha256(Span(seed))
    assert_equal(
        hex_encode(Span(digest)),
        "eed4c37861936c6ebb91ab9d195c1b489de46362d3bb8e30d8aab08bf217e6f3",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
