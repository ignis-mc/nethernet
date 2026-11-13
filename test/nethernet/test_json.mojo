from nethernet.crypto.base64 import (
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
)
from nethernet.json import json_parse_int, json_parse_object, json_parse_string, json_quote
from nethernet.wire import bytes_of, hex_decode, hex_encode, string_of
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def test_base64_rfc4648_vectors() raises:
    var cases: List[String] = ["", "f", "fo", "foo", "foob", "fooba", "foobar"]
    var expected: List[String] = ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"]
    for i in range(len(cases)):
        var data = bytes_of(cases[i])
        assert_equal(base64_encode(Span(data)), expected[i])
        var back = base64_decode(expected[i])
        assert_equal(string_of(Span(back)), cases[i])
    # Unpadded input is accepted too.
    var unpadded = base64_decode("Zm9vYg")
    assert_equal(string_of(Span(unpadded)), "foob")


def test_base64url() raises:
    var data = hex_decode("fbff3e")
    assert_equal(base64_encode(Span(data)), "+/8+")
    assert_equal(base64url_encode(Span(data)), "-_8-")
    var two = hex_decode("fbff")
    assert_equal(base64url_encode(Span(two)), "-_8")
    var back = base64url_decode("-_8")
    assert_equal(hex_encode(Span(back)), "fbff")
    var padded = base64url_decode("-_8=")
    assert_equal(hex_encode(Span(padded)), "fbff")
    with assert_raises(contains="invalid character"):
        _ = base64url_decode("+/8+")
    with assert_raises(contains="invalid character"):
        _ = base64_decode("-_8-")


def test_base64_rejects_malformed() raises:
    with assert_raises(contains="invalid length"):
        _ = base64_decode("Z")
    with assert_raises(contains="invalid length"):
        _ = base64_decode("Zm9vY")
    with assert_raises(contains="invalid length"):
        _ = base64_decode("Zg===")
    with assert_raises(contains="invalid character"):
        _ = base64_decode("Zm9$")
    with assert_raises(contains="trailing bits"):
        _ = base64_decode("Zh")
    for n in range(0, 70):
        var data = List[UInt8]()
        for i in range(n):
            data.append(UInt8((i * 37 + n) & 0xFF))
        var a = base64_decode(base64_encode(Span(data)))
        var b = base64url_decode(base64url_encode(Span(data)))
        assert_equal(hex_encode(Span(a)), hex_encode(Span(data)))
        assert_equal(hex_encode(Span(b)), hex_encode(Span(data)))


def test_quote() raises:
    assert_equal(json_quote("sha-256"), "\"sha-256\"")
    assert_equal(json_quote("AB:CD"), "\"AB:CD\"")
    assert_equal(json_quote("a\"b\\c\n\t"), "\"a\\\"b\\\\c\\n\\t\"")
    var control = List[UInt8]()
    control.append(0x01)
    assert_equal(json_quote(string_of(Span(control))), "\"\\u0001\"")


def test_parse_object() raises:
    var obj = json_parse_object(
        " {\"assertion\": \"{\\\"token\\\":\\\"a.b.c\\\"}\", \"idp\": {\"domain\": \"self\", \"protocol\":\"default\"}, \"n\": 17, \"t\": true, \"arr\": [1, {\"x\": \"}\"}, \"]\"] } "
    )
    assert_equal(len(obj), 5)
    assert_equal(json_parse_string(obj["assertion"]), "{\"token\":\"a.b.c\"}")
    var idp = json_parse_object(obj["idp"])
    assert_equal(json_parse_string(idp["domain"]), "self")
    assert_equal(json_parse_string(idp["protocol"]), "default")
    assert_equal(json_parse_int(obj["n"]), 17)
    assert_equal(obj["t"], "true")
    assert_equal(obj["arr"], "[1, {\"x\": \"}\"}, \"]\"]")
    var inner = json_parse_object(json_parse_string(obj["assertion"]))
    assert_equal(json_parse_string(inner["token"]), "a.b.c")
    var empty = json_parse_object("{}")
    assert_equal(len(empty), 0)


def test_parse_object_rejects_malformed() raises:
    for bad in [
        "", "[]", "{", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "{\"a\":1 \"b\":2}",
        "{\"a\":1} x", "{a:1}", "{\"a\":\"unterminated}", "{\"a\":[1,2}",
    ]:
        with assert_raises():
            _ = json_parse_object(bad)
    var deep = String()
    for _ in range(40):
        deep += "[".copy()
    with assert_raises():
        _ = json_parse_object("{\"a\":" + deep + "}")


def test_parse_string_escapes() raises:
    assert_equal(json_parse_string("\"plain\""), "plain")
    assert_equal(json_parse_string("\"a\\\"b\\\\c\\/d\\n\\t\""), "a\"b\\c/d\n\t")
    assert_equal(json_parse_string("\"\\u0041\\u00e9\\u20ac\""), "Aé€")
    assert_equal(json_parse_string("\"\\ud83d\\udd25\""), "🔥")
    for bad in ["plain", "\"", "\"a", "\"\\x\"", "\"\\u12\"", "\"\\ud83d\"", "\"\\udd25\"", "\"a\"b\""]:
        with assert_raises():
            _ = json_parse_string(bad)


def test_parse_int() raises:
    assert_equal(json_parse_int("0"), 0)
    assert_equal(json_parse_int(" 1762995600 "), 1762995600)
    assert_equal(json_parse_int("-42"), -42)
    assert_equal(json_parse_int("1762995600.75"), 1762995600)
    for bad in ["", "abc", "1e9", "1.", "--1", "99999999999999999999999"]:
        with assert_raises():
            _ = json_parse_int(bad)
    assert_true(True)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
