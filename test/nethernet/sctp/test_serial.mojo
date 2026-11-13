from nethernet.sctp.serial import ssn_le, ssn_lt, tsn_ge, tsn_gt, tsn_le, tsn_lt
from std.testing import TestSuite, assert_false, assert_true


def test_tsn_ordering() raises:
    assert_true(tsn_lt(1, 2))
    assert_false(tsn_lt(2, 1))
    assert_false(tsn_lt(5, 5))
    assert_true(tsn_le(5, 5))
    assert_true(tsn_le(4, 5))
    assert_false(tsn_le(6, 5))
    assert_true(tsn_gt(6, 5))
    assert_false(tsn_gt(5, 5))
    assert_true(tsn_ge(5, 5))
    assert_true(tsn_ge(6, 5))
    assert_false(tsn_ge(4, 5))


def test_tsn_wraparound() raises:
    assert_true(tsn_lt(0xFFFFFFFF, 0))
    assert_true(tsn_lt(0xFFFFFFF0, 5))
    assert_true(tsn_gt(0, 0xFFFFFFFF))
    assert_false(tsn_lt(0, 0xFFFFFFFF))
    assert_true(tsn_le(0xFFFFFFFF, 0))
    assert_true(tsn_ge(3, 0xFFFFFFFE))
    # Just under half the number space apart is still "ahead".
    assert_true(tsn_lt(0, 0x7FFFFFFF))
    assert_true(tsn_lt(100, 100 + 0x7FFFFFFF))
    # Half the space or more apart flips the order.
    assert_false(tsn_lt(0, 0x80000000))
    assert_false(tsn_le(0, 0x80000000))
    assert_true(tsn_lt(0x80000001, 0))


def test_ssn_ordering_and_wraparound() raises:
    assert_true(ssn_lt(1, 2))
    assert_false(ssn_lt(2, 2))
    assert_true(ssn_le(2, 2))
    assert_false(ssn_lt(3, 2))
    assert_true(ssn_lt(65535, 0))
    assert_true(ssn_le(65535, 0))
    assert_false(ssn_lt(0, 65535))
    assert_true(ssn_lt(65000, 100))
    assert_true(ssn_lt(0, 0x7FFF))
    assert_false(ssn_lt(0, 0x8000))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
