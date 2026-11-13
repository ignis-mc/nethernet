from nethernet.sctp.timer import RtoEstimator, Timer
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def test_timer() raises:
    var t = Timer()
    assert_false(t.armed)
    assert_false(t.expired(1000000))
    t.start(500)
    assert_true(t.armed)
    assert_equal(t.deadline, 500)
    assert_false(t.expired(499))
    assert_true(t.expired(500))
    assert_true(t.expired(501))
    t.start(900)
    assert_false(t.expired(600))
    t.stop()
    assert_false(t.armed)
    assert_false(t.expired(2000))


def test_rto_before_any_measurement() raises:
    var r = RtoEstimator(1000, 1000, 60000)
    assert_equal(r.rto(), 1000)
    assert_equal(r.srtt(), 0)
    var other = RtoEstimator(3000, 1000, 60000)
    assert_equal(other.rto(), 3000)


def test_rto_first_and_later_measurements() raises:
    var r = RtoEstimator(1000, 1, 60000)
    # RFC 9260 6.3.1 C2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 * RTTVAR.
    r.observe(400)
    assert_equal(r.srtt(), 400)
    assert_equal(r.rto(), 1200)
    # C3 with R' = 400: RTTVAR = 3/4 * 200 = 150, SRTT stays 400.
    r.observe(400)
    assert_equal(r.srtt(), 400)
    assert_equal(r.rto(), 1000)
    # C3 with R' = 800: RTTVAR = 3/4 * 150 + 1/4 * 400 = 212.5,
    # SRTT = 7/8 * 400 + 1/8 * 800 = 450.
    r.observe(800)
    assert_equal(r.srtt(), 450)
    assert_true(r.rto() >= 1298 and r.rto() <= 1302)
    # A long run of equal samples converges on them.
    for _ in range(200):
        r.observe(100)
    assert_true(r.srtt() >= 99 and r.srtt() <= 101)
    assert_true(r.rto() <= 110)


def test_rto_clamping() raises:
    var r = RtoEstimator(1000, 1000, 60000)
    r.observe(10)
    assert_equal(r.rto(), 1000)
    r.observe(500000)
    assert_equal(r.rto(), 60000)
    r.observe(-5)
    assert_true(r.rto() >= 1000)


def test_rto_backoff() raises:
    var r = RtoEstimator(1000, 1000, 60000)
    var expected: List[Int] = [2000, 4000, 8000, 16000, 32000, 60000, 60000]
    for i in range(len(expected)):
        r.backoff()
        assert_equal(r.rto(), expected[i])
    # A new measurement ends the backoff.
    r.observe(100)
    assert_equal(r.rto(), 1000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
