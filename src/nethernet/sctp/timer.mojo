"""Retransmission timing: a one-shot deadline and the RTO estimator."""


struct Timer(ImplicitlyCopyable):
    """A one-shot timer expressed as an absolute deadline in milliseconds."""

    var armed: Bool
    """Whether the timer is running."""
    var deadline: Int
    """The absolute time at which the timer fires; meaningful when armed."""

    def __init__(out self):
        """Creates a stopped timer."""
        self.armed = False
        self.deadline = 0

    def start(mut self, deadline: Int):
        """Starts or restarts the timer.

        Args:
            deadline: The absolute time in milliseconds at which to fire.
        """
        self.armed = True
        self.deadline = deadline

    def stop(mut self):
        """Stops the timer."""
        self.armed = False

    def expired(self, now_ms: Int) -> Bool:
        """Checks whether the timer is due.

        Args:
            now_ms: The current time in milliseconds.

        Returns:
            `True` if the timer is running and its deadline has passed.
        """
        return self.armed and self.deadline <= now_ms


struct RtoEstimator(ImplicitlyCopyable):
    """The retransmission timeout calculation of RFC 9260 section 6.3.1.

    Times are integer milliseconds. The smoothed round-trip time is kept
    scaled by 8 and its variance by 4, as in Jacobson's algorithm.
    """

    var _srtt8: Int
    var _rttvar4: Int
    var _has_sample: Bool
    var _rto: Int
    var _min: Int
    var _max: Int

    def __init__(out self, initial_ms: Int, min_ms: Int, max_ms: Int):
        """Creates an estimator with no measurement yet.

        Args:
            initial_ms: The timeout to use before the first measurement.
            min_ms: The smallest timeout.
            max_ms: The largest timeout.
        """
        self._srtt8 = 0
        self._rttvar4 = 0
        self._has_sample = False
        self._rto = initial_ms
        self._min = min_ms
        self._max = max_ms

    def rto(self) -> Int:
        """Returns the current retransmission timeout.

        Returns:
            The timeout in milliseconds, including any backoff.
        """
        return self._rto

    def srtt(self) -> Int:
        """Returns the smoothed round-trip time.

        Returns:
            The estimate in milliseconds, or 0 before the first measurement.
        """
        return self._srtt8 >> 3

    def observe(mut self, rtt_ms: Int):
        """Feeds one round-trip measurement and recomputes the timeout.

        Per Karn's rule the caller must only measure chunks that were sent
        exactly once.

        Args:
            rtt_ms: The measured round-trip time in milliseconds.
        """
        var r = rtt_ms
        if r < 0:
            r = 0
        if not self._has_sample:
            self._has_sample = True
            self._srtt8 = r * 8
            self._rttvar4 = r * 2
        else:
            var delta = r - (self._srtt8 >> 3)
            self._srtt8 += delta
            if delta < 0:
                delta = -delta
            self._rttvar4 += delta - (self._rttvar4 >> 2)
        self._rto = self._clamp((self._srtt8 >> 3) + self._rttvar4)

    def backoff(mut self):
        """Doubles the timeout after a retransmission timer expiry."""
        self._rto = self._clamp(self._rto * 2)

    def _clamp(self, value: Int) -> Int:
        if value < self._min:
            return self._min
        if value > self._max:
            return self._max
        return value
