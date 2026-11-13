"""A deterministic in-memory network for two SCTP associations.

Time is simulated. Every packet either side emits is put on a queue with a
delivery time, and may be lost, duplicated or delayed further (which reorders
it) according to a seeded generator, so that every run of a test sees the same
sequence of events.
"""

from nethernet.sctp.association import Association
from nethernet.sctp.config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SctpConfig,
    SctpEvent,
)


struct Rng(Copyable):
    """xorshift64*: small, fast and reproducible."""

    var state: UInt64

    def __init__(out self, seed: UInt64):
        self.state = seed * 0x9E3779B97F4A7C15 + 0x1234567
        if self.state == 0:
            self.state = 1

    def next(mut self) -> UInt64:
        var x = self.state
        x ^= x >> 12
        x ^= x << 25
        x ^= x >> 27
        self.state = x
        return x * 0x2545F4914F6CDD1D

    def below(mut self, n: Int) -> Int:
        if n <= 0:
            return 0
        return Int((self.next() >> 33) % UInt64(n))

    def chance(mut self, permille: Int) -> Bool:
        return self.below(1000) < permille

    def bytes(mut self, n: Int) -> List[UInt8]:
        var out = List[UInt8](capacity=n)
        for _ in range(n):
            out.append(UInt8(self.next() >> 56))
        return out^


struct Flight(Copyable):
    """One packet on the wire."""

    var deliver_at: Int
    var order: Int
    var to_b: Bool
    var data: List[UInt8]

    def __init__(
        out self, deliver_at: Int, order: Int, to_b: Bool, data: Span[UInt8, _]
    ):
        self.deliver_at = deliver_at
        self.order = order
        self.to_b = to_b
        self.data = List[UInt8](data)


def make_config(seed: UInt64) -> SctpConfig:
    """Builds a configuration with reproducible "random" values."""
    var rng = Rng(seed)
    var tag = UInt32(rng.next() >> 32)
    if tag == 0:
        tag = 1
    var tsn = UInt32(rng.next() >> 32)
    var secret = rng.bytes(32)
    return SctpConfig(tag, tsn, Span(secret))


def pattern(n: Int, seed: Int) -> List[UInt8]:
    """Builds `n` bytes that differ per position and per seed."""
    var out = List[UInt8](capacity=n)
    var x = UInt32(seed) * 2654435761 + 12345
    for i in range(n):
        x = x * 1664525 + 1013904223
        out.append(UInt8((x >> 24) ^ UInt32(i & 0xFF)))
    return out^


struct Net(Movable):
    """Two associations joined by a lossy link, with a simulated clock."""

    var a: Association
    var b: Association
    var now: Int
    var rng: Rng
    var wire: List[Flight]
    var order: Int
    var loss_ab: Int
    """Loss from A to B in permille."""
    var loss_ba: Int
    """Loss from B to A in permille."""
    var duplicate: Int
    """Duplication in permille, both directions."""
    var reorder: Int
    """Permille of packets that get an extra random delay."""
    var delay_ms: Int
    """One-way delay of every packet."""
    var a_events: List[SctpEvent]
    var b_events: List[SctpEvent]
    var packets_ab: Int
    var packets_ba: Int
    var lost: Int
    var max_packet: Int
    var hold_b_events: Bool
    """When set, B's events stay queued inside B (a slow reader)."""
    var capture: Bool
    """When set, every packet A emits is kept in `captured`."""
    var captured: List[List[UInt8]]
    var captured_ba: List[List[UInt8]]
    """With `capture` set, every packet B emits."""

    def __init__(
        out self, var a: Association, var b: Association, seed: UInt64
    ):
        self.a = a^
        self.b = b^
        self.now = 0
        self.rng = Rng(seed)
        self.wire = List[Flight]()
        self.order = 0
        self.loss_ab = 0
        self.loss_ba = 0
        self.duplicate = 0
        self.reorder = 0
        self.delay_ms = 5
        self.a_events = List[SctpEvent]()
        self.b_events = List[SctpEvent]()
        self.packets_ab = 0
        self.packets_ba = 0
        self.lost = 0
        self.max_packet = 0
        self.hold_b_events = False
        self.capture = False
        self.captured = List[List[UInt8]]()
        self.captured_ba = List[List[UInt8]]()

    def _enqueue(mut self, to_b: Bool, data: Span[UInt8, _]):
        if len(data) > self.max_packet:
            self.max_packet = len(data)
        if to_b:
            self.packets_ab += 1
            if self.capture:
                self.captured.append(List[UInt8](data))
        else:
            self.packets_ba += 1
            if self.capture:
                self.captured_ba.append(List[UInt8](data))
        var loss = self.loss_ab if to_b else self.loss_ba
        if self.rng.chance(loss):
            self.lost += 1
            return
        var copies = 1
        if self.rng.chance(self.duplicate):
            copies = 2
        for _ in range(copies):
            var at = self.now + self.delay_ms
            if self.rng.chance(self.reorder):
                at += 1 + self.rng.below(3 * self.delay_ms + 20)
            self.wire.append(Flight(at, self.order, to_b, data))
            self.order += 1

    def flush(mut self):
        """Moves pending output of both sides onto the wire, drains events."""
        while True:
            var p = self.a.poll_transmit(self.now)
            if not p:
                break
            self._enqueue(True, Span(p.value()))
        while True:
            var p = self.b.poll_transmit(self.now)
            if not p:
                break
            self._enqueue(False, Span(p.value()))
        while True:
            var e = self.a.poll_event()
            if not e:
                break
            self.a_events.append(e.value().copy())
        if not self.hold_b_events:
            while True:
                var e = self.b.poll_event()
                if not e:
                    break
                self.b_events.append(e.value().copy())

    def _next_time(self) -> Int:
        var best = -1
        for i in range(len(self.wire)):
            if best < 0 or self.wire[i].deliver_at < best:
                best = self.wire[i].deliver_at
        var ta = self.a.next_timeout()
        if ta:
            if best < 0 or ta.value() < best:
                best = ta.value()
        var tb = self.b.next_timeout()
        if tb:
            if best < 0 or tb.value() < best:
                best = tb.value()
        return best

    def step(mut self, limit: Int) -> Bool:
        """Advances to the next packet delivery or timer.

        Returns `False` when nothing is left to do before `limit`.
        """
        self.flush()
        var t = self._next_time()
        if t < 0 or t > limit:
            return False
        if t > self.now:
            self.now = t
        # Deliver every packet that is due, oldest first.
        while True:
            var pick = -1
            for i in range(len(self.wire)):
                if self.wire[i].deliver_at > self.now:
                    continue
                if pick < 0 or (
                    self.wire[i].deliver_at < self.wire[pick].deliver_at
                    or (
                        self.wire[i].deliver_at == self.wire[pick].deliver_at
                        and self.wire[i].order < self.wire[pick].order
                    )
                ):
                    pick = i
            if pick < 0:
                break
            var f = self.wire.pop(pick)
            if f.to_b:
                self.b.handle_packet(Span(f.data), self.now)
            else:
                self.a.handle_packet(Span(f.data), self.now)
        self.a.handle_timeout(self.now)
        self.b.handle_timeout(self.now)
        self.flush()
        return True

    def run(mut self, duration_ms: Int):
        """Runs until the network is idle or `duration_ms` has passed."""
        var limit = self.now + duration_ms
        while self.step(limit):
            pass
        self.flush()

    def run_for(mut self, duration_ms: Int):
        """Runs for exactly `duration_ms`, idle or not."""
        var limit = self.now + duration_ms
        while self.step(limit):
            pass
        self.now = limit
        self.a.handle_timeout(self.now)
        self.b.handle_timeout(self.now)
        self.flush()


def new_net(seed: UInt64) -> Net:
    """Two fresh associations with default configuration."""
    return Net(
        Association(make_config(seed * 2 + 1)),
        Association(make_config(seed * 2 + 2)),
        seed,
    )


def count_kind(events: List[SctpEvent], kind: Int) -> Int:
    var n = 0
    for i in range(len(events)):
        if events[i].kind == kind:
            n += 1
    return n


def messages(events: List[SctpEvent]) -> List[SctpEvent]:
    """The MESSAGE events, in order."""
    var out = List[SctpEvent]()
    for i in range(len(events)):
        if events[i].kind == SCTP_EVENT_MESSAGE:
            out.append(events[i].copy())
    return out^


def same_bytes(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True
