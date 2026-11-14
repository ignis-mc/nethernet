"""Send side of an association: queueing, fragmentation and loss recovery.

`Sender` owns the user messages waiting to be sent and the DATA chunks in
flight. It implements the transmission rules of RFC 9260 sections 6 and 7
(receiver window, congestion window with slow start and congestion
avoidance, T3-rtx with exponential backoff, fast retransmit) and the
limited-retransmission policy of RFC 3758 with FORWARD-TSN.

On top of fast retransmit it detects losses the way RACK-TLP does for TCP
(RFC 8985), as pion's SCTP does: a chunk is lost once a chunk transmitted
after it is acknowledged, and a tail that goes unacknowledged for about two
round trips is probed by resending its last chunk, again at doubling
intervals while no acknowledgement arrives. Request/response traffic
ends every message in such a tail, where waiting for three missing reports
or for T3-rtx (at least a second, doubling) stalls the connection.
"""

from std.collections import Deque

from .chunk import (
    DATA_CHUNK_OVERHEAD,
    DATA_FLAG_BEGIN,
    DATA_FLAG_END,
    DATA_FLAG_IMMEDIATE,
    DATA_FLAG_UNORDERED,
    ForwardTsnChunk,
    SackChunk,
    encode_data,
)
from .packet import SCTP_HEADER_SIZE, pad4
from .serial import ssn_lt, tsn_ge, tsn_gt, tsn_le, tsn_lt
from .timer import RtoEstimator, Timer

comptime _FAST_RETRANSMIT_THRESHOLD = 3
comptime _PROBE_SLACK_MS = 10
"""Added to two smoothed round trips for the tail loss probe timeout."""


struct _OutMessage(Copyable):
    var stream_id: UInt16
    var ppid: UInt32
    var unordered: Bool
    var max_retransmits: Int
    var payload: List[UInt8]
    var offset: Int
    var ssn: UInt16
    var is_reset: Bool

    def __init__(
        out self,
        stream_id: UInt16,
        ppid: UInt32,
        unordered: Bool,
        max_retransmits: Int,
        payload: Span[UInt8, _],
        is_reset: Bool,
    ):
        self.stream_id = stream_id
        self.ppid = ppid
        self.unordered = unordered
        self.max_retransmits = max_retransmits
        self.payload = List[UInt8](payload)
        self.offset = 0
        self.ssn = 0
        self.is_reset = is_reset


struct _OutChunk(Copyable):
    var tsn: UInt32
    var stream_id: UInt16
    var ssn: UInt16
    var ppid: UInt32
    var flags: UInt8
    var payload: List[UInt8]
    var max_retransmits: Int
    var sent_count: Int
    var sent_at: Int
    var acked: Bool
    var abandoned: Bool
    var retransmit: Bool
    var fast: Bool
    var fast_done: Bool
    var miss_count: Int
    var xmit_seq: Int
    """Order of the latest transmission among all transmissions."""

    def __init__(
        out self,
        tsn: UInt32,
        stream_id: UInt16,
        ssn: UInt16,
        ppid: UInt32,
        flags: UInt8,
        payload: Span[UInt8, _],
        max_retransmits: Int,
        now_ms: Int,
    ):
        self.tsn = tsn
        self.stream_id = stream_id
        self.ssn = ssn
        self.ppid = ppid
        self.flags = flags
        self.payload = List[UInt8](payload)
        self.max_retransmits = max_retransmits
        self.sent_count = 1
        self.sent_at = now_ms
        self.acked = False
        self.abandoned = False
        self.retransmit = False
        self.fast = False
        self.fast_done = False
        self.miss_count = 0
        self.xmit_seq = 0


def initial_cwnd(mtu: Int) -> Int:
    """Computes the initial congestion window of RFC 9260 section 7.2.1."""
    var floor = 2 * mtu
    if floor < 4380:
        floor = 4380
    if 4 * mtu < floor:
        return 4 * mtu
    return floor


def fragment_size_for_mtu(mtu: Int) -> Int:
    """Computes the largest DATA payload per chunk for an MTU.

    The size leaves room for the common header, the DATA chunk header and a
    SACK without gap blocks, and is a multiple of 4 so that full fragments
    need no padding.
    """
    var size = (mtu - SCTP_HEADER_SIZE - DATA_CHUNK_OVERHEAD - 16) & ~3
    if size < 4:
        size = 4
    return size


struct Sender(Movable):
    """Outbound user messages, DATA chunks in flight and loss recovery."""

    var rto: RtoEstimator
    """The retransmission timeout estimator."""
    var t3: Timer
    """The T3-rtx timer; armed whenever a TSN awaits its cumulative ack."""
    var probe: Timer
    """The loss detection timer: tail loss probe and RACK reorder wait."""
    var progress: Bool
    """Whether the last SACK acknowledged anything new."""
    var retransmits: Int
    """DATA chunks retransmitted."""
    var fast_retransmits: Int
    """DATA chunks marked for fast retransmission."""
    var t3_expiries: Int
    """Expiries of the T3-rtx timer."""
    var abandoned_chunks: Int
    """DATA chunks abandoned under a retransmission limit."""
    var data_chunks_out: Int
    """DATA chunks sent for the first time."""
    var forward_tsns_out: Int
    """FORWARD-TSN chunks written."""
    var loss_probes: Int
    """Tail loss probes sent."""
    var rack_losses: Int
    """DATA chunks found lost because a later transmission was acked."""

    var _mtu: Int
    var _fragment_size: Int
    var _next_tsn: UInt32
    var _cum_ack: UInt32
    var _adv_ack: UInt32
    var _pending: Deque[_OutMessage]
    var _pending_bytes: Int
    var _inflight: Deque[_OutChunk]
    var _inflight_bytes: Int
    var _outstanding: Int
    var _marked: Int
    var _next_ssn: Dict[UInt16, UInt16]
    var _cwnd: Int
    var _ssthresh: Int
    var _partial_acked: Int
    var _fast_recovery: Bool
    var _recovery_exit: UInt32
    var _cwnd_limited: Bool
    var _peer_rwnd: Int
    var _forward_tsn_ok: Bool
    var _forward_needed: Bool
    var _blocked: Dict[UInt16, Bool]
    var _reset_ready: List[UInt16]
    var _xmit_seq: Int
    var _rack_seq: Int
    var _probes: Int
    """Tail loss probes sent since the last acknowledgement."""

    def __init__(
        out self,
        initial_tsn: UInt32,
        mtu: Int,
        rto_initial_ms: Int,
        rto_min_ms: Int,
        rto_max_ms: Int,
    ):
        """Creates a sender with nothing queued."""
        self.rto = RtoEstimator(rto_initial_ms, rto_min_ms, rto_max_ms)
        self.t3 = Timer()
        self.probe = Timer()
        self.progress = False
        self.retransmits = 0
        self.fast_retransmits = 0
        self.t3_expiries = 0
        self.abandoned_chunks = 0
        self.data_chunks_out = 0
        self.forward_tsns_out = 0
        self.loss_probes = 0
        self.rack_losses = 0
        self._mtu = mtu
        self._fragment_size = fragment_size_for_mtu(mtu)
        self._next_tsn = initial_tsn
        self._cum_ack = initial_tsn - 1
        self._adv_ack = initial_tsn - 1
        self._pending = Deque[_OutMessage]()
        self._pending_bytes = 0
        self._inflight = Deque[_OutChunk]()
        self._inflight_bytes = 0
        self._outstanding = 0
        self._marked = 0
        self._next_ssn = Dict[UInt16, UInt16]()
        self._cwnd = initial_cwnd(mtu)
        self._ssthresh = 1 << 30
        self._partial_acked = 0
        self._fast_recovery = False
        self._recovery_exit = initial_tsn - 1
        self._cwnd_limited = False
        self._peer_rwnd = 0
        self._forward_tsn_ok = False
        self._forward_needed = False
        self._blocked = Dict[UInt16, Bool]()
        self._reset_ready = List[UInt16]()
        self._xmit_seq = 0
        self._rack_seq = 0
        self._probes = 0

    def set_peer(mut self, a_rwnd: UInt32, forward_tsn: Bool):
        """Records what the peer announced in its INIT or INIT ACK."""
        self._peer_rwnd = Int(a_rwnd)
        self._ssthresh = Int(a_rwnd)
        self._forward_tsn_ok = forward_tsn

    def fragment_size(self) -> Int:
        """Returns the DATA payload size messages are fragmented at."""
        return self._fragment_size

    def cwnd(self) -> Int:
        """Returns the congestion window."""
        return self._cwnd

    def peer_rwnd(self) -> Int:
        """Returns the peer's receive window as last advertised."""
        return self._peer_rwnd

    def next_tsn(self) -> UInt32:
        """Returns the TSN the next new DATA chunk will get."""
        return self._next_tsn

    def cumulative_ack(self) -> UInt32:
        """Returns the highest TSN the peer acknowledged cumulatively."""
        return self._cum_ack

    def buffered_amount(self) -> Int:
        """Counts user bytes queued or in flight and not yet acknowledged."""
        return self._pending_bytes + self._inflight_bytes

    def is_drained(self) -> Bool:
        """Checks whether every queued message was sent and acknowledged."""
        return len(self._pending) == 0 and len(self._inflight) == 0

    def inflight_count(self) -> Int:
        """Counts the DATA chunks awaiting their cumulative ack."""
        return len(self._inflight)

    def queue_message(
        mut self,
        stream_id: UInt16,
        ppid: UInt32,
        payload: Span[UInt8, _],
        unordered: Bool,
        max_retransmits: Int,
    ):
        """Queues one user message behind everything queued before it."""
        self._pending.append(
            _OutMessage(
                stream_id, ppid, unordered, max_retransmits, payload, False
            )
        )
        self._pending_bytes += len(payload)

    def queue_reset(mut self, stream_id: UInt16):
        """Queues a stream reset behind the messages queued so far.

        The stream becomes ready for an Outgoing SSN Reset Request once all
        earlier messages have been assigned TSNs; see `take_reset_ready()`.
        """
        var empty = List[UInt8]()
        self._pending.append(
            _OutMessage(stream_id, 0, False, -1, Span(empty), True)
        )

    def take_reset_ready(mut self) -> List[UInt16]:
        """Takes the streams whose queued reset reached the head of the queue.

        Sending on these streams is held back until `finish_reset()`.
        """
        self._absorb_reset_markers()
        var ready = self._reset_ready.copy()
        self._reset_ready.clear()
        return ready^

    def finish_reset(mut self, stream_ids: Span[UInt16, _], performed: Bool):
        """Completes a reset request and lets the streams send again."""
        for s in stream_ids:
            try:
                if s in self._blocked:
                    _ = self._blocked.pop(s)
                if performed and s in self._next_ssn:
                    _ = self._next_ssn.pop(s)
            except:
                pass

    def _absorb_reset_markers(mut self):
        while len(self._pending) > 0 and self._pending[0].is_reset:
            var stream_id = self._pending[0].stream_id
            try:
                _ = self._pending.popleft()
            except:
                return
            self._reset_ready.append(stream_id)
            self._blocked[stream_id] = True

    def _cwnd_allows(mut self, size: Int) -> Bool:
        # RFC 9260 6.1 B, applied strictly: the flight may not exceed cwnd,
        # except that a single chunk may always be in flight.
        if self._outstanding > 0 and self._outstanding + size > self._cwnd:
            self._cwnd_limited = True
            return False
        return True

    def _should_abandon(self, i: Int) -> Bool:
        if not self._forward_tsn_ok:
            return False
        var limit = self._inflight[i].max_retransmits
        return limit >= 0 and self._inflight[i].sent_count - 1 >= limit

    def _abandon_message(mut self, i: Int):
        var n = len(self._inflight)
        var first = i
        while (
            first > 0 and (self._inflight[first].flags & DATA_FLAG_BEGIN) == 0
        ):
            first -= 1
        var last = i
        while (
            last < n - 1 and (self._inflight[last].flags & DATA_FLAG_END) == 0
        ):
            last += 1
        for j in range(first, last + 1):
            if self._inflight[j].abandoned:
                continue
            var size = len(self._inflight[j].payload)
            self._inflight[j].abandoned = True
            if self._inflight[j].retransmit:
                self._inflight[j].retransmit = False
                self._inflight[j].fast = False
                self._marked -= 1
            elif not self._inflight[j].acked:
                self._outstanding -= size
            self._inflight_bytes -= size
            self.abandoned_chunks += 1
        if (self._inflight[last].flags & DATA_FLAG_END) == 0:
            # The rest of the message was never fragmented: drop it too.
            if (
                len(self._pending) > 0
                and self._pending[0].offset > 0
                and not self._pending[0].is_reset
            ):
                self._pending_bytes -= (
                    len(self._pending[0].payload) - self._pending[0].offset
                )
                try:
                    _ = self._pending.popleft()
                except:
                    pass
                # The unsent rest becomes one abandoned TSN that is never
                # transmitted. The peer cannot move its cumulative TSN past
                # it by itself, so it has to process a FORWARD-TSN, which
                # is what releases the partial message and its stream.
                var empty = List[UInt8]()
                var tail = _OutChunk(
                    self._next_tsn,
                    self._inflight[last].stream_id,
                    self._inflight[last].ssn,
                    self._inflight[last].ppid,
                    (self._inflight[last].flags & DATA_FLAG_UNORDERED)
                    | DATA_FLAG_END,
                    Span(empty),
                    self._inflight[last].max_retransmits,
                    0,
                )
                tail.abandoned = True
                tail.sent_count = 0
                self._inflight.append(tail^)
                self._next_tsn += 1

    def _mark_for_retransmit(mut self, i: Int, fast: Bool):
        # Precondition: not abandoned, not already marked.
        if self._should_abandon(i):
            self._abandon_message(i)
            return
        if self._inflight[i].acked:
            self._inflight[i].acked = False
        else:
            self._outstanding -= len(self._inflight[i].payload)
        self._inflight[i].retransmit = True
        self._inflight[i].fast = fast
        if fast:
            self._inflight[i].fast_done = True
            self.fast_retransmits += 1
        self._marked += 1

    def _enter_fast_recovery(mut self):
        if self._fast_recovery:
            return
        self._ssthresh = self._cwnd // 2
        if self._ssthresh < 4 * self._mtu:
            self._ssthresh = 4 * self._mtu
        self._cwnd = self._ssthresh
        self._partial_acked = 0
        self._fast_recovery = True
        self._recovery_exit = self._next_tsn - 1

    def _update_forward_point(mut self):
        if not self._forward_tsn_ok:
            return
        var moved = False
        for i in range(len(self._inflight)):
            var tsn = self._inflight[i].tsn
            if tsn_le(tsn, self._adv_ack):
                continue
            if tsn != self._adv_ack + 1 or not self._inflight[i].abandoned:
                break
            self._adv_ack = tsn
            moved = True
        if moved:
            self._forward_needed = True

    def on_sack(mut self, sack: SackChunk, now_ms: Int) raises -> Bool:
        """Processes a SACK from the peer."""
        self.progress = False
        if tsn_lt(sack.cumulative_tsn, self._cum_ack):
            return True
        if tsn_gt(sack.cumulative_tsn, self._next_tsn - 1):
            return False
        var acked_bytes = 0
        var rtt = -1
        var newly_acked = False
        var newest_xmit = 0
        while len(self._inflight) > 0 and tsn_le(
            self._inflight[0].tsn, sack.cumulative_tsn
        ):
            var c = self._inflight.popleft()
            var size = len(c.payload)
            newly_acked = True
            if c.abandoned:
                continue
            # Only a chunk sent once says unambiguously which transmission
            # arrived.
            if not c.acked and c.sent_count == 1 and c.xmit_seq > newest_xmit:
                newest_xmit = c.xmit_seq
            self._inflight_bytes -= size
            if c.retransmit:
                self._marked -= 1
            elif not c.acked:
                self._outstanding -= size
                acked_bytes += size
                if c.sent_count == 1:
                    rtt = now_ms - c.sent_at
        var advanced = sack.cumulative_tsn != self._cum_ack
        self._cum_ack = sack.cumulative_tsn
        if tsn_lt(self._adv_ack, self._cum_ack):
            self._adv_ack = self._cum_ack

        var n = len(self._inflight)
        var highest_new = self._cum_ack
        var have_highest = False
        var prev_end = 0
        for g in sack.gaps:
            var s = Int(g.start)
            var e = Int(g.end)
            if s < 1 or e < s or s <= prev_end or s > n:
                break
            if e > n:
                e = n
            prev_end = e
            for off in range(s, e + 1):
                var i = off - 1
                if self._inflight[i].acked:
                    continue
                self._inflight[i].acked = True
                newly_acked = True
                highest_new = self._inflight[i].tsn
                have_highest = True
                if self._inflight[i].abandoned:
                    continue
                if (
                    self._inflight[i].sent_count == 1
                    and self._inflight[i].xmit_seq > newest_xmit
                ):
                    newest_xmit = self._inflight[i].xmit_seq
                if self._inflight[i].retransmit:
                    self._inflight[i].retransmit = False
                    self._inflight[i].fast = False
                    self._marked -= 1
                else:
                    self._outstanding -= len(self._inflight[i].payload)
                    if self._inflight[i].sent_count == 1:
                        rtt = now_ms - self._inflight[i].sent_at

        if have_highest:
            # Chunks below the highest newly acked TSN were passed over.
            for i in range(n):
                if not tsn_lt(self._inflight[i].tsn, highest_new):
                    break
                if (
                    self._inflight[i].acked
                    or self._inflight[i].abandoned
                    or self._inflight[i].retransmit
                ):
                    continue
                self._inflight[i].miss_count += 1
                if (
                    self._inflight[i].miss_count == _FAST_RETRANSMIT_THRESHOLD
                    and not self._inflight[i].fast_done
                ):
                    self._mark_for_retransmit(i, True)
                    self._enter_fast_recovery()

        if newest_xmit > self._rack_seq:
            self._rack_seq = newest_xmit
        _ = self._rack_detect(now_ms)
        if newly_acked:
            self._probes = 0

        if acked_bytes > 0 and not self._fast_recovery:
            if self._cwnd <= self._ssthresh:
                if self._cwnd_limited:
                    var step = acked_bytes
                    if step > self._mtu:
                        step = self._mtu
                    self._cwnd += step
            else:
                self._partial_acked += acked_bytes
                if self._partial_acked >= self._cwnd and self._cwnd_limited:
                    self._partial_acked -= self._cwnd
                    self._cwnd += self._mtu
        if acked_bytes > 0:
            # "Fully utilized" is judged anew for each acknowledged flight.
            self._cwnd_limited = False
        if self._fast_recovery and tsn_ge(self._cum_ack, self._recovery_exit):
            self._fast_recovery = False

        if rtt >= 0:
            self.rto.observe(rtt)
        self._peer_rwnd = Int(sack.a_rwnd)
        if len(self._inflight) == 0:
            self.t3.stop()
        elif advanced:
            self.t3.start(now_ms + self.rto.rto())
        self._update_forward_point()
        self.progress = newly_acked or advanced
        self._arm_probe(now_ms)
        return True

    def _rack_detect(mut self, now_ms: Int) -> Int:
        # A chunk transmitted before the newest acknowledged transmission is
        # lost once it is older than the reordering window (RFC 8985 6.2).
        var reorder = self.rto.srtt() // 4
        var found = 0
        var n = len(self._inflight)
        for i in range(n):
            if self._inflight[i].xmit_seq >= self._rack_seq:
                continue
            if (
                self._inflight[i].acked
                or self._inflight[i].abandoned
                or self._inflight[i].retransmit
            ):
                continue
            if now_ms - self._inflight[i].sent_at < reorder:
                continue
            self._mark_for_retransmit(i, True)
            self.rack_losses += 1
            found += 1
        if found > 0:
            self._enter_fast_recovery()
        return found

    def _arm_probe(mut self, now_ms: Int):
        if self._outstanding <= 0:
            self.probe.stop()
            return
        # Each unanswered probe doubles the wait, so a silent peer gets a
        # handful of probes before T3-rtx, not a stream of them.
        var shift = self._probes if self._probes < 10 else 10
        var deadline = now_ms + (
            (2 * self.rto.srtt() + _PROBE_SLACK_MS) << shift
        )
        var reorder = self.rto.srtt() // 4
        if reorder > 0:
            # Wake when a chunk RACK already suspects leaves the window.
            for i in range(len(self._inflight)):
                if (
                    self._inflight[i].xmit_seq >= self._rack_seq
                    or self._inflight[i].acked
                    or self._inflight[i].abandoned
                    or self._inflight[i].retransmit
                ):
                    continue
                var at = self._inflight[i].sent_at + reorder
                if deadline < 0 or at < deadline:
                    deadline = at
        if self.t3.armed and deadline >= self.t3.deadline:
            self.probe.stop()
            return
        self.probe.start(deadline)

    def on_probe_expired(mut self, now_ms: Int):
        """Handles an expiry of the loss detection timer.

        Marks the chunks RACK now judges lost or, if there are none, marks
        the highest unacknowledged chunk for one retransmission that
        bypasses the congestion window. Neither backs off the RTO; the next
        probe waits twice as long unless an acknowledgement arrives first.
        """
        self.probe.stop()
        if self._rack_detect(now_ms) > 0:
            return
        var i = len(self._inflight) - 1
        while i >= 0:
            if not (
                self._inflight[i].acked
                or self._inflight[i].abandoned
                or self._inflight[i].retransmit
                or self._should_abandon(i)
            ):
                break
            i -= 1
        if i < 0:
            return
        self._outstanding -= len(self._inflight[i].payload)
        self._inflight[i].retransmit = True
        self._inflight[i].fast = True
        self._marked += 1
        self._probes += 1
        self.loss_probes += 1

    def on_t3_expired(mut self, now_ms: Int):
        """Handles an expiry of the T3-rtx timer.

        The congestion window collapses to one MTU, the timeout doubles and
        every chunk still unacknowledged is marked for retransmission or,
        if its retransmission limit is used up, abandoned.
        """
        self.t3_expiries += 1
        self.probe.stop()
        self._probes = 0
        self._ssthresh = self._cwnd // 2
        if self._ssthresh < 4 * self._mtu:
            self._ssthresh = 4 * self._mtu
        self._cwnd = self._mtu
        self._partial_acked = 0
        self._fast_recovery = False
        self.rto.backoff()
        for i in range(len(self._inflight)):
            if self._inflight[i].abandoned or self._inflight[i].retransmit:
                continue
            # Gap-acked chunks are marked too: the peer may have reneged.
            self._mark_for_retransmit(i, False)
        self._update_forward_point()
        if tsn_gt(self._adv_ack, self._cum_ack):
            self._forward_needed = True
        if len(self._inflight) > 0:
            self.t3.start(now_ms + self.rto.rto())
        else:
            self.t3.stop()

    def _write_forward_tsn(mut self, mut out: List[UInt8], limit: Int) -> Bool:
        var chunk = ForwardTsnChunk(self._adv_ack)
        var max_entries = (limit - len(out) - 8) // 4
        for i in range(len(self._inflight)):
            if tsn_gt(self._inflight[i].tsn, self._adv_ack):
                break
            if (self._inflight[i].flags & DATA_FLAG_UNORDERED) != 0:
                continue
            var stream_id = self._inflight[i].stream_id
            var ssn = self._inflight[i].ssn
            var found = False
            for j in range(len(chunk.stream_ids)):
                if chunk.stream_ids[j] == stream_id:
                    found = True
                    if ssn_lt(chunk.ssns[j], ssn):
                        chunk.ssns[j] = ssn
                    break
            if not found and len(chunk.stream_ids) < max_entries:
                chunk.stream_ids.append(stream_id)
                chunk.ssns.append(ssn)
        if len(out) + 8 + 4 * len(chunk.stream_ids) > limit:
            return False
        chunk.encode(out)
        self.forward_tsns_out += 1
        return True

    def fill(
        mut self, mut out: List[UInt8], limit: Int, now_ms: Int
    ) raises -> Int:
        """Appends as many chunks to a packet as the windows allow.

        Writes a FORWARD-TSN if one is due, then retransmissions, then new
        DATA fragments, each only while the packet stays within `limit`.
        """
        var added = self._fill(out, limit, now_ms)
        if added > 0:
            self._arm_probe(now_ms)
        return added

    def _fill(
        mut self, mut out: List[UInt8], limit: Int, now_ms: Int
    ) raises -> Int:
        var added = 0
        if self._forward_needed and tsn_gt(self._adv_ack, self._cum_ack):
            if not self._write_forward_tsn(out, limit):
                return added
            self._forward_needed = False
            added += 1
            if not self.t3.armed:
                self.t3.start(now_ms + self.rto.rto())
        else:
            self._forward_needed = False

        if self._marked > 0:
            for i in range(len(self._inflight)):
                if self._marked == 0:
                    break
                if not self._inflight[i].retransmit:
                    continue
                var size = DATA_CHUNK_OVERHEAD + pad4(
                    len(self._inflight[i].payload)
                )
                if len(out) + size > limit:
                    return added
                if not self._inflight[i].fast and not self._cwnd_allows(
                    len(self._inflight[i].payload)
                ):
                    return added
                encode_data(
                    out,
                    self._inflight[i].tsn,
                    self._inflight[i].stream_id,
                    self._inflight[i].ssn,
                    self._inflight[i].ppid,
                    self._inflight[i].flags,
                    Span(self._inflight[i].payload),
                )
                self._inflight[i].retransmit = False
                self._inflight[i].fast = False
                self._inflight[i].sent_count += 1
                self._inflight[i].sent_at = now_ms
                self._xmit_seq += 1
                self._inflight[i].xmit_seq = self._xmit_seq
                self._outstanding += len(self._inflight[i].payload)
                self._marked -= 1
                self.retransmits += 1
                added += 1
                if not self.t3.armed:
                    self.t3.start(now_ms + self.rto.rto())

        while len(self._pending) > 0:
            if self._pending[0].is_reset:
                self._absorb_reset_markers()
                continue
            var stream_id = self._pending[0].stream_id
            if stream_id in self._blocked:
                break
            var offset = self._pending[0].offset
            var remaining = len(self._pending[0].payload) - offset
            var frag = remaining
            if frag > self._fragment_size:
                frag = self._fragment_size
            if len(out) + DATA_CHUNK_OVERHEAD + pad4(frag) > limit:
                break
            if not self._cwnd_allows(frag):
                break
            if frag > self._peer_rwnd - self._outstanding and (
                self._outstanding > 0
            ):
                # With nothing in flight one chunk goes out regardless, as
                # the zero window probe.
                break
            var unordered = self._pending[0].unordered
            var flags = UInt8(0)
            if unordered:
                flags |= DATA_FLAG_UNORDERED
            if offset == 0:
                flags |= DATA_FLAG_BEGIN
                var ssn = self._next_ssn.get(stream_id).or_else(0)
                self._pending[0].ssn = ssn
                if not unordered:
                    self._next_ssn[stream_id] = ssn + 1
            if frag == remaining:
                flags |= DATA_FLAG_END
                if len(self._pending) == 1:
                    # The last chunk for now: ask for a SACK at once (RFC
                    # 7053) rather than after the peer's delayed-ack timer,
                    # so the tail loss probe can stay short.
                    flags |= DATA_FLAG_IMMEDIATE
            var chunk = _OutChunk(
                self._next_tsn,
                stream_id,
                self._pending[0].ssn,
                self._pending[0].ppid,
                flags,
                Span(self._pending[0].payload)[offset : offset + frag],
                self._pending[0].max_retransmits,
                now_ms,
            )
            self._xmit_seq += 1
            chunk.xmit_seq = self._xmit_seq
            encode_data(
                out,
                chunk.tsn,
                chunk.stream_id,
                chunk.ssn,
                chunk.ppid,
                chunk.flags,
                Span(chunk.payload),
            )
            self._inflight.append(chunk^)
            self._next_tsn += 1
            self._outstanding += frag
            self._inflight_bytes += frag
            self._pending_bytes -= frag
            self.data_chunks_out += 1
            added += 1
            if frag == remaining:
                _ = self._pending.popleft()
            else:
                self._pending[0].offset = offset + frag
            if not self.t3.armed:
                self.t3.start(now_ms + self.rto.rto())
        return added

    def has_sendable(self) -> Bool:
        """Checks whether `fill()` might have something to write."""
        return (
            len(self._pending) > 0 or self._marked > 0 or self._forward_needed
        )

    def clear(mut self):
        """Drops everything queued or in flight and stops the timer."""
        self._pending.clear()
        self._inflight.clear()
        self._pending_bytes = 0
        self._inflight_bytes = 0
        self._outstanding = 0
        self._marked = 0
        self._forward_needed = False
        self.t3.stop()
        self.probe.stop()
        self._probes = 0
