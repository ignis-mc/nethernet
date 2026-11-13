"""Receive side of an association: TSN tracking and message reassembly.

`TsnTracker` records which TSNs arrived, which yields the cumulative TSN, the
gap ack blocks of a SACK and duplicate detection. `Reassembly` stores DATA
fragments until a whole user message is present and, for ordered streams,
until every earlier message of the stream was delivered or skipped.
"""

from .chunk import DataChunk, GapBlock
from .serial import ssn_le, ssn_lt, tsn_le

comptime TSN_NEW = 0
"""`TsnTracker.classify()`: the TSN was not seen before."""
comptime TSN_DUPLICATE = 1
"""`TsnTracker.classify()`: the TSN was already received."""
comptime TSN_OUT_OF_WINDOW = 2
"""`TsnTracker.classify()`: the TSN is too far ahead to be tracked."""

comptime REASSEMBLY_OK = 0
"""`Reassembly.insert()`: the fragment was stored or delivered."""
comptime REASSEMBLY_DISCARDED = 1
"""`Reassembly.insert()`: the fragment can never complete a message."""
comptime REASSEMBLY_TOO_LARGE = 2
"""`Reassembly.insert()`: a message exceeds the size limit."""

comptime CHUNK_BUFFER_OVERHEAD = 64
"""Bytes charged per stored fragment on top of its payload."""


struct TsnTracker(Movable):
    """The set of received TSNs above the cumulative TSN."""

    var _cum: UInt32
    var _highest: UInt32
    var _ring: List[UInt8]
    var _mask: UInt32
    var _count: Int

    def __init__(out self, cumulative_tsn: UInt32, window: Int):
        """Creates a tracker with nothing received above `cumulative_tsn`.

        Args:
            cumulative_tsn: The peer's initial TSN minus one.
            window: How many TSNs past the cumulative TSN can be tracked;
                rounded up to a power of two between 64 and 32768.
        """
        var size = 64
        while size < window and size < 32768:
            size *= 2
        self._cum = cumulative_tsn
        self._highest = cumulative_tsn
        self._ring = List[UInt8](length=size, fill=0)
        self._mask = UInt32(size - 1)
        self._count = 0

    def cumulative_tsn(self) -> UInt32:
        """Returns the highest TSN received with no gap before it.

        Returns:
            The cumulative TSN.
        """
        return self._cum

    def has_gaps(self) -> Bool:
        """Checks whether any TSN above the cumulative TSN was received.

        Returns:
            `True` if a SACK would carry gap ack blocks.
        """
        return self._count > 0

    def classify(self, tsn: UInt32) -> Int:
        """Decides what to do with an arriving TSN.

        Args:
            tsn: The TSN of a DATA chunk.

        Returns:
            `TSN_NEW`, `TSN_DUPLICATE` or `TSN_OUT_OF_WINDOW`.
        """
        if tsn_le(tsn, self._cum):
            return TSN_DUPLICATE
        if tsn - self._cum > self._mask:
            return TSN_OUT_OF_WINDOW
        if self._ring[Int(tsn & self._mask)] != 0:
            return TSN_DUPLICATE
        return TSN_NEW

    def mark(mut self, tsn: UInt32):
        """Records a TSN that `classify()` reported as new.

        Args:
            tsn: The TSN to record.
        """
        if self.classify(tsn) != TSN_NEW:
            return
        if tsn == self._cum + 1:
            self._cum = tsn
            self._advance()
        else:
            self._ring[Int(tsn & self._mask)] = 1
            self._count += 1
            if tsn_le(self._highest, tsn):
                self._highest = tsn

    def forward(mut self, new_cumulative_tsn: UInt32):
        """Moves the cumulative TSN forward, as FORWARD-TSN asks.

        Does nothing if the new value is not ahead of the current one.

        Args:
            new_cumulative_tsn: The TSN to skip to.
        """
        if tsn_le(new_cumulative_tsn, self._cum):
            return
        var distance = new_cumulative_tsn - self._cum
        if self._count > 0:
            if distance > self._mask:
                for i in range(len(self._ring)):
                    self._ring[i] = 0
                self._count = 0
            else:
                var t = self._cum + 1
                for _ in range(Int(distance)):
                    var slot = Int(t & self._mask)
                    if self._ring[slot] != 0:
                        self._ring[slot] = 0
                        self._count -= 1
                    t += 1
        self._cum = new_cumulative_tsn
        self._advance()

    def _advance(mut self):
        while self._count > 0:
            var slot = Int((self._cum + 1) & self._mask)
            if self._ring[slot] == 0:
                break
            self._ring[slot] = 0
            self._count -= 1
            self._cum += 1
        if tsn_le(self._highest, self._cum):
            self._highest = self._cum

    def gap_blocks(self, max_blocks: Int) -> List[GapBlock]:
        """Lists the received runs above the cumulative TSN.

        Args:
            max_blocks: The largest number of blocks to return.

        Returns:
            Gap ack blocks in ascending order, lowest runs first.
        """
        var blocks = List[GapBlock]()
        if self._count == 0:
            return blocks^
        var span = Int(self._highest - self._cum)
        if span > Int(self._mask):
            span = Int(self._mask)
        var run_start = 0
        var seen = 0
        for off in range(1, span + 2):
            var present = False
            if off <= span:
                present = (
                    self._ring[Int((self._cum + UInt32(off)) & self._mask)] != 0
                )
            if present:
                seen += 1
                if run_start == 0:
                    run_start = off
            elif run_start != 0:
                if len(blocks) >= max_blocks:
                    break
                blocks.append(GapBlock(UInt16(run_start), UInt16(off - 1)))
                run_start = 0
                if seen >= self._count:
                    break
        return blocks^


struct SctpMessage(Copyable):
    """A reassembled user message."""

    var stream_id: UInt16
    """The stream the message arrived on."""
    var ppid: UInt32
    """The payload protocol identifier."""
    var unordered: Bool
    """Whether the message was sent unordered."""
    var payload: List[UInt8]
    """The user data."""

    def __init__(
        out self,
        stream_id: UInt16,
        ppid: UInt32,
        unordered: Bool,
        var payload: List[UInt8],
    ):
        """Creates a message.

        Args:
            stream_id: The stream the message arrived on.
            ppid: The payload protocol identifier.
            unordered: Whether the message was sent unordered.
            payload: The user data.
        """
        self.stream_id = stream_id
        self.ppid = ppid
        self.unordered = unordered
        self.payload = payload^


def _ready_key(stream_id: UInt16, ssn: UInt16) -> UInt32:
    return (UInt32(stream_id) << 16) | UInt32(ssn)


struct Reassembly(Movable):
    """Fragment storage and in-order delivery for all inbound streams.

    Fragments of one message carry consecutive TSNs, so stored fragments are
    grouped into runs of adjacent TSNs that can belong to the same message. A
    run that starts with a B fragment and ends with an E fragment is a
    complete message.
    """

    var _chunks: Dict[UInt32, DataChunk]
    var _run_end: Dict[UInt32, UInt32]
    var _run_start: Dict[UInt32, UInt32]
    var _run_bytes: Dict[UInt32, Int]
    var _next_ssn: Dict[UInt16, UInt16]
    var _ready: Dict[UInt32, UInt32]
    var _cost: Int
    var _max_message_size: Int

    def __init__(out self, max_message_size: Int):
        """Creates an empty reassembly buffer.

        Args:
            max_message_size: The largest message to reassemble, in bytes.
        """
        self._chunks = Dict[UInt32, DataChunk]()
        self._run_end = Dict[UInt32, UInt32]()
        self._run_start = Dict[UInt32, UInt32]()
        self._run_bytes = Dict[UInt32, Int]()
        self._next_ssn = Dict[UInt16, UInt16]()
        self._ready = Dict[UInt32, UInt32]()
        self._cost = 0
        self._max_message_size = max_message_size

    def cost(self) -> Int:
        """Returns the buffer space taken by stored fragments.

        Returns:
            Payload bytes plus `CHUNK_BUFFER_OVERHEAD` per fragment.
        """
        return self._cost

    def fragment_count(self) -> Int:
        """Counts the stored fragments.

        Returns:
            The number of DATA chunks held.
        """
        return len(self._chunks)

    def _joins(self, left: DataChunk, right: DataChunk) -> Bool:
        if left.ending() or right.beginning():
            return False
        if left.stream_id != right.stream_id:
            return False
        if left.unordered() != right.unordered():
            return False
        return left.unordered() or left.ssn == right.ssn

    def _take_run(mut self, start: UInt32, keep: Bool) raises -> SctpMessage:
        var end = self._run_end.pop(start)
        _ = self._run_start.pop(end)
        var size = self._run_bytes.pop(start)
        var payload = List[UInt8](capacity=size if keep else 0)
        var stream_id = UInt16(0)
        var ppid = UInt32(0)
        var unordered = False
        var t = start
        while True:
            var c = self._chunks.pop(t)
            self._cost -= len(c.payload) + CHUNK_BUFFER_OVERHEAD
            if t == start:
                stream_id = c.stream_id
                ppid = c.ppid
                unordered = c.unordered()
            if keep:
                payload.extend(Span(c.payload))
            if t == end:
                break
            t += 1
        return SctpMessage(stream_id, ppid, unordered, payload^)

    def _drop_orphan(
        mut self, start: UInt32, mut out: List[SctpMessage]
    ) raises:
        # Drops a partial message that can never be completed. If its
        # ordered stream was waiting for exactly this message, the stream
        # moves on, as it would after a FORWARD-TSN.
        var stream_id = self._chunks[start].stream_id
        var ordered = not self._chunks[start].unordered()
        var ssn = self._chunks[start].ssn
        _ = self._take_run(start, False)
        if ordered:
            var next = self._next_ssn.get(stream_id).or_else(0)
            if ssn == next:
                self._next_ssn[stream_id] = next + 1
                self._drain_ready(stream_id, out)

    def _drain_ready(
        mut self, stream_id: UInt16, mut out: List[SctpMessage]
    ) raises:
        var next = self._next_ssn.get(stream_id).or_else(0)
        while len(self._ready) > 0:
            var key = _ready_key(stream_id, next)
            if key not in self._ready:
                break
            var start = self._ready.pop(key)
            out.append(self._take_run(start, True))
            next += 1
        self._next_ssn[stream_id] = next

    def insert(
        mut self,
        var chunk: DataChunk,
        cumulative_tsn: UInt32,
        mut out: List[SctpMessage],
    ) raises -> Int:
        """Adds a new DATA chunk and collects any messages it completes.

        Args:
            chunk: A chunk whose TSN was not received before.
            cumulative_tsn: The cumulative TSN after recording the chunk.
            out: The list that deliverable messages are appended to.

        Returns:
            `REASSEMBLY_OK`, `REASSEMBLY_DISCARDED` when the chunk belongs
            to a message that was skipped or already delivered, or
            `REASSEMBLY_TOO_LARGE` when a message exceeds the size limit.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        var tsn = chunk.tsn
        var stream_id = chunk.stream_id
        var size = len(chunk.payload)
        if size > self._max_message_size:
            return REASSEMBLY_TOO_LARGE

        # Look at the stored neighbours. Fragments of one message carry
        # consecutive TSNs, so a neighbour that does not continue into this
        # chunk shows which partial messages can never be completed.
        var join_left = False
        var join_right = False
        var left_blocks = False
        var right_blocks = False
        if len(self._run_end) > 0:
            if (tsn - 1) in self._run_start:
                join_left = self._joins(self._chunks[tsn - 1], chunk)
                if not join_left:
                    left_blocks = True
                    if not self._chunks[tsn - 1].ending():
                        self._drop_orphan(self._run_start[tsn - 1], out)
            if (tsn + 1) in self._run_end:
                join_right = self._joins(chunk, self._chunks[tsn + 1])
                if not join_right:
                    right_blocks = True
                    if not self._chunks[tsn + 1].beginning():
                        self._drop_orphan(tsn + 1, out)
        if not chunk.beginning() and not join_left:
            if left_blocks or tsn_le(tsn - 1, cumulative_tsn):
                # The preceding fragment was skipped or belonged to another
                # message, so this one can never be completed.
                return REASSEMBLY_DISCARDED
        if not chunk.ending() and right_blocks:
            if join_left:
                self._drop_orphan(self._run_start[tsn - 1], out)
            return REASSEMBLY_DISCARDED

        if chunk.beginning() and chunk.ending():
            if chunk.unordered():
                var whole = List[UInt8]()
                swap(whole, chunk.payload)
                out.append(SctpMessage(stream_id, chunk.ppid, True, whole^))
                return REASSEMBLY_OK
            var next = self._next_ssn.get(stream_id).or_else(0)
            if chunk.ssn == next:
                var whole = List[UInt8]()
                swap(whole, chunk.payload)
                out.append(SctpMessage(stream_id, chunk.ppid, False, whole^))
                self._next_ssn[stream_id] = next + 1
                self._drain_ready(stream_id, out)
                return REASSEMBLY_OK
            if ssn_lt(chunk.ssn, next):
                return REASSEMBLY_DISCARDED

        var start = tsn
        var end = tsn
        var total = size
        if join_left:
            start = self._run_start.pop(tsn - 1)
            total += self._run_bytes[start]
        if join_right:
            end = self._run_end.pop(tsn + 1)
            total += self._run_bytes.pop(tsn + 1)
        self._run_end[start] = end
        self._run_start[end] = start
        self._run_bytes[start] = total
        self._cost += size + CHUNK_BUFFER_OVERHEAD
        self._chunks[tsn] = chunk^
        if total > self._max_message_size:
            return REASSEMBLY_TOO_LARGE

        if not (self._chunks[start].beginning() and self._chunks[end].ending()):
            return REASSEMBLY_OK
        if self._chunks[start].unordered():
            out.append(self._take_run(start, True))
            return REASSEMBLY_OK
        var ssn = self._chunks[start].ssn
        var next = self._next_ssn.get(stream_id).or_else(0)
        if ssn == next:
            out.append(self._take_run(start, True))
            self._next_ssn[stream_id] = next + 1
            self._drain_ready(stream_id, out)
        elif ssn_lt(ssn, next):
            _ = self._take_run(start, False)
            return REASSEMBLY_DISCARDED
        else:
            var key = _ready_key(stream_id, ssn)
            if key in self._ready:
                _ = self._take_run(start, False)
                return REASSEMBLY_DISCARDED
            self._ready[key] = start
        return REASSEMBLY_OK

    def forward(
        mut self,
        new_cumulative_tsn: UInt32,
        cumulative_tsn: UInt32,
        stream_ids: Span[UInt16, _],
        ssns: Span[UInt16, _],
        mut out: List[SctpMessage],
    ) raises:
        """Applies a FORWARD-TSN: drops skipped fragments, releases streams.

        Partial messages that reach back to or before the new cumulative TSN
        are dropped. For every listed ordered stream, complete messages up
        to the skipped sequence number are delivered and the stream moves
        past it.

        Args:
            new_cumulative_tsn: The value carried by the FORWARD-TSN.
            cumulative_tsn: The cumulative TSN after applying it.
            stream_ids: The ordered streams that had messages skipped.
            ssns: For each stream, the largest skipped sequence number.
            out: The list that deliverable messages are appended to.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        var doomed = List[UInt32]()
        for entry in self._run_end.items():
            var start = entry.key
            var end = entry.value
            var has_begin = self._chunks[start].beginning()
            var has_end = self._chunks[end].ending()
            if has_begin and has_end:
                continue
            if tsn_le(start, new_cumulative_tsn):
                doomed.append(start)
            elif not has_begin and tsn_le(start - 1, cumulative_tsn):
                doomed.append(start)
            elif not has_end and tsn_le(end + 1, cumulative_tsn):
                doomed.append(start)
        for start in doomed:
            _ = self._take_run(start, False)

        var count = len(stream_ids)
        if len(ssns) < count:
            count = len(ssns)
        for i in range(count):
            var stream_id = stream_ids[i]
            var skipped = ssns[i]
            var next = self._next_ssn.get(stream_id).or_else(0)
            if not ssn_le(next, skipped):
                continue
            if len(self._ready) > 0:
                # Complete messages at or below the skipped one were only
                # waiting for messages that will never come.
                var offsets = List[Int]()
                for entry in self._ready.items():
                    var key = entry.key
                    if UInt16(key >> 16) != stream_id:
                        continue
                    var ssn = UInt16(key & 0xFFFF)
                    if ssn_le(next, ssn) and ssn_le(ssn, skipped):
                        offsets.append(Int(ssn - next))
                _sort(offsets)
                for off in offsets:
                    var key = _ready_key(stream_id, next + UInt16(off))
                    var start = self._ready.pop(key)
                    out.append(self._take_run(start, True))
            self._next_ssn[stream_id] = skipped + 1
            self._drain_ready(stream_id, out)

    def reset_stream(mut self, stream_id: UInt16) raises:
        """Restarts an inbound stream at sequence number 0.

        Ordered data still held for the stream is dropped: after a reset it
        can no longer be delivered in order.

        Args:
            stream_id: The inbound stream the peer reset.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        var doomed = List[UInt32]()
        for entry in self._run_end.items():
            if (
                self._chunks[entry.key].stream_id == stream_id
                and not self._chunks[entry.key].unordered()
            ):
                doomed.append(entry.key)
        for start in doomed:
            _ = self._take_run(start, False)
        var keys = List[UInt32]()
        for entry in self._ready.items():
            if UInt16(entry.key >> 16) == stream_id:
                keys.append(entry.key)
        for key in keys:
            _ = self._ready.pop(key)
        if stream_id in self._next_ssn:
            _ = self._next_ssn.pop(stream_id)

    def clear(mut self):
        """Drops every stored fragment and all stream state."""
        self._chunks = Dict[UInt32, DataChunk]()
        self._run_end = Dict[UInt32, UInt32]()
        self._run_start = Dict[UInt32, UInt32]()
        self._run_bytes = Dict[UInt32, Int]()
        self._next_ssn = Dict[UInt16, UInt16]()
        self._ready = Dict[UInt32, UInt32]()
        self._cost = 0


def _sort(mut values: List[Int]):
    # Insertion sort: the lists are short.
    for i in range(1, len(values)):
        var v = values[i]
        var j = i - 1
        while j >= 0 and values[j] > v:
            values[j + 1] = values[j]
            j -= 1
        values[j + 1] = v
