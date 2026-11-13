"""Receive side of an association: what to accept and what to acknowledge.

`Receiver` puts `TsnTracker` and `Reassembly` behind the receive window: it
decides whether an arriving DATA chunk is kept, produces the messages it
completes, and builds the SACK that reports the result.
"""

from .chunk import DataChunk, ForwardTsnChunk, SackChunk
from .reassembly import (
    CHUNK_BUFFER_OVERHEAD,
    REASSEMBLY_DISCARDED,
    REASSEMBLY_TOO_LARGE,
    TSN_DUPLICATE,
    TSN_OUT_OF_WINDOW,
    Reassembly,
    SctpMessage,
    TsnTracker,
)

comptime RECEIVE_OK = 0
"""`Receiver.on_data()`: the chunk was accepted."""
comptime RECEIVE_DUPLICATE = 1
"""`Receiver.on_data()`: the TSN was received before."""
comptime RECEIVE_REFUSED = 2
"""`Receiver.on_data()`: no room; the peer has to retransmit."""
comptime RECEIVE_DISCARDED = 3
"""`Receiver.on_data()`: accepted, but part of a message given up on."""
comptime RECEIVE_INVALID_STREAM = 4
"""`Receiver.on_data()`: accepted, but the stream does not exist."""
comptime RECEIVE_TOO_LARGE = 5
"""`Receiver.on_data()`: a message exceeds the size limit."""

comptime _MAX_DUPLICATE_REPORTS = 16
comptime _MAX_GAP_BLOCKS = 64


struct Receiver(Movable):
    """TSN tracking, reassembly and receive window of one association."""

    var _tracker: TsnTracker
    var _reasm: Reassembly
    var _dups: List[UInt32]
    var _last_rwnd: Int
    var _window: Int
    var _max_message_size: Int
    var _mtu: Int
    var _max_tsn_gap: Int
    var _in_streams: Int

    def __init__(
        out self,
        a_rwnd: UInt32,
        max_message_size: Int,
        mtu: Int,
        max_tsn_gap: Int,
        inbound_streams: Int,
    ):
        """Creates a receiver that waits for the peer's initial TSN.

        Args:
            a_rwnd: The receive window to advertise, in bytes.
            max_message_size: The largest message to reassemble.
            mtu: The largest packet to emit, which bounds a SACK.
            max_tsn_gap: How far past the cumulative TSN chunks are kept.
            inbound_streams: The number of inbound streams offered.
        """
        self._tracker = TsnTracker(0, max_tsn_gap)
        self._reasm = Reassembly(max_message_size)
        self._dups = List[UInt32]()
        self._last_rwnd = Int(a_rwnd)
        self._window = Int(a_rwnd)
        self._max_message_size = max_message_size
        self._mtu = mtu
        self._max_tsn_gap = max_tsn_gap
        self._in_streams = inbound_streams

    def set_peer(mut self, initial_tsn: UInt32, inbound_streams: Int):
        """Starts over at the peer's initial TSN.

        Args:
            initial_tsn: The initial TSN from the peer's INIT or INIT ACK.
            inbound_streams: The negotiated number of inbound streams.
        """
        self._tracker = TsnTracker(initial_tsn - 1, self._max_tsn_gap)
        self._in_streams = inbound_streams

    def cumulative_tsn(self) -> UInt32:
        """Returns the highest TSN received with no gap before it.

        Returns:
            The cumulative TSN.
        """
        return self._tracker.cumulative_tsn()

    def buffered(self) -> Int:
        """Returns the buffer space taken by stored fragments.

        Returns:
            The cost of everything held for reassembly or ordering.
        """
        return self._reasm.cost()

    def advertised_rwnd(self, unread: Int) -> Int:
        """Computes the receive window to advertise.

        Args:
            unread: Bytes of delivered messages the user has not read yet.

        Returns:
            The free receive buffer in bytes, never negative.
        """
        var free = self._window - self._reasm.cost() - unread
        if free < 0:
            return 0
        return free

    def window_update_due(self, unread: Int) -> Bool:
        """Checks whether the window reopened enough to tell the peer.

        Args:
            unread: Bytes of delivered messages the user has not read yet.

        Returns:
            `True` if the last SACK advertised less than a quarter of the
            window and at least another quarter has become free since.
        """
        var quarter = self._window // 4
        return self._last_rwnd < quarter and (
            self.advertised_rwnd(unread) - self._last_rwnd >= quarter
        )

    def on_data(
        mut self,
        var chunk: DataChunk,
        unread: Int,
        events_full: Bool,
        mut out: List[SctpMessage],
    ) raises -> Int:
        """Processes one DATA chunk with a non-empty payload.

        Args:
            chunk: The decoded chunk.
            unread: Bytes of delivered messages the user has not read yet.
            events_full: Whether the user's event queue is at its limit.
            out: The list that completed messages are appended to.

        Returns:
            One of the `RECEIVE_*` values.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        var kind = self._tracker.classify(chunk.tsn)
        if kind == TSN_DUPLICATE:
            if len(self._dups) < _MAX_DUPLICATE_REPORTS:
                self._dups.append(chunk.tsn)
            return RECEIVE_DUPLICATE
        if kind == TSN_OUT_OF_WINDOW:
            return RECEIVE_REFUSED
        # Refuse what does not fit the receive buffer. Unread messages
        # alone may fill it: then the reader has to catch up first.
        # Otherwise the next expected TSN gets extra room, so that a buffer
        # full of later data cannot block the chunk that would release it.
        var cost = len(chunk.payload) + CHUNK_BUFFER_OVERHEAD
        var held = self._reasm.cost() + unread
        var fits = held + cost <= self._window
        if not fits and chunk.tsn == self._tracker.cumulative_tsn() + 1:
            fits = unread + cost <= self._window and (
                held + cost <= self._window + self._max_message_size + self._mtu
            )
        if not fits or events_full:
            return RECEIVE_REFUSED
        self._tracker.mark(chunk.tsn)
        if Int(chunk.stream_id) >= self._in_streams:
            return RECEIVE_INVALID_STREAM
        var status = self._reasm.insert(
            chunk^, self._tracker.cumulative_tsn(), out
        )
        if status == REASSEMBLY_TOO_LARGE:
            return RECEIVE_TOO_LARGE
        if status == REASSEMBLY_DISCARDED:
            return RECEIVE_DISCARDED
        return RECEIVE_OK

    def on_forward_tsn(
        mut self, fwd: ForwardTsnChunk, mut out: List[SctpMessage]
    ) raises:
        """Processes a FORWARD-TSN chunk (RFC 3758 section 3.6).

        A FORWARD-TSN at or behind the cumulative TSN leaves it alone but
        still names messages the sender gave up, so the buffers are cleaned
        either way.

        Args:
            fwd: The decoded chunk.
            out: The list that released messages are appended to.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        self._tracker.forward(fwd.new_cumulative_tsn)
        self._reasm.forward(
            fwd.new_cumulative_tsn,
            self._tracker.cumulative_tsn(),
            Span(fwd.stream_ids),
            Span(fwd.ssns),
            out,
        )

    def build_sack(mut self, unread: Int) -> SackChunk:
        """Builds the SACK for the current state.

        The pending duplicate reports move into the SACK; if it is not sent
        after all, hand them back with `keep_duplicates()`.

        Args:
            unread: Bytes of delivered messages the user has not read yet.

        Returns:
            A SACK that fits one packet.
        """
        var rwnd = self.advertised_rwnd(unread)
        self._last_rwnd = rwnd
        var sack = SackChunk(self._tracker.cumulative_tsn(), UInt32(rwnd))
        var room = (self._mtu - 12 - 16 - 4 * len(self._dups)) // 4
        if room > _MAX_GAP_BLOCKS:
            room = _MAX_GAP_BLOCKS
        if room > 0:
            sack.gaps = self._tracker.gap_blocks(room)
        swap(sack.duplicates, self._dups)
        return sack^

    def keep_duplicates(mut self, mut sack: SackChunk):
        """Takes the duplicate reports back from a SACK that was not sent.

        Args:
            sack: The SACK returned by `build_sack()`.
        """
        swap(self._dups, sack.duplicates)

    def reset_stream(mut self, stream_id: UInt16) raises:
        """Restarts an inbound stream at sequence number 0.

        Args:
            stream_id: The inbound stream the peer reset.

        Raises:
            Error: If the internal bookkeeping is inconsistent.
        """
        self._reasm.reset_stream(stream_id)

    def clear(mut self):
        """Drops everything held for reassembly."""
        self._reasm.clear()
        self._dups.clear()
