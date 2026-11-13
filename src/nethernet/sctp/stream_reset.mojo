"""Stream reset bookkeeping for both directions (RFC 6525).

`StreamReset` decides when an Outgoing SSN Reset Request of ours may go out
and how a request of the peer is answered. It does no I/O: it hands back
encoded RE-CONFIG chunks and the inbound streams to reset, and the
association queues, retransmits and reports them.
"""

from .reconfig import (
    PARAM_ADD_INCOMING_STREAMS,
    PARAM_INCOMING_RESET,
    PARAM_OUTGOING_RESET,
    RECONFIG_RESULT_BAD_SEQUENCE,
    RECONFIG_RESULT_DENIED,
    RECONFIG_RESULT_IN_PROGRESS,
    RECONFIG_RESULT_PERFORMED,
    ReconfigParam,
    encode_reconfig,
    outgoing_reset_request,
    reconfig_response,
)
from .sender import Sender
from .serial import tsn_gt, tsn_le
from .timer import Timer

comptime RESET_RESPONSE_IGNORED = 0
"""`StreamReset.on_response()`: the response matches no pending request."""
comptime RESET_RESPONSE_IN_PROGRESS = 1
"""`StreamReset.on_response()`: the peer is still working on the request."""
comptime RESET_RESPONSE_FINAL = 2
"""`StreamReset.on_response()`: the request is finished."""


def _response_chunk(seq: UInt32, result: UInt32) -> List[UInt8]:
    var params: List[ReconfigParam] = []
    params.append(reconfig_response(seq, result))
    var chunk = List[UInt8]()
    encode_reconfig(chunk, Span(params))
    return chunk^


struct StreamReset(Movable):
    """The request and response sequencing of RFC 6525 stream resets."""

    var timer: Timer
    """The re-configuration timer; armed while a request of ours is open."""
    var in_progress: Bool
    """Whether the peer answered "in progress" since the last transmission."""

    var _next_seq: UInt32
    var _active: Bool
    var _seq: UInt32
    var _last_tsn: UInt32
    var _streams: List[UInt16]
    var _waiting: List[UInt16]
    var _peer_seq: UInt32
    var _peer_result: UInt32
    var _deferred_active: Bool
    var _deferred_seq: UInt32
    var _deferred_last_tsn: UInt32
    var _deferred_streams: List[UInt16]

    def __init__(out self, initial_tsn: UInt32):
        """Creates the bookkeeping with no request open.

        Args:
            initial_tsn: The local initial TSN, which is also the first
                request sequence number.
        """
        self.timer = Timer()
        self.in_progress = False
        self._next_seq = initial_tsn
        self._active = False
        self._seq = 0
        self._last_tsn = 0
        self._streams = List[UInt16]()
        self._waiting = List[UInt16]()
        self._peer_seq = 0
        self._peer_result = 0
        self._deferred_active = False
        self._deferred_seq = 0
        self._deferred_last_tsn = 0
        self._deferred_streams = List[UInt16]()

    def set_peer(mut self, peer_initial_tsn: UInt32):
        """Records the peer's initial TSN, its first request sequence number.

        Args:
            peer_initial_tsn: The initial TSN from the peer's INIT.
        """
        self._peer_seq = peer_initial_tsn - 1
        self._peer_result = 0

    def request_chunk(self) -> List[UInt8]:
        """Encodes the open Outgoing SSN Reset Request.

        Returns:
            A RE-CONFIG chunk, the same bytes for every retransmission.
        """
        var params: List[ReconfigParam] = []
        params.append(
            outgoing_reset_request(
                self._seq, self._peer_seq, self._last_tsn, Span(self._streams)
            )
        )
        var chunk = List[UInt8]()
        encode_reconfig(chunk, Span(params))
        return chunk^

    def start_request(mut self, mut sender: Sender, peer_supports: Bool) -> Bool:
        """Opens a request for the streams whose reset is due, if allowed.

        Only one request may be open at a time, so streams that become
        ready meanwhile wait for the next one.

        Args:
            sender: The send side, which says which resets are due.
            peer_supports: Whether the peer announced RE-CONFIG support.

        Returns:
            `True` if a new request was opened: the caller sends
            `request_chunk()` and starts `timer`.
        """
        var ready = sender.take_reset_ready()
        for s in ready:
            self._waiting.append(s)
        if self._active or len(self._waiting) == 0:
            return False
        if not peer_supports:
            # Nothing to negotiate with: just let the streams continue.
            sender.finish_reset(Span(self._waiting), False)
            self._waiting.clear()
            return False
        self._active = True
        self.in_progress = False
        self._seq = self._next_seq
        self._next_seq += 1
        self._last_tsn = sender.next_tsn() - 1
        self._streams.clear()
        swap(self._streams, self._waiting)
        return True

    def on_response(
        mut self, seq: UInt32, result: UInt32, mut sender: Sender
    ) -> Int:
        """Handles a Re-configuration Response from the peer.

        Args:
            seq: The response sequence number.
            result: The result code.
            sender: The send side, whose streams continue once finished.

        Returns:
            `RESET_RESPONSE_IGNORED`, `RESET_RESPONSE_IN_PROGRESS` (the
            caller restarts `timer`) or `RESET_RESPONSE_FINAL`.
        """
        if not self._active or seq != self._seq:
            return RESET_RESPONSE_IGNORED
        if result == RECONFIG_RESULT_IN_PROGRESS:
            self.in_progress = True
            return RESET_RESPONSE_IN_PROGRESS
        self.in_progress = False
        sender.finish_reset(
            Span(self._streams), result <= RECONFIG_RESULT_PERFORMED
        )
        self._active = False
        self._streams.clear()
        self.timer.stop()
        return RESET_RESPONSE_FINAL

    def _perform(
        mut self,
        seq: UInt32,
        streams: Span[UInt16, _],
        mut reset_streams: List[UInt16],
    ) -> List[UInt8]:
        for s in streams:
            reset_streams.append(s)
        self._deferred_active = False
        self._peer_seq = seq
        self._peer_result = RECONFIG_RESULT_PERFORMED
        return _response_chunk(seq, RECONFIG_RESULT_PERFORMED)

    def on_request(
        mut self,
        param: ReconfigParam,
        cumulative_tsn: UInt32,
        can_report: Bool,
        can_reset_outgoing: Bool,
        mut sender: Sender,
        mut reset_streams: List[UInt16],
    ) -> List[UInt8]:
        """Handles one request parameter from the peer.

        Args:
            param: A decoded request parameter.
            cumulative_tsn: The receive side's cumulative TSN.
            can_report: Whether there is room to report a stream reset.
            can_reset_outgoing: Whether our own streams may be reset now.
            sender: The send side, for an Incoming SSN Reset Request.
            reset_streams: The list that inbound streams to reset now are
                appended to.

        Returns:
            The RE-CONFIG chunk to answer with, or an empty list to stay
            silent and let the peer retransmit.
        """
        var none = List[UInt8]()
        var kind = param.kind
        var seq = param.request_seq
        if kind < PARAM_OUTGOING_RESET or kind > PARAM_ADD_INCOMING_STREAMS:
            return none^
        # The sequence number says whether the request is new.
        if seq == self._peer_seq:
            return _response_chunk(seq, self._peer_result)
        if not tsn_gt(seq, self._peer_seq):
            return _response_chunk(seq, RECONFIG_RESULT_BAD_SEQUENCE)
        if kind == PARAM_OUTGOING_RESET:
            if not can_report:
                return none^
            if tsn_gt(param.last_tsn, cumulative_tsn):
                # Data sent before the reset is still missing.
                self._deferred_active = True
                self._deferred_seq = seq
                self._deferred_last_tsn = param.last_tsn
                self._deferred_streams = param.streams.copy()
                return _response_chunk(seq, RECONFIG_RESULT_IN_PROGRESS)
            return self._perform(seq, Span(param.streams), reset_streams)
        self._peer_seq = seq
        self._peer_result = RECONFIG_RESULT_DENIED
        if kind == PARAM_INCOMING_RESET and can_reset_outgoing:
            # The peer asks us to reset our outgoing streams.
            for s in param.streams:
                sender.queue_reset(s)
            self._peer_result = RECONFIG_RESULT_PERFORMED
        return _response_chunk(seq, self._peer_result)

    def on_cumulative_tsn(
        mut self,
        cumulative_tsn: UInt32,
        can_report: Bool,
        mut reset_streams: List[UInt16],
    ) -> List[UInt8]:
        """Completes a peer request that waited for missing data.

        Args:
            cumulative_tsn: The receive side's cumulative TSN.
            can_report: Whether there is room to report a stream reset.
            reset_streams: The list that inbound streams to reset now are
                appended to.

        Returns:
            The RE-CONFIG chunk to send, or an empty list.
        """
        if (
            self._deferred_active
            and can_report
            and tsn_le(self._deferred_last_tsn, cumulative_tsn)
        ):
            var streams = self._deferred_streams.copy()
            return self._perform(
                self._deferred_seq, Span(streams), reset_streams
            )
        return List[UInt8]()
