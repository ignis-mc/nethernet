"""The SCTP association state machine for WebRTC data channels.

One `Association` is one SCTP association running over a DTLS connection:
a single path and a single peer. It is sans-I/O: packets come in through
`handle_packet()`, go out through `poll_transmit()`, time arrives as
`now_ms`, and results are read with `poll_event()`.

Implemented: RFC 9260 association setup (active, passive and simultaneous),
DATA transfer with SACK, flow and congestion control, retransmission,
shutdown and abort; RFC 3758 partial reliability with FORWARD-TSN; RFC 6525
stream reset. Not implemented: multihoming, association restart, I-DATA,
AUTH, ASCONF and sending HEARTBEAT.
"""

from std.collections import Deque

from ..wire import put_u32
from .cause import (
    CAUSE_INVALID_MANDATORY_PARAMETER,
    CAUSE_NO_USER_DATA,
    CAUSE_OUT_OF_RESOURCE,
    CAUSE_PROTOCOL_VIOLATION,
    CAUSE_STALE_COOKIE,
    CAUSE_USER_INITIATED_ABORT,
    ErrorCause,
    decode_causes,
)
from .chunk import (
    SackChunk,
    decode_data,
    decode_forward_tsn,
    decode_init,
    decode_sack,
    decode_shutdown,
    encode_cookie_ack,
    encode_cookie_echo,
    encode_heartbeat,
    encode_shutdown,
    encode_shutdown_ack,
    encode_shutdown_complete,
)
from .config import (
    SCTP_EVENT_CLOSED,
    SCTP_EVENT_CONNECTED,
    SCTP_EVENT_MESSAGE,
    SCTP_EVENT_STREAM_RESET,
    SCTP_STATE_CLOSED,
    SCTP_STATE_COOKIE_ECHOED,
    SCTP_STATE_COOKIE_WAIT,
    SCTP_STATE_ESTABLISHED,
    SCTP_STATE_SHUTDOWN_ACK_SENT,
    SCTP_STATE_SHUTDOWN_PENDING,
    SCTP_STATE_SHUTDOWN_RECEIVED,
    SCTP_STATE_SHUTDOWN_SENT,
    SctpConfig,
    SctpEvent,
    SctpStats,
)
from .control import (
    abort_packet,
    abort_reason,
    init_ack_packet,
    init_backoff,
    init_is_valid,
    init_packet,
    invalid_stream_report,
    stale_cookie_packet,
    stray_reply,
    supports_forward_tsn,
    unrecognized_chunk_report,
)
from .cookie import decode_cookie
from .packet import (
    CHUNK_ABORT,
    CHUNK_COOKIE_ACK,
    CHUNK_COOKIE_ECHO,
    CHUNK_DATA,
    CHUNK_ERROR,
    CHUNK_FORWARD_TSN,
    CHUNK_HEARTBEAT,
    CHUNK_HEARTBEAT_ACK,
    CHUNK_INIT,
    CHUNK_INIT_ACK,
    CHUNK_RECONFIG,
    CHUNK_SACK,
    CHUNK_SHUTDOWN,
    CHUNK_SHUTDOWN_ACK,
    CHUNK_SHUTDOWN_COMPLETE,
    ChunkRef,
    PacketView,
    begin_packet,
    finish_packet,
    parse_packet,
)
from .reassembly import SctpMessage
from .receiver import (
    RECEIVE_DUPLICATE,
    RECEIVE_INVALID_STREAM,
    RECEIVE_REFUSED,
    RECEIVE_TOO_LARGE,
    Receiver,
)
from .reconfig import PARAM_RECONFIG_RESPONSE, decode_reconfig
from .sender import Sender
from .stream_reset import (
    RESET_RESPONSE_IGNORED,
    RESET_RESPONSE_IN_PROGRESS,
    StreamReset,
)
from .timer import Timer

comptime _MAX_CONTROL_QUEUE = 64


struct Association(Movable):
    """One SCTP association over a single DTLS path.

    Drive it by feeding every decrypted inbound datagram to
    `handle_packet()`, calling `handle_timeout()` when `next_timeout()` is
    due, and after each call draining `poll_transmit()` and `poll_event()`
    until they return `None`.
    """

    var _cfg: SctpConfig
    var _state: Int
    var _ended: Bool
    var _stats: SctpStats

    var _peer_known: Bool
    var _peer_tag: UInt32
    var _peer_reconfig: Bool
    var _out_streams: Int

    var _t1: Timer
    var _init_attempts: Int
    var _cookie_echo: List[UInt8]
    var _send_cookie_echo: Bool

    var _receiver: Receiver
    var _sack_needed: Bool
    var _saw_data: Bool

    var _sender: Sender
    var _error_count: Int

    var _reset: StreamReset
    var _t2: Timer

    var _ctrl_packets: Deque[List[UInt8]]
    var _ctrl_chunks: Deque[List[UInt8]]
    var _events: Deque[SctpEvent]
    var _event_bytes: Int

    def __init__(out self, config: SctpConfig):
        """Creates a closed association.

        It answers a peer's INIT on its own; call `connect()` to send one.
        """
        self._cfg = config.copy()
        self._state = SCTP_STATE_CLOSED
        self._ended = False
        self._stats = SctpStats()
        self._peer_known = False
        self._peer_tag = 0
        self._peer_reconfig = False
        self._out_streams = Int(config.num_outbound_streams)
        self._t1 = Timer()
        self._init_attempts = 0
        self._cookie_echo = List[UInt8]()
        self._send_cookie_echo = False
        self._receiver = Receiver(
            config.a_rwnd,
            config.max_message_size,
            config.mtu,
            config.max_tsn_gap,
            Int(config.num_inbound_streams),
        )
        self._sack_needed = False
        self._saw_data = False
        self._sender = Sender(
            config.initial_tsn,
            config.mtu,
            config.rto_initial_ms,
            config.rto_min_ms,
            config.rto_max_ms,
        )
        self._error_count = 0
        self._reset = StreamReset(config.initial_tsn)
        self._t2 = Timer()
        self._ctrl_packets = Deque[List[UInt8]]()
        self._ctrl_chunks = Deque[List[UInt8]]()
        self._events = Deque[SctpEvent]()
        self._event_bytes = 0

    # ----------------------------------------------------------------- API

    def state(self) -> Int:
        """Returns the association state."""
        return self._state

    def stats(self) -> SctpStats:
        """Returns a snapshot of the counters."""
        var s = self._stats
        s.retransmits = self._sender.retransmits
        s.fast_retransmits = self._sender.fast_retransmits
        s.t3_expiries = self._sender.t3_expiries
        s.abandoned_chunks = self._sender.abandoned_chunks
        s.data_chunks_out = self._sender.data_chunks_out
        s.forward_tsns_out = self._sender.forward_tsns_out
        s.loss_probes = self._sender.loss_probes
        s.rack_losses = self._sender.rack_losses
        return s

    def buffered_amount(self) -> Int:
        """Counts user bytes queued or in flight and not yet acknowledged."""
        return self._sender.buffered_amount()

    def congestion_window(self) -> Int:
        """Returns the congestion window."""
        return self._sender.cwnd()

    def rto_ms(self) -> Int:
        """Returns the current retransmission timeout."""
        return self._sender.rto.rto()

    def receive_buffered(self) -> Int:
        """Returns the receive buffer space in use."""
        return self._receiver.buffered() + self._event_bytes

    def connect(mut self, now_ms: Int):
        """Starts an active open by queueing an INIT.

        Safe to call when the peer does the same (simultaneous open). Does
        nothing unless the association is closed and unused.
        """
        if self._ended or self._state != SCTP_STATE_CLOSED:
            return
        self._state = SCTP_STATE_COOKIE_WAIT
        self._init_attempts = 0
        self._queue_init()
        self._t1.start(now_ms + self._cfg.rto_initial_ms)

    def send(
        mut self,
        stream_id: UInt16,
        ppid: UInt32,
        payload: Span[UInt8, _],
        unordered: Bool,
        max_retransmits: Int,
    ) raises:
        """Queues one user message.

        The message is fragmented into DATA chunks that fit the MTU.
        Fragments get consecutive TSNs and are never interleaved with
        another message. Messages queued while connecting are sent once
        the association is established.
        """
        if self._ended or not (
            self._state == SCTP_STATE_ESTABLISHED
            or self._state == SCTP_STATE_COOKIE_WAIT
            or self._state == SCTP_STATE_COOKIE_ECHOED
        ):
            raise Error("sctp: association is not open")
        if len(payload) == 0:
            raise Error("sctp: cannot send an empty message")
        if len(payload) > self._cfg.max_message_size:
            raise Error("sctp: message exceeds max_message_size")
        if Int(stream_id) >= self._out_streams:
            raise Error("sctp: no such outbound stream")
        self._sender.queue_message(
            stream_id, ppid, payload, unordered, max_retransmits
        )
        self._stats.messages_out += 1

    def reset_stream(mut self, stream_id: UInt16):
        """Resets an outbound stream, as closing a data channel requires.

        An Outgoing SSN Reset Request goes out once every message queued
        on the stream so far has been sent, and is retransmitted until the
        peer answers. Does nothing unless the association is established.
        """
        if self._ended or self._state != SCTP_STATE_ESTABLISHED:
            return
        self._sender.queue_reset(stream_id)

    def shutdown(mut self, now_ms: Int):
        """Starts a graceful shutdown.

        Queued data is still delivered; the SHUTDOWN goes out once all of
        it is acknowledged. While still connecting this closes at once.
        """
        if self._ended:
            return
        if self._state == SCTP_STATE_ESTABLISHED:
            self._state = SCTP_STATE_SHUTDOWN_PENDING
            self._progress_shutdown(now_ms)
        elif (
            self._state == SCTP_STATE_CLOSED
            or self._state == SCTP_STATE_COOKIE_WAIT
            or self._state == SCTP_STATE_COOKIE_ECHOED
        ):
            var why = "shutdown before the association was established"
            self._queue_abort(CAUSE_USER_INITIATED_ABORT, why.as_bytes())
            self._close(why)

    def abort(mut self, reason: StringSpan):
        """Ends the association at once and tells the peer why.

        Queues an ABORT with a User-Initiated Abort cause if the peer is
        known, and emits `SCTP_EVENT_CLOSED`.
        """
        if self._ended:
            return
        self._queue_abort(CAUSE_USER_INITIATED_ABORT, reason.as_bytes())
        self._close(String(reason))

    def next_timeout(self) -> Optional[Int]:
        """Returns when `handle_timeout()` next has work to do."""
        var best: Optional[Int] = None
        if self._ended:
            return best
        for t in [
            self._t1,
            self._sender.t3,
            self._sender.probe,
            self._t2,
            self._reset.timer,
        ]:
            if t.armed and (not best or t.deadline < best.or_else(0)):
                best = t.deadline
        return best

    def handle_timeout(mut self, now_ms: Int):
        """Runs every timer whose deadline has passed."""
        if self._ended:
            return
        if self._t1.expired(now_ms):
            self._on_t1(now_ms)
        if not self._ended and self._sender.t3.expired(now_ms):
            if self._count_error():
                self._sender.on_t3_expired(now_ms)
        if not self._ended and self._sender.probe.expired(now_ms):
            self._sender.on_probe_expired(now_ms)
        if not self._ended and self._t2.expired(now_ms):
            if self._count_error():
                self._sender.rto.backoff()
                self._send_shutdown_chunk()
                self._t2.start(now_ms + self._sender.rto.rto())
        if not self._ended and self._reset.timer.expired(now_ms):
            # Repeating the request counts as a silent round only if the
            # peer did not answer "in progress" (RFC 6525 5.2.7) and no
            # DATA is outstanding: otherwise T3-rtx already judges whether
            # the peer still answers, and one round must count once.
            var counts = not self._reset.in_progress and (
                not self._sender.t3.armed
            )
            self._reset.in_progress = False
            if not counts or self._count_error():
                if counts:
                    self._sender.rto.backoff()
                self._push_chunk(self._reset.request_chunk())
                self._reset.timer.start(now_ms + self._sender.rto.rto())

    def poll_event(mut self) -> Optional[SctpEvent]:
        """Takes the next queued event."""
        if len(self._events) == 0:
            return None
        try:
            var ev = self._events.popleft()
            if ev.kind == SCTP_EVENT_MESSAGE:
                self._event_bytes -= len(ev.payload)
                self._maybe_window_update()
            return ev^
        except:
            return None

    def poll_transmit(mut self, now_ms: Int) -> Optional[List[UInt8]]:
        """Builds the next packet to hand to DTLS.

        Call until it returns `None`. A SACK that is due goes first in the
        packet, followed by other control chunks and as much DATA as the
        MTU and the send windows allow.
        """
        try:
            return self._poll_transmit(now_ms)
        except:
            return None

    def handle_packet(mut self, packet: Span[UInt8, _], now_ms: Int):
        """Processes one inbound SCTP packet.

        Never raises: packets that are malformed, fail the checksum or
        carry the wrong ports or verification tag are dropped and counted.
        """
        self._stats.packets_in += 1
        self._stats.bytes_in += len(packet)
        if self._ended:
            # The association is gone. Tell a peer that still talks to it,
            # so that it does not have to find out by timing out.
            self._stats.packets_dropped += 1
            try:
                var stray = parse_packet(packet)
                if (
                    stray.destination_port == self._cfg.local_port
                    and stray.source_port == self._cfg.remote_port
                    and len(stray.chunks) > 0
                ):
                    self._push_packet(stray_reply(self._cfg, stray))
            except:
                pass
            return
        try:
            var view = parse_packet(packet)
            if (
                view.destination_port != self._cfg.local_port
                or view.source_port != self._cfg.remote_port
                or len(view.chunks) == 0
            ):
                self._stats.packets_dropped += 1
                return
            self._process(packet, view, now_ms)
        except:
            self._stats.packets_dropped += 1
        if self._saw_data:
            self._saw_data = False
            if not self._ended:
                self._sack_needed = True
                if self._state == SCTP_STATE_SHUTDOWN_SENT:
                    # RFC 9260 9.2: DATA after our SHUTDOWN is answered
                    # with another SHUTDOWN, and T2 starts over.
                    self._send_shutdown_chunk()
                    self._t2.start(now_ms + self._sender.rto.rto())
        if not self._ended:
            self._progress_shutdown(now_ms)

    # ------------------------------------------------------------ plumbing

    def _push_event(mut self, var ev: SctpEvent):
        self._events.append(ev^)

    def _push_packet(mut self, var pkt: List[UInt8]):
        if len(pkt) > 0 and len(self._ctrl_packets) < _MAX_CONTROL_QUEUE:
            self._ctrl_packets.append(pkt^)

    def _push_chunk(mut self, var chunk: List[UInt8]):
        if len(chunk) > 0 and len(self._ctrl_chunks) < _MAX_CONTROL_QUEUE:
            self._ctrl_chunks.append(chunk^)

    def _new_packet(self, tag: UInt32) -> List[UInt8]:
        var out = List[UInt8](capacity=64)
        begin_packet(out, self._cfg.local_port, self._cfg.remote_port, tag)
        return out^

    def _close(mut self, var reason: String):
        if self._ended:
            return
        self._ended = True
        self._state = SCTP_STATE_CLOSED
        self._t1.stop()
        self._t2.stop()
        self._reset.timer.stop()
        self._sender.clear()
        self._receiver.clear()
        self._ctrl_chunks.clear()
        self._sack_needed = False
        self._send_cookie_echo = False
        var ev = SctpEvent(SCTP_EVENT_CLOSED)
        ev.reason = reason^
        self._push_event(ev^)

    def _queue_abort(mut self, code: UInt16, info: Span[UInt8, _]):
        if not self._peer_known:
            return
        var causes: List[ErrorCause] = []
        causes.append(ErrorCause(code, info))
        self._push_packet(
            abort_packet(self._cfg, self._peer_tag, False, Span(causes))
        )

    def _abort_with(mut self, code: UInt16, text: StringSpan):
        var info = List[UInt8]()
        if code == CAUSE_PROTOCOL_VIOLATION:
            info = List[UInt8](text.as_bytes())
        self._queue_abort(code, Span(info))
        self._close(String(text))

    def _count_error(mut self) -> Bool:
        # Returns False once the association has been given up.
        self._error_count += 1
        if self._error_count > self._cfg.max_retransmits:
            var why = "retransmission limit exceeded"
            self._queue_abort(CAUSE_USER_INITIATED_ABORT, why.as_bytes())
            self._close(why)
            return False
        return True

    def _can_receive_data(self) -> Bool:
        return (
            self._state == SCTP_STATE_ESTABLISHED
            or self._state == SCTP_STATE_SHUTDOWN_PENDING
            or self._state == SCTP_STATE_SHUTDOWN_SENT
            or self._state == SCTP_STATE_COOKIE_ECHOED
        )

    def _can_send_data(self) -> Bool:
        return (
            self._state == SCTP_STATE_ESTABLISHED
            or self._state == SCTP_STATE_SHUTDOWN_PENDING
            or self._state == SCTP_STATE_SHUTDOWN_RECEIVED
        )

    def _maybe_window_update(mut self):
        # After the reader frees a large part of a nearly closed window,
        # tell the peer instead of waiting for its zero window probe.
        if self._receiver.window_update_due(self._event_bytes):
            if self._can_receive_data() or (
                self._state == SCTP_STATE_SHUTDOWN_RECEIVED
            ):
                self._sack_needed = True

    # ----------------------------------------------------------- handshake

    def _queue_init(mut self):
        self._push_packet(init_packet(self._cfg))

    def _on_t1(mut self, now_ms: Int):
        self._init_attempts += 1
        if self._init_attempts > self._cfg.max_init_retransmits:
            var why = "handshake timed out"
            self._queue_abort(CAUSE_USER_INITIATED_ABORT, why.as_bytes())
            self._close(why)
            return
        if self._state == SCTP_STATE_COOKIE_WAIT:
            self._queue_init()
        elif self._state == SCTP_STATE_COOKIE_ECHOED:
            self._send_cookie_echo = True
        else:
            self._t1.stop()
            return
        self._t1.start(now_ms + init_backoff(self._cfg, self._init_attempts))

    def _set_peer(
        mut self,
        tag: UInt32,
        initial_tsn: UInt32,
        a_rwnd: UInt32,
        outbound: UInt16,
        inbound: UInt16,
        forward_tsn: Bool,
        reconfig: Bool,
    ):
        self._peer_known = True
        self._peer_tag = tag
        self._peer_reconfig = reconfig
        self._reset.set_peer(initial_tsn)
        self._sender.set_peer(a_rwnd, forward_tsn)
        self._out_streams = Int(self._cfg.num_outbound_streams)
        if Int(inbound) < self._out_streams:
            self._out_streams = Int(inbound)
        var in_streams = Int(self._cfg.num_inbound_streams)
        if Int(outbound) < in_streams:
            in_streams = Int(outbound)
        self._receiver.set_peer(initial_tsn, in_streams)

    def _establish(mut self):
        self._state = SCTP_STATE_ESTABLISHED
        self._t1.stop()
        self._send_cookie_echo = False
        self._cookie_echo.clear()
        self._error_count = 0
        self._push_event(SctpEvent(SCTP_EVENT_CONNECTED))

    def _on_init(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        var init = decode_init(value)
        if not init_is_valid(init):
            self._stats.chunks_dropped += 1
            if init.initiate_tag != 0:
                var causes: List[ErrorCause] = []
                var none = List[UInt8]()
                causes.append(
                    ErrorCause(CAUSE_INVALID_MANDATORY_PARAMETER, Span(none))
                )
                self._push_packet(
                    abort_packet(
                        self._cfg, init.initiate_tag, False, Span(causes)
                    )
                )
            return
        if self._state == SCTP_STATE_SHUTDOWN_ACK_SENT:
            self._send_shutdown_chunk()
            return
        # RFC 9260 5.1 and 5.2: in every other state the answer is an INIT
        # ACK, and nothing is remembered until the cookie comes back.
        self._push_packet(init_ack_packet(self._cfg, init, now_ms))

    def _on_init_ack(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        if self._state != SCTP_STATE_COOKIE_WAIT:
            self._stats.chunks_dropped += 1
            return
        var ack = decode_init(value)
        if not init_is_valid(ack) or len(ack.cookie) == 0:
            self._stats.chunks_dropped += 1
            return
        self._set_peer(
            ack.initiate_tag,
            ack.initial_tsn,
            ack.a_rwnd,
            ack.num_outbound_streams,
            ack.num_inbound_streams,
            supports_forward_tsn(ack),
            ack.supports_extension(CHUNK_RECONFIG),
        )
        self._cookie_echo = ack.cookie.copy()
        self._send_cookie_echo = True
        self._state = SCTP_STATE_COOKIE_ECHOED
        self._init_attempts = 0
        self._t1.start(now_ms + self._cfg.rto_initial_ms)

    def _on_cookie_echo(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        var data = decode_cookie(value, Span(self._cfg.cookie_secret))
        if (
            data.local_tag != self._cfg.local_tag
            or data.local_initial_tsn != self._cfg.initial_tsn
        ):
            raise Error("sctp: cookie belongs to another association")
        var established = not (
            self._state == SCTP_STATE_CLOSED
            or self._state == SCTP_STATE_COOKIE_WAIT
            or self._state == SCTP_STATE_COOKIE_ECHOED
        )
        if established:
            # A retransmitted COOKIE ECHO of this association is answered
            # again; anything else would be a restart, which is unsupported.
            if data.peer_tag != self._peer_tag:
                raise Error("sctp: association restart is not supported")
            var ack = List[UInt8]()
            encode_cookie_ack(ack)
            self._push_chunk(ack^)
            return
        var age = now_ms - data.created_ms
        if age < 0 or age > self._cfg.cookie_lifetime_ms:
            self._push_packet(
                stale_cookie_packet(self._cfg, data.peer_tag, age)
            )
            raise Error("sctp: stale cookie")
        if not self._peer_known or self._peer_tag != data.peer_tag:
            self._set_peer(
                data.peer_tag,
                data.peer_initial_tsn,
                data.peer_a_rwnd,
                data.peer_outbound_streams,
                data.peer_inbound_streams,
                data.peer_forward_tsn,
                data.peer_reconfig,
            )
        self._establish()
        var ack = List[UInt8]()
        encode_cookie_ack(ack)
        self._push_chunk(ack^)

    # ------------------------------------------------------------ dispatch

    def _process(
        mut self, packet: Span[UInt8, _], view: PacketView, now_ms: Int
    ) raises:
        var first = view.chunks[0]
        if first.kind == CHUNK_INIT:
            if len(view.chunks) != 1 or view.verification_tag != 0:
                self._stats.packets_dropped += 1
                return
            self._on_init(
                packet[first.offset : first.offset + first.length], now_ms
            )
            return
        var tag_ok = view.verification_tag == self._cfg.local_tag
        if not tag_ok and self._peer_known and (first.flags & 1) != 0:
            # ABORT and SHUTDOWN COMPLETE may reflect the tag we send.
            if (
                first.kind == CHUNK_ABORT
                or first.kind == CHUNK_SHUTDOWN_COMPLETE
            ):
                tag_ok = view.verification_tag == self._peer_tag
        var fresh = self._state == SCTP_STATE_CLOSED
        if not tag_ok or (fresh and first.kind != CHUNK_COOKIE_ECHO):
            self._stats.packets_dropped += 1
            if fresh:
                # RFC 9260 8.4: no association exists for this packet.
                self._push_packet(stray_reply(self._cfg, view))
            return
        for c in view.chunks:
            if self._ended:
                return
            var value = packet[c.offset : c.offset + c.length]
            if not self._on_chunk(c, value, now_ms):
                return

    def _on_chunk(
        mut self, c: ChunkRef, value: Span[UInt8, _], now_ms: Int
    ) raises -> Bool:
        # Returns False when the rest of the packet must be skipped.
        if c.kind == CHUNK_DATA:
            self._on_data(value, c.flags, now_ms)
        elif c.kind == CHUNK_SACK:
            self._on_sack(value, now_ms)
        elif c.kind == CHUNK_COOKIE_ECHO:
            self._on_cookie_echo(value, now_ms)
        elif c.kind == CHUNK_COOKIE_ACK:
            if self._state == SCTP_STATE_COOKIE_ECHOED:
                self._establish()
        elif c.kind == CHUNK_INIT_ACK:
            self._on_init_ack(value, now_ms)
        elif c.kind == CHUNK_INIT:
            # INIT must be alone in its packet.
            self._stats.chunks_dropped += 1
            return False
        elif c.kind == CHUNK_HEARTBEAT:
            if self._peer_known:
                var pkt = self._new_packet(self._peer_tag)
                encode_heartbeat(pkt, CHUNK_HEARTBEAT_ACK, value)
                finish_packet(pkt)
                self._push_packet(pkt^)
        elif c.kind == CHUNK_HEARTBEAT_ACK:
            pass
        elif c.kind == CHUNK_ABORT:
            self._on_abort(value)
            return False
        elif c.kind == CHUNK_ERROR:
            self._on_error(value, now_ms)
        elif c.kind == CHUNK_FORWARD_TSN:
            self._on_forward_tsn(value)
        elif c.kind == CHUNK_RECONFIG:
            self._on_reconfig(value, now_ms)
        elif c.kind == CHUNK_SHUTDOWN:
            self._on_shutdown(value, now_ms)
        elif c.kind == CHUNK_SHUTDOWN_ACK:
            if (
                self._state == SCTP_STATE_SHUTDOWN_SENT
                or self._state == SCTP_STATE_SHUTDOWN_ACK_SENT
            ):
                var pkt = self._new_packet(self._peer_tag)
                encode_shutdown_complete(pkt, False)
                finish_packet(pkt)
                self._push_packet(pkt^)
                self._close("shutdown complete")
                return False
        elif c.kind == CHUNK_SHUTDOWN_COMPLETE:
            if self._state == SCTP_STATE_SHUTDOWN_ACK_SENT:
                self._close("shutdown complete")
                return False
        else:
            # Unknown chunk: the two high bits of the type say what to do.
            self._stats.chunks_dropped += 1
            if (c.kind & 0x40) != 0 and self._peer_known:
                self._push_chunk(
                    unrecognized_chunk_report(c.kind, c.flags, c.length)
                )
            if (c.kind & 0x80) == 0:
                return False
        return True

    # ------------------------------------------------------------- receive

    def _deliver(mut self, mut messages: List[SctpMessage]):
        for i in range(len(messages)):
            var ev = SctpEvent(SCTP_EVENT_MESSAGE)
            ev.stream_id = messages[i].stream_id
            ev.ppid = messages[i].ppid
            ev.unordered = messages[i].unordered
            swap(ev.payload, messages[i].payload)
            self._event_bytes += len(ev.payload)
            self._stats.messages_in += 1
            self._push_event(ev^)

    def _on_data(
        mut self, value: Span[UInt8, _], flags: UInt8, now_ms: Int
    ) raises:
        if not self._can_receive_data():
            self._stats.chunks_dropped += 1
            return
        var chunk = decode_data(value, flags)
        self._saw_data = True
        if len(chunk.payload) == 0:
            var info = List[UInt8]()
            put_u32(info, chunk.tsn)
            self._queue_abort(CAUSE_NO_USER_DATA, Span(info))
            self._close("peer sent a DATA chunk without user data")
            return
        var stream_id = chunk.stream_id
        var messages = List[SctpMessage]()
        var status = self._receiver.on_data(
            chunk^,
            self._event_bytes,
            len(self._events) >= self._cfg.max_queued_events,
            messages,
        )
        self._deliver(messages)
        if status == RECEIVE_DUPLICATE:
            self._stats.duplicate_tsns += 1
            return
        if status == RECEIVE_REFUSED:
            self._stats.chunks_dropped += 1
            return
        self._stats.data_chunks_in += 1
        if status == RECEIVE_TOO_LARGE:
            var none = List[UInt8]()
            self._queue_abort(CAUSE_OUT_OF_RESOURCE, Span(none))
            self._close("peer sent a message larger than max_message_size")
            return
        if status == RECEIVE_INVALID_STREAM:
            self._push_chunk(invalid_stream_report(stream_id))
        elif status != 0:
            self._stats.chunks_dropped += 1
        self._after_cumulative_change()

    def _on_forward_tsn(mut self, value: Span[UInt8, _]) raises:
        if not self._can_receive_data():
            self._stats.chunks_dropped += 1
            return
        var fwd = decode_forward_tsn(value)
        # Like DATA, a FORWARD-TSN is answered with a SACK at once.
        self._saw_data = True
        var messages = List[SctpMessage]()
        self._receiver.on_forward_tsn(fwd, messages)
        self._deliver(messages)
        self._after_cumulative_change()

    def _apply_resets(
        mut self, streams: List[UInt16], var response: List[UInt8]
    ) raises:
        for s in streams:
            self._receiver.reset_stream(s)
            var ev = SctpEvent(SCTP_EVENT_STREAM_RESET)
            ev.stream_id = s
            self._push_event(ev^)
        self._push_chunk(response^)

    def _after_cumulative_change(mut self) raises:
        # A reset request of the peer may have waited for missing data.
        var streams = List[UInt16]()
        var response = self._reset.on_cumulative_tsn(
            self._receiver.cumulative_tsn(),
            len(self._events) < self._cfg.max_queued_events,
            streams,
        )
        self._apply_resets(streams, response^)

    # ---------------------------------------------------------------- send

    def _on_sack(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        if not (
            self._can_send_data() or self._state == SCTP_STATE_SHUTDOWN_SENT
        ):
            self._stats.chunks_dropped += 1
            return
        var sack = decode_sack(value)
        if not self._sender.on_sack(sack, now_ms):
            self._abort_with(
                CAUSE_PROTOCOL_VIOLATION,
                "peer acknowledged a TSN that was never sent",
            )
            return
        # Any valid SACK shows the peer is alive, also while its window is
        # closed and probes go unacknowledged.
        self._error_count = 0

    def _poll_transmit(mut self, now_ms: Int) raises -> Optional[List[UInt8]]:
        if len(self._ctrl_packets) > 0:
            var ready = self._ctrl_packets.popleft()
            self._stats.packets_out += 1
            self._stats.bytes_out += len(ready)
            return ready^
        if self._ended or not self._peer_known:
            return None
        self._pump_reconfig(now_ms)
        var mtu = self._cfg.mtu
        var out = List[UInt8](capacity=mtu)
        begin_packet(
            out, self._cfg.local_port, self._cfg.remote_port, self._peer_tag
        )
        var chunks = 0
        if self._send_cookie_echo and self._state == SCTP_STATE_COOKIE_ECHOED:
            encode_cookie_echo(out, Span(self._cookie_echo))
            self._send_cookie_echo = False
            chunks += 1
        while len(self._ctrl_chunks) > 0:
            if chunks > 0 and len(out) + len(self._ctrl_chunks[0]) > mtu:
                break
            var chunk = self._ctrl_chunks.popleft()
            out.extend(Span(chunk))
            chunks += 1
        if self._sack_needed:
            var sack = self._receiver.build_sack(self._event_bytes)
            if chunks == 0 or len(out) + sack.encoded_size() <= mtu:
                sack.encode(out)
                self._sack_needed = False
                chunks += 1
            else:
                # Keep the duplicate reports for the SACK in the next packet.
                self._receiver.keep_duplicates(sack)
        if self._can_send_data():
            chunks += self._sender.fill(out, mtu, now_ms)
        if chunks == 0:
            return None
        finish_packet(out)
        self._stats.packets_out += 1
        self._stats.bytes_out += len(out)
        return out^

    # ------------------------------------------------------------ reconfig

    def _pump_reconfig(mut self, now_ms: Int):
        if self._state != SCTP_STATE_ESTABLISHED:
            return
        if self._reset.start_request(self._sender, self._peer_reconfig):
            self._push_chunk(self._reset.request_chunk())
            self._reset.timer.start(now_ms + self._sender.rto.rto())

    def _on_reconfig(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        if not (
            self._state == SCTP_STATE_ESTABLISHED
            or self._state == SCTP_STATE_SHUTDOWN_PENDING
            or self._state == SCTP_STATE_SHUTDOWN_RECEIVED
        ):
            self._stats.chunks_dropped += 1
            return
        var params = decode_reconfig(value)
        for i in range(len(params)):
            if params[i].kind == PARAM_RECONFIG_RESPONSE:
                var outcome = self._reset.on_response(
                    params[i].request_seq, params[i].result, self._sender
                )
                if outcome == RESET_RESPONSE_IGNORED:
                    continue
                # Any answer to our request shows the peer is alive.
                self._error_count = 0
                if outcome == RESET_RESPONSE_IN_PROGRESS:
                    self._reset.timer.start(now_ms + self._sender.rto.rto())
                continue
            var streams = List[UInt16]()
            var response = self._reset.on_request(
                params[i],
                self._receiver.cumulative_tsn(),
                len(self._events) < self._cfg.max_queued_events,
                self._state == SCTP_STATE_ESTABLISHED,
                self._sender,
                streams,
            )
            self._apply_resets(streams, response^)

    # ------------------------------------------------- shutdown and errors

    def _send_shutdown_chunk(mut self):
        var chunk = List[UInt8]()
        if self._state == SCTP_STATE_SHUTDOWN_SENT:
            encode_shutdown(chunk, self._receiver.cumulative_tsn())
        elif self._state == SCTP_STATE_SHUTDOWN_ACK_SENT:
            encode_shutdown_ack(chunk)
        else:
            return
        self._push_chunk(chunk^)

    def _progress_shutdown(mut self, now_ms: Int):
        if not self._sender.is_drained():
            return
        if self._state == SCTP_STATE_SHUTDOWN_PENDING:
            self._state = SCTP_STATE_SHUTDOWN_SENT
        elif self._state == SCTP_STATE_SHUTDOWN_RECEIVED:
            self._state = SCTP_STATE_SHUTDOWN_ACK_SENT
        else:
            return
        self._reset.timer.stop()
        self._send_shutdown_chunk()
        self._t2.start(now_ms + self._sender.rto.rto())

    def _on_shutdown(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        var cum = decode_shutdown(value)
        if not (
            self._state == SCTP_STATE_ESTABLISHED
            or self._state == SCTP_STATE_SHUTDOWN_PENDING
            or self._state == SCTP_STATE_SHUTDOWN_RECEIVED
            or self._state == SCTP_STATE_SHUTDOWN_SENT
        ):
            self._stats.chunks_dropped += 1
            return
        var sack = SackChunk(cum, UInt32(self._sender.peer_rwnd()))
        if not self._sender.on_sack(sack, now_ms):
            self._abort_with(
                CAUSE_PROTOCOL_VIOLATION,
                "peer acknowledged a TSN that was never sent",
            )
            return
        self._error_count = 0
        if self._state == SCTP_STATE_SHUTDOWN_SENT:
            # Both ends shut down at once.
            self._state = SCTP_STATE_SHUTDOWN_ACK_SENT
            self._send_shutdown_chunk()
            self._t2.start(now_ms + self._sender.rto.rto())
        elif self._state != SCTP_STATE_SHUTDOWN_RECEIVED:
            self._state = SCTP_STATE_SHUTDOWN_RECEIVED

    def _on_abort(mut self, value: Span[UInt8, _]):
        self._close(abort_reason(value))

    def _on_error(mut self, value: Span[UInt8, _], now_ms: Int) raises:
        var causes = decode_causes(value)
        for i in range(len(causes)):
            if (
                causes[i].code == CAUSE_STALE_COOKIE
                and self._state == SCTP_STATE_COOKIE_ECHOED
            ):
                # Our cookie expired on the way: start over with a new INIT.
                self._state = SCTP_STATE_COOKIE_WAIT
                self._send_cookie_echo = False
                self._queue_init()
                self._t1.start(now_ms + self._cfg.rto_initial_ms)
                return
