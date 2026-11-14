"""Configuration, events and counters of an SCTP association."""

comptime SCTP_STATE_CLOSED = 0
"""No association exists, or it has ended."""
comptime SCTP_STATE_COOKIE_WAIT = 1
"""An INIT was sent and the INIT ACK is awaited."""
comptime SCTP_STATE_COOKIE_ECHOED = 2
"""A COOKIE ECHO was sent and the COOKIE ACK is awaited."""
comptime SCTP_STATE_ESTABLISHED = 3
"""The association is up and carries data."""
comptime SCTP_STATE_SHUTDOWN_PENDING = 4
"""A local shutdown waits for outstanding data to be acknowledged."""
comptime SCTP_STATE_SHUTDOWN_SENT = 5
"""A SHUTDOWN was sent and the SHUTDOWN ACK is awaited."""
comptime SCTP_STATE_SHUTDOWN_RECEIVED = 6
"""The peer sent SHUTDOWN; outstanding data is being flushed."""
comptime SCTP_STATE_SHUTDOWN_ACK_SENT = 7
"""A SHUTDOWN ACK was sent and the SHUTDOWN COMPLETE is awaited."""

comptime SCTP_EVENT_CONNECTED = 1
"""The association reached the established state."""
comptime SCTP_EVENT_MESSAGE = 2
"""A complete user message was reassembled."""
comptime SCTP_EVENT_STREAM_RESET = 3
"""The peer reset its outgoing stream `stream_id` (incoming for us)."""
comptime SCTP_EVENT_CLOSED = 4
"""The association ended; `reason` says why."""


struct SctpConfig(Copyable):
    """The parameters of one SCTP association.

    The association does no I/O and has no entropy source, so the caller
    supplies the random values.
    """

    var local_port: UInt16
    """The SCTP source port; 5000 for WebRTC data channels."""
    var remote_port: UInt16
    """The SCTP destination port; 5000 for WebRTC data channels."""
    var local_tag: UInt32
    """The local initiate tag: random and non-zero."""
    var initial_tsn: UInt32
    """The first TSN to send: random."""
    var cookie_secret: List[UInt8]
    """Random bytes that authenticate State Cookies."""
    var a_rwnd: UInt32
    """The advertised receive window in bytes."""
    var mtu: Int
    """The largest SCTP packet to emit, in bytes."""
    var max_message_size: Int
    """The largest user message accepted for sending or receiving."""
    var num_outbound_streams: UInt16
    """The number of outbound streams to request."""
    var num_inbound_streams: UInt16
    """The number of inbound streams to accept."""
    var rto_initial_ms: Int
    """The retransmission timeout before the first RTT measurement."""
    var rto_min_ms: Int
    """The smallest retransmission timeout."""
    var rto_max_ms: Int
    """The largest retransmission timeout."""
    var max_init_retransmits: Int
    """How often an INIT or COOKIE ECHO is retransmitted before giving up."""
    var max_retransmits: Int
    """Consecutive unanswered timer expiries that end the association."""
    var cookie_lifetime_ms: Int
    """How long a State Cookie stays valid."""
    var max_queued_events: Int
    """The number of unread events after which inbound data is refused."""
    var max_tsn_gap: Int
    """How far past the cumulative TSN a DATA chunk may be and be kept."""

    def __init__(
        out self,
        local_tag: UInt32,
        initial_tsn: UInt32,
        cookie_secret: Span[UInt8, _],
    ):
        """Creates a configuration with WebRTC defaults.

        Ports are 5000, the receive window is 1 MiB, the MTU 1200 bytes, the
        message limit 262144 bytes, 65535 streams each way, and the timers
        follow RFC 9260 (RTO 1 s initial and minimum, 60 s maximum, 8 INIT
        retransmissions, 10 data retransmissions).
        """
        self.local_port = 5000
        self.remote_port = 5000
        self.local_tag = local_tag
        self.initial_tsn = initial_tsn
        self.cookie_secret = List[UInt8](cookie_secret)
        self.a_rwnd = 1048576
        self.mtu = 1200
        self.max_message_size = 262144
        self.num_outbound_streams = 65535
        self.num_inbound_streams = 65535
        self.rto_initial_ms = 1000
        self.rto_min_ms = 1000
        self.rto_max_ms = 60000
        self.max_init_retransmits = 8
        self.max_retransmits = 10
        self.cookie_lifetime_ms = 60000
        self.max_queued_events = 4096
        self.max_tsn_gap = 16384


struct SctpEvent(Copyable):
    """Something the association reports to its user."""

    var kind: Int
    """One of the `SCTP_EVENT_*` values."""
    var stream_id: UInt16
    """The stream of a message or a stream reset."""
    var ppid: UInt32
    """The payload protocol identifier of a message."""
    var unordered: Bool
    """Whether a message was sent unordered."""
    var payload: List[UInt8]
    """The user data of a message; empty for other events."""
    var reason: String
    """Why the association closed; empty for other events."""

    def __init__(out self, kind: Int):
        """Creates an event with every other field empty."""
        self.kind = kind
        self.stream_id = 0
        self.ppid = 0
        self.unordered = False
        self.payload = List[UInt8]()
        self.reason = String("")


struct SctpStats(ImplicitlyCopyable):
    """Counters of one association."""

    var packets_in: Int
    """Packets handed to `handle_packet()`."""
    var packets_out: Int
    """Packets returned by `poll_transmit()`."""
    var bytes_in: Int
    """Bytes of all inbound packets."""
    var bytes_out: Int
    """Bytes of all outbound packets."""
    var packets_dropped: Int
    """Inbound packets discarded: malformed, bad checksum, port or tag."""
    var chunks_dropped: Int
    """Inbound chunks discarded: malformed, unexpected or out of window."""
    var data_chunks_in: Int
    """DATA chunks accepted, duplicates excluded."""
    var data_chunks_out: Int
    """DATA chunks sent, retransmissions excluded."""
    var duplicate_tsns: Int
    """DATA chunks received more than once."""
    var messages_in: Int
    """User messages delivered."""
    var messages_out: Int
    """User messages accepted by `send()`."""
    var retransmits: Int
    """DATA chunks retransmitted."""
    var fast_retransmits: Int
    """DATA chunks marked for fast retransmission."""
    var t3_expiries: Int
    """Expiries of the data retransmission timer."""
    var abandoned_chunks: Int
    """DATA chunks given up under a retransmission limit."""
    var forward_tsns_out: Int
    """FORWARD-TSN chunks sent."""
    var loss_probes: Int
    """Tail loss probes sent."""
    var rack_losses: Int
    """DATA chunks found lost because a later transmission was acked."""

    def __init__(out self):
        """Creates counters that are all zero."""
        self.packets_in = 0
        self.packets_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.packets_dropped = 0
        self.chunks_dropped = 0
        self.data_chunks_in = 0
        self.data_chunks_out = 0
        self.duplicate_tsns = 0
        self.messages_in = 0
        self.messages_out = 0
        self.retransmits = 0
        self.fast_retransmits = 0
        self.t3_expiries = 0
        self.abandoned_chunks = 0
        self.forward_tsns_out = 0
        self.loss_probes = 0
        self.rack_losses = 0
