"""SCTP association over DTLS for WebRTC data channels.

`Association` is a sans-I/O implementation of the SCTP subset that data
channels need: RFC 9260 with a single path, RFC 3758 partial reliability
(FORWARD-TSN) and RFC 6525 stream reset (RE-CONFIG). The caller moves
packets between it and DTLS, supplies time as monotonic milliseconds and
random values through `SctpConfig`.
"""

from .association import Association
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
