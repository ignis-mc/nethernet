"""The State Cookie an association hands out in its INIT ACK.

The cookie carries everything needed to create the association once the peer
echoes it, so that an INIT allocates no state (RFC 9260 section 5.1.3). It is
authenticated with HMAC-SHA-256 under a secret only this endpoint knows.
"""

from ..crypto.ct import constant_time_eq
from ..crypto.hmac import hmac
from ..crypto.sha256 import Sha256
from ..wire import Reader, put_bytes, put_u16, put_u32, put_u64, put_u8

comptime _COOKIE_VERSION = 1
comptime _COOKIE_BODY_SIZE = 36
comptime COOKIE_SIZE = 68
"""The size of an encoded State Cookie in bytes."""


struct CookieData(ImplicitlyCopyable):
    """The association parameters stored in a State Cookie."""

    var peer_tag: UInt32
    """The peer's initiate tag."""
    var peer_initial_tsn: UInt32
    """The peer's initial TSN."""
    var peer_a_rwnd: UInt32
    """The peer's advertised receiver window credit."""
    var peer_outbound_streams: UInt16
    """The number of outbound streams the peer asked for."""
    var peer_inbound_streams: UInt16
    """The number of inbound streams the peer accepts."""
    var peer_forward_tsn: Bool
    """Whether the peer supports FORWARD-TSN."""
    var peer_reconfig: Bool
    """Whether the peer supports RE-CONFIG."""
    var local_tag: UInt32
    """The initiate tag sent in the INIT ACK."""
    var local_initial_tsn: UInt32
    """The initial TSN sent in the INIT ACK."""
    var created_ms: Int
    """When the cookie was made, in the caller's monotonic milliseconds."""

    def __init__(out self):
        """Creates cookie data with every field zero."""
        self.peer_tag = 0
        self.peer_initial_tsn = 0
        self.peer_a_rwnd = 0
        self.peer_outbound_streams = 0
        self.peer_inbound_streams = 0
        self.peer_forward_tsn = False
        self.peer_reconfig = False
        self.local_tag = 0
        self.local_initial_tsn = 0
        self.created_ms = 0


def encode_cookie(data: CookieData, secret: Span[UInt8, _]) -> List[UInt8]:
    """Serializes and authenticates a State Cookie.

    Args:
        data: The association parameters to store.
        secret: The key for the authentication tag.

    Returns:
        The `COOKIE_SIZE`-byte cookie.
    """
    var out = List[UInt8](capacity=COOKIE_SIZE)
    var flags = UInt8(0)
    if data.peer_forward_tsn:
        flags |= 1
    if data.peer_reconfig:
        flags |= 2
    put_u8(out, _COOKIE_VERSION)
    put_u8(out, flags)
    put_u16(out, 0)
    put_u16(out, data.peer_outbound_streams)
    put_u16(out, data.peer_inbound_streams)
    put_u32(out, data.peer_tag)
    put_u32(out, data.peer_initial_tsn)
    put_u32(out, data.peer_a_rwnd)
    put_u32(out, data.local_tag)
    put_u32(out, data.local_initial_tsn)
    put_u64(out, UInt64(data.created_ms))
    var tag = hmac[Sha256](secret, Span(out))
    put_bytes(out, Span(tag))
    return out^


def decode_cookie(
    cookie: Span[UInt8, _], secret: Span[UInt8, _]
) raises -> CookieData:
    """Authenticates and parses a State Cookie.

    Args:
        cookie: The cookie carried by a COOKIE ECHO.
        secret: The key the cookie was authenticated with.

    Returns:
        The stored association parameters.

    Raises:
        Error: If the size, version or authentication tag is wrong.
    """
    if len(cookie) != COOKIE_SIZE:
        raise Error("sctp: cookie has the wrong size")
    var body = cookie[0:_COOKIE_BODY_SIZE]
    var tag = hmac[Sha256](secret, body)
    if not constant_time_eq(Span(tag), cookie[_COOKIE_BODY_SIZE:COOKIE_SIZE]):
        raise Error("sctp: cookie authentication failed")
    var r = Reader(body)
    if r.u8() != _COOKIE_VERSION:
        raise Error("sctp: unknown cookie version")
    var flags = r.u8()
    r.skip(2)
    var data = CookieData()
    data.peer_forward_tsn = (flags & 1) != 0
    data.peer_reconfig = (flags & 2) != 0
    data.peer_outbound_streams = r.u16()
    data.peer_inbound_streams = r.u16()
    data.peer_tag = r.u32()
    data.peer_initial_tsn = r.u32()
    data.peer_a_rwnd = r.u32()
    data.local_tag = r.u32()
    data.local_initial_tsn = r.u32()
    data.created_ms = Int(r.u64())
    return data
