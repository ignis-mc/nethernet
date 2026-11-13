"""STUN messages: parsing, building, MESSAGE-INTEGRITY and FINGERPRINT.

Only the Binding method and the attributes ICE uses are modelled. Unknown
attributes are preserved on parse and ignored.
"""

from ..crypto.crc import crc32
from ..crypto.ct import constant_time_eq
from ..crypto.hmac import hmac
from ..crypto.sha1 import Sha1
from ..os.addr import SocketAddr
from ..wire import Reader, put_bytes, put_u16, put_u32, put_u64, set_u16

comptime STUN_MAGIC_COOKIE = 0x2112A442
"""The fixed value in bytes 4 to 7 of every STUN message."""
comptime STUN_HEADER_LEN = 20
"""The size of the STUN header in bytes."""

comptime STUN_BINDING_REQUEST = 0x0001
"""Message type of a Binding request."""
comptime STUN_BINDING_INDICATION = 0x0011
"""Message type of a Binding indication."""
comptime STUN_BINDING_SUCCESS = 0x0101
"""Message type of a Binding success response."""
comptime STUN_BINDING_ERROR = 0x0111
"""Message type of a Binding error response."""

comptime STUN_ATTR_MAPPED_ADDRESS = 0x0001
"""Attribute type `MAPPED-ADDRESS`."""
comptime STUN_ATTR_USERNAME = 0x0006
"""Attribute type `USERNAME`."""
comptime STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
"""Attribute type `MESSAGE-INTEGRITY`."""
comptime STUN_ATTR_ERROR_CODE = 0x0009
"""Attribute type `ERROR-CODE`."""
comptime STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
"""Attribute type `XOR-MAPPED-ADDRESS`."""
comptime STUN_ATTR_PRIORITY = 0x0024
"""Attribute type `PRIORITY` (ICE)."""
comptime STUN_ATTR_USE_CANDIDATE = 0x0025
"""Attribute type `USE-CANDIDATE` (ICE)."""
comptime STUN_ATTR_FINGERPRINT = 0x8028
"""Attribute type `FINGERPRINT`."""
comptime STUN_ATTR_ICE_CONTROLLED = 0x8029
"""Attribute type `ICE-CONTROLLED`."""
comptime STUN_ATTR_ICE_CONTROLLING = 0x802A
"""Attribute type `ICE-CONTROLLING`."""

comptime STUN_ERROR_ROLE_CONFLICT = 487
"""Error code 487, Role Conflict (ICE)."""

comptime _FINGERPRINT_XOR = 0x5354554E


def is_stun(data: Span[UInt8, _]) -> Bool:
    """Checks whether a datagram looks like a STUN message.

    Used to demultiplex STUN from DTLS on one socket (RFC 7983): the first
    two bits are zero and the magic cookie is present.

    Args:
        data: The datagram.

    Returns:
        `True` if the datagram has a STUN header with the magic cookie.
    """
    if len(data) < STUN_HEADER_LEN:
        return False
    if (data[0] & 0xC0) != 0:
        return False
    return (
        data[4] == 0x21
        and data[5] == 0x12
        and data[6] == 0xA4
        and data[7] == 0x42
    )


@fieldwise_init
struct StunAttribute(Copyable):
    """One STUN attribute as a type and its unpadded value."""

    var kind: UInt16
    """The attribute type."""
    var value: List[UInt8]
    """The attribute value without padding."""


struct StunMessage(Copyable):
    """A decoded STUN message."""

    var msg_type: UInt16
    """The message type, for example `STUN_BINDING_REQUEST`."""
    var transaction_id: Array[UInt8, 12]
    """The 96-bit transaction identifier."""
    var attributes: List[StunAttribute]
    """The attributes in wire order."""

    def __init__(out self, msg_type: UInt16, transaction_id: Array[UInt8, 12]):
        """Creates a message with no attributes.

        Args:
            msg_type: The message type.
            transaction_id: The transaction identifier.
        """
        self.msg_type = msg_type
        self.transaction_id = transaction_id.copy()
        self.attributes = List[StunAttribute]()

    def find(self, kind: UInt16) -> Int:
        """Finds the first attribute of a type.

        Args:
            kind: The attribute type to look for.

        Returns:
            The index into `attributes`, or -1 if absent.
        """
        for i in range(len(self.attributes)):
            if self.attributes[i].kind == kind:
                return i
        return -1

    def has(self, kind: UInt16) -> Bool:
        """Checks whether an attribute is present.

        Args:
            kind: The attribute type to look for.

        Returns:
            `True` if at least one attribute of that type exists.
        """
        return self.find(kind) >= 0

    def username(self) -> Optional[String]:
        """Gets the USERNAME attribute.

        Returns:
            The username, or `None` if absent.
        """
        var i = self.find(STUN_ATTR_USERNAME)
        if i < 0:
            return None
        return String(from_utf8_lossy=Span(self.attributes[i].value))

    def priority(self) -> Optional[UInt32]:
        """Gets the ICE PRIORITY attribute.

        Returns:
            The priority, or `None` if absent or malformed.
        """
        var i = self.find(STUN_ATTR_PRIORITY)
        if i < 0 or len(self.attributes[i].value) != 4:
            return None
        ref v = self.attributes[i].value
        return (
            (UInt32(v[0]) << 24)
            | (UInt32(v[1]) << 16)
            | (UInt32(v[2]) << 8)
            | UInt32(v[3])
        )

    def _u64(self, kind: UInt16) -> Optional[UInt64]:
        var i = self.find(kind)
        if i < 0 or len(self.attributes[i].value) != 8:
            return None
        var out = UInt64(0)
        for b in self.attributes[i].value:
            out = (out << 8) | UInt64(b)
        return out

    def ice_controlling(self) -> Optional[UInt64]:
        """Gets the ICE-CONTROLLING tie-breaker.

        Returns:
            The tie-breaker, or `None` if absent or malformed.
        """
        return self._u64(STUN_ATTR_ICE_CONTROLLING)

    def ice_controlled(self) -> Optional[UInt64]:
        """Gets the ICE-CONTROLLED tie-breaker.

        Returns:
            The tie-breaker, or `None` if absent or malformed.
        """
        return self._u64(STUN_ATTR_ICE_CONTROLLED)

    def xor_mapped_address(self) -> Optional[SocketAddr]:
        """Gets the IPv4 XOR-MAPPED-ADDRESS attribute.

        Returns:
            The decoded address, or `None` if absent, malformed or IPv6.
        """
        var i = self.find(STUN_ATTR_XOR_MAPPED_ADDRESS)
        if i < 0 or len(self.attributes[i].value) != 8:
            return None
        ref v = self.attributes[i].value
        if v[1] != 0x01:
            return None
        var port = ((UInt16(v[2]) << 8) | UInt16(v[3])) ^ 0x2112
        var ip = (
            (UInt32(v[4]) << 24)
            | (UInt32(v[5]) << 16)
            | (UInt32(v[6]) << 8)
            | UInt32(v[7])
        ) ^ STUN_MAGIC_COOKIE
        return SocketAddr(ip, port)

    def error_code(self) -> Optional[Int]:
        """Gets the numeric code of the ERROR-CODE attribute.

        Returns:
            The code (for example 487), or `None` if absent or malformed.
        """
        var i = self.find(STUN_ATTR_ERROR_CODE)
        if i < 0 or len(self.attributes[i].value) < 4:
            return None
        ref v = self.attributes[i].value
        return Int(v[2] & 0x07) * 100 + Int(v[3])


def parse_stun(data: Span[UInt8, _]) raises -> StunMessage:
    """Decodes a STUN message.

    The integrity and fingerprint attributes are parsed but not verified; use
    `verify_message_integrity()` and `verify_fingerprint()` on the raw bytes.

    Args:
        data: The whole datagram.

    Returns:
        The decoded message.

    Raises:
        Error: If the header, the length field or an attribute is malformed.
    """
    if not is_stun(data):
        raise Error("not a STUN message")
    var r = Reader(data)
    var msg_type = r.u16()
    var length = Int(r.u16())
    r.skip(4)
    if length % 4 != 0 or length != len(data) - STUN_HEADER_LEN:
        raise Error("STUN length field does not match the datagram")
    var tid = Array[UInt8, 12](fill=0)
    var tid_bytes = r.bytes(12)
    for i in range(12):
        tid[i] = tid_bytes[i]
    var msg = StunMessage(msg_type, tid)
    while not r.at_end():
        var kind = r.u16()
        var alen = Int(r.u16())
        var value = r.bytes(alen)
        var pad = (4 - alen % 4) % 4
        r.skip(pad)
        msg.attributes.append(StunAttribute(kind, List[UInt8](value)))
    return msg^


def _attribute_offset(data: Span[UInt8, _], kind: UInt16) -> Int:
    """Finds the offset of an attribute header in raw message bytes, or -1."""
    var pos = STUN_HEADER_LEN
    while pos + 4 <= len(data):
        var k = (UInt16(data[pos]) << 8) | UInt16(data[pos + 1])
        var alen = (Int(data[pos + 2]) << 8) | Int(data[pos + 3])
        if k == kind:
            return pos
        pos += 4 + alen + (4 - alen % 4) % 4
    return -1


def verify_message_integrity(data: Span[UInt8, _], key: Span[UInt8, _]) -> Bool:
    """Checks the MESSAGE-INTEGRITY attribute of a raw message.

    The HMAC-SHA1 covers the message up to the attribute, with the header
    length rewritten to end at the attribute (RFC 8489 section 14.5).

    Args:
        data: The whole datagram, already known to be STUN.
        key: The short-term credential password.

    Returns:
        `True` if the attribute is present and matches.
    """
    var off = _attribute_offset(data, STUN_ATTR_MESSAGE_INTEGRITY)
    if off < 0 or off + 24 > len(data):
        return False
    if data[off + 2] != 0 or data[off + 3] != 20:
        return False
    var signed = List[UInt8](data[0:off])
    set_u16(signed, 2, UInt16(off + 24 - STUN_HEADER_LEN))
    var expected = hmac[Sha1](key, Span(signed))
    return constant_time_eq(Span(expected), data[off + 4 : off + 24])


def verify_fingerprint(data: Span[UInt8, _]) -> Bool:
    """Checks the FINGERPRINT attribute of a raw message.

    Args:
        data: The whole datagram, already known to be STUN.

    Returns:
        `True` if the last attribute is a FINGERPRINT that matches.
    """
    if len(data) < STUN_HEADER_LEN + 8:
        return False
    var off = len(data) - 8
    if (
        data[off] != 0x80
        or data[off + 1] != 0x28
        or data[off + 2] != 0
        or data[off + 3] != 4
    ):
        return False
    var expected = crc32(data[0:off]) ^ _FINGERPRINT_XOR
    var got = (
        (UInt32(data[off + 4]) << 24)
        | (UInt32(data[off + 5]) << 16)
        | (UInt32(data[off + 6]) << 8)
        | UInt32(data[off + 7])
    )
    return expected == got


struct StunBuilder(Movable):
    """Builds a STUN message attribute by attribute."""

    var _buf: List[UInt8]

    def __init__(out self, msg_type: UInt16, transaction_id: Array[UInt8, 12]):
        """Starts a message.

        Args:
            msg_type: The message type.
            transaction_id: The transaction identifier.
        """
        self._buf = List[UInt8](capacity=128)
        put_u16(self._buf, msg_type)
        put_u16(self._buf, 0)
        put_u32(self._buf, STUN_MAGIC_COOKIE)
        for i in range(12):
            self._buf.append(transaction_id[i])

    def add(mut self, kind: UInt16, value: Span[UInt8, _]):
        """Appends an attribute, padding it to four bytes.

        Args:
            kind: The attribute type.
            value: The attribute value.
        """
        put_u16(self._buf, kind)
        put_u16(self._buf, UInt16(len(value)))
        put_bytes(self._buf, value)
        for _ in range((4 - len(value) % 4) % 4):
            self._buf.append(0)

    def add_username(mut self, username: StringSpan):
        """Appends a USERNAME attribute.

        Args:
            username: The username, `remote-ufrag:local-ufrag` for ICE.
        """
        self.add(STUN_ATTR_USERNAME, username.as_bytes())

    def add_priority(mut self, priority: UInt32):
        """Appends an ICE PRIORITY attribute.

        Args:
            priority: The priority a peer-reflexive candidate would have.
        """
        var v = List[UInt8]()
        put_u32(v, priority)
        self.add(STUN_ATTR_PRIORITY, Span(v))

    def add_use_candidate(mut self):
        """Appends an empty USE-CANDIDATE attribute."""
        var v = List[UInt8]()
        self.add(STUN_ATTR_USE_CANDIDATE, Span(v))

    def add_ice_controlling(mut self, tie_breaker: UInt64):
        """Appends an ICE-CONTROLLING attribute.

        Args:
            tie_breaker: The agent's random tie-breaker.
        """
        var v = List[UInt8]()
        put_u64(v, tie_breaker)
        self.add(STUN_ATTR_ICE_CONTROLLING, Span(v))

    def add_ice_controlled(mut self, tie_breaker: UInt64):
        """Appends an ICE-CONTROLLED attribute.

        Args:
            tie_breaker: The agent's random tie-breaker.
        """
        var v = List[UInt8]()
        put_u64(v, tie_breaker)
        self.add(STUN_ATTR_ICE_CONTROLLED, Span(v))

    def add_xor_mapped_address(mut self, addr: SocketAddr):
        """Appends an IPv4 XOR-MAPPED-ADDRESS attribute.

        Args:
            addr: The reflexive transport address to report.
        """
        var v = List[UInt8]()
        v.append(0)
        v.append(0x01)
        put_u16(v, addr.port ^ 0x2112)
        put_u32(v, addr.ip ^ STUN_MAGIC_COOKIE)
        self.add(STUN_ATTR_XOR_MAPPED_ADDRESS, Span(v))

    def add_error_code(mut self, code: Int, reason: StringSpan):
        """Appends an ERROR-CODE attribute.

        Args:
            code: The error code, 300 to 699.
            reason: A short human-readable reason.
        """
        var v = List[UInt8]()
        v.append(0)
        v.append(0)
        v.append(UInt8(code // 100))
        v.append(UInt8(code % 100))
        put_bytes(v, reason.as_bytes())
        self.add(STUN_ATTR_ERROR_CODE, Span(v))

    def finish(
        mut self, integrity_key: Span[UInt8, _], fingerprint: Bool = True
    ) -> List[UInt8]:
        """Completes the message and returns its bytes.

        Args:
            integrity_key: The password for MESSAGE-INTEGRITY; an empty span
                omits the attribute.
            fingerprint: Whether to append a FINGERPRINT attribute.

        Returns:
            The encoded message. The builder is empty afterwards.
        """
        if len(integrity_key) > 0:
            set_u16(
                self._buf, 2, UInt16(len(self._buf) + 24 - STUN_HEADER_LEN)
            )
            var tag = hmac[Sha1](integrity_key, Span(self._buf))
            self.add(STUN_ATTR_MESSAGE_INTEGRITY, Span(tag))
        if fingerprint:
            set_u16(self._buf, 2, UInt16(len(self._buf) + 8 - STUN_HEADER_LEN))
            var crc = crc32(Span(self._buf)) ^ _FINGERPRINT_XOR
            var v = List[UInt8]()
            put_u32(v, crc)
            self.add(STUN_ATTR_FINGERPRINT, Span(v))
        set_u16(self._buf, 2, UInt16(len(self._buf) - STUN_HEADER_LEN))
        var out = List[UInt8]()
        swap(out, self._buf)
        return out^
