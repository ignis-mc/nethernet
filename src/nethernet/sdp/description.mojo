"""NetherNet session descriptions.

NetherNet does not run full JSEP. Each side sends one SDP document with a
single `m=application` section describing its ICE credentials, DTLS
fingerprint and role, and SCTP message size. This module writes that document
the way go-nethernet and Minecraft do and reads the fields they read; every
other line is ignored.
"""

from ..wire import hex_decode

comptime DEFAULT_MAX_MESSAGE_SIZE = 262144
"""The `a=max-message-size` NetherNet peers advertise."""
comptime SCTP_PORT = 5000
"""The SCTP port used on both ends, carried in `a=sctp-port`."""

comptime SETUP_ACTPASS: StaticString = "actpass"
comptime SETUP_ACTIVE: StaticString = "active"
comptime SETUP_PASSIVE: StaticString = "passive"


struct Description(Copyable):
    """The negotiable parameters of one end of a NetherNet connection."""

    var session_id: UInt64
    """The numeric session identifier in the `o=` line."""
    var ice_ufrag: String
    """The ICE username fragment."""
    var ice_pwd: String
    """The ICE password."""
    var fingerprint_algorithm: String
    """The certificate hash name as written, normally `sha-256`.

    The identity assertion signs this exact text, so it is not normalised.
    """
    var fingerprint: String
    """The certificate hash as colon-separated hex."""
    var setup: String
    """The DTLS role: `actpass`, `active` or `passive`."""
    var max_message_size: Int
    """The largest SCTP user message this end accepts."""
    var identity: String
    """The base64 `a=identity` assertion, or empty."""
    var candidates: List[String]
    """Candidate attribute values embedded in the document (non-trickle)."""

    def __init__(out self):
        """Creates an empty description with NetherNet defaults."""
        self.session_id = 0
        self.ice_ufrag = String()
        self.ice_pwd = String()
        self.fingerprint_algorithm = "sha-256"
        self.fingerprint = String()
        self.setup = SETUP_ACTPASS
        self.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        self.identity = String()
        self.candidates = List[String]()

    def encode(self) -> String:
        """Formats the description as an SDP document with CRLF line endings.

        Embedded candidates are written as `a=candidate` lines, and the first
        one supplies the address and port of the `c=` and `m=` lines.

        Returns:
            The SDP text.
        """
        var port = String("9")
        var address = String("0.0.0.0")
        if len(self.candidates) > 0:
            # "<foundation> <component> <transport> <priority> <ip> <port> …"
            var fields = self.candidates[0].split(" ")
            if len(fields) >= 6:
                address = String(fields[4])
                port = String(fields[5])
        var out = String()
        out += "v=0\r\n"
        out += String(t"o=- {self.session_id} 2 IN IP4 127.0.0.1\r\n")
        out += "s=-\r\n"
        out += "t=0 0\r\n"
        out += "a=group:BUNDLE 0\r\n"
        out += "a=extmap-allow-mixed\r\n"
        out += "a=msid-semantic: WMS\r\n"
        if self.identity.byte_length() > 0:
            out += String(t"a=identity:{self.identity}\r\n")
        out += String(
            t"m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\n"
        )
        out += String(t"c=IN IP4 {address}\r\n")
        for c in self.candidates:
            out += String(t"a=candidate:{c}\r\n")
        out += String(t"a=ice-ufrag:{self.ice_ufrag}\r\n")
        out += String(t"a=ice-pwd:{self.ice_pwd}\r\n")
        out += "a=ice-options:trickle\r\n"
        out += String(
            t"a=fingerprint:{self.fingerprint_algorithm} {self.fingerprint}\r\n"
        )
        out += String(t"a=setup:{self.setup}\r\n")
        out += "a=mid:0\r\n"
        out += String(t"a=sctp-port:{SCTP_PORT}\r\n")
        out += String(t"a=max-message-size:{self.max_message_size}\r\n")
        return out

    def fingerprint_bytes(self) raises -> List[UInt8]:
        """Decodes the colon-separated fingerprint into raw digest bytes.

        Returns:
            The digest bytes.

        Raises:
            Error: If the fingerprint is not colon-separated hex bytes.
        """
        var hex = String()
        var parts = self.fingerprint.split(":")
        for p in parts:
            if p.byte_length() != 2:
                raise Error("SDP: malformed fingerprint")
            hex += String(p)
        return hex_decode(hex)


def _parse_decimal(text: StringSpan) raises -> UInt64:
    var bytes = text.as_bytes()
    if len(bytes) == 0 or len(bytes) > 19:
        raise Error("SDP: invalid number")
    var v = UInt64(0)
    for c in bytes:
        if c < 0x30 or c > 0x39:
            raise Error("SDP: invalid number")
        v = v * 10 + UInt64(c - 0x30)
    return v


def parse_description(text: StringSpan) raises -> Description:
    """Reads a NetherNet session description.

    Follows what go-nethernet accepts: exactly one media section;
    `ice-ufrag`, `ice-pwd`, `setup` and `max-message-size` at media level;
    `fingerprint` at media level or else session level; `identity` at session
    level; `candidate` at either level. Unknown lines are ignored.

    Args:
        text: The SDP document, with LF or CRLF line endings.

    Returns:
        The parsed description.

    Raises:
        Error: If a required attribute is missing or malformed.
    """
    var d = Description()
    d.max_message_size = 0
    var media_sections = 0
    var session_fingerprint = String()
    var media_fingerprint = String()
    var have_setup = False
    var lines = text.split("\n")
    for raw in lines:
        var line = raw.strip()
        if line.byte_length() < 2:
            continue
        if line.startswith("m="):
            media_sections += 1
            continue
        if line.startswith("o="):
            var fields = line.split(" ")
            if len(fields) >= 2:
                try:
                    d.session_id = _parse_decimal(fields[1])
                except:
                    d.session_id = 0
            continue
        if not line.startswith("a="):
            continue
        var attr = line[byte=2 : line.byte_length()]
        var key = attr
        var value = attr[byte=0:0]
        var colon = attr.find(":")
        if colon >= 0:
            key = attr[byte=0:colon]
            value = attr[byte=colon + 1 : attr.byte_length()]
        var in_media = media_sections > 0
        if key == "candidate":
            d.candidates.append(String(value))
        elif key == "fingerprint":
            if in_media:
                media_fingerprint = String(value)
            else:
                session_fingerprint = String(value)
        elif key == "identity":
            if not in_media:
                d.identity = String(value)
        elif not in_media:
            continue
        elif key == "ice-ufrag":
            d.ice_ufrag = String(value)
        elif key == "ice-pwd":
            d.ice_pwd = String(value)
        elif key == "setup":
            if (
                value != SETUP_ACTPASS
                and value != SETUP_ACTIVE
                and value != SETUP_PASSIVE
            ):
                raise Error("SDP: unknown setup role")
            d.setup = String(value)
            have_setup = True
        elif key == "max-message-size":
            var n = _parse_decimal(value)
            if n <= 1 or n > 0xFFFF_FFFF:
                raise Error("SDP: max-message-size out of range")
            d.max_message_size = Int(n)
    if media_sections != 1:
        raise Error("SDP: expected exactly one media section")
    if d.ice_ufrag.byte_length() == 0 or d.ice_pwd.byte_length() == 0:
        raise Error("SDP: missing ICE credentials")
    var fp = media_fingerprint
    if fp.byte_length() == 0:
        fp = session_fingerprint
    var fp_fields = fp.split(" ")
    if len(fp_fields) != 2:
        raise Error("SDP: missing or malformed fingerprint")
    d.fingerprint_algorithm = String(fp_fields[0])
    d.fingerprint = String(fp_fields[1])
    if not have_setup:
        raise Error("SDP: missing setup attribute")
    if d.max_message_size == 0:
        raise Error("SDP: missing max-message-size")
    return d^
