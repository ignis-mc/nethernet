"""ICE candidate lines as NetherNet signals them.

A candidate travels either as the data of a `CANDIDATEADD` signal, with a
`candidate:` prefix, or as the value of an SDP `a=candidate:` attribute,
without it. Only IPv4 UDP candidates are usable by this library; others parse
as errors that callers skip.
"""

from ..crypto.crc import crc32
from ..os.addr import SocketAddr

comptime ICE_HOST_PRIORITY = 2130706431
"""Priority of a host candidate: type preference 126, local preference 65535."""
comptime ICE_PRFLX_PRIORITY = 1862270975
"""Priority of a peer-reflexive candidate: type preference 110."""


struct IceCandidate(Copyable):
    """One ICE candidate."""

    var foundation: String
    """The foundation, at most 32 characters."""
    var component: Int
    """The component ID; always 1 for data channels."""
    var priority: UInt32
    """The candidate priority."""
    var addr: SocketAddr
    """The transport address."""
    var kind: String
    """The candidate type: `host`, `srflx`, `prflx` or `relay`."""
    var related: Optional[SocketAddr]
    """The related address (`raddr`/`rport`), if any."""

    def __init__(
        out self,
        foundation: StringSpan,
        priority: UInt32,
        addr: SocketAddr,
        kind: StringSpan,
    ):
        """Creates a component-1 UDP candidate.

        Args:
            foundation: The foundation string.
            priority: The candidate priority.
            addr: The transport address.
            kind: The candidate type.
        """
        self.foundation = String(foundation)
        self.component = 1
        self.priority = priority
        self.addr = addr
        self.kind = String(kind)
        self.related = None

    @staticmethod
    def host(addr: SocketAddr) -> IceCandidate:
        """Creates a host candidate for a local socket address.

        The foundation is the decimal CRC-32 of the type, address and
        transport, which is how pion derives it.

        Args:
            addr: The bound local address.

        Returns:
            The host candidate.
        """
        var seed = String(t"host{addr.ip_string()}udp")
        var foundation = String(crc32(seed.as_bytes()))
        return IceCandidate(foundation, ICE_HOST_PRIORITY, addr, "host")

    def attribute_value(self, ufrag: StringSpan, network_id: Int) -> String:
        """Formats the candidate as an SDP attribute value.

        Args:
            ufrag: The local ICE username fragment.
            network_id: The index of the candidate among the local ones.

        Returns:
            The text that follows `a=candidate:`.
        """
        var out = String(
            t"{self.foundation} {self.component} udp {self.priority}"
            t" {self.addr.ip_string()} {self.addr.port} typ {self.kind}"
        )
        if case .Some(rel) = self.related:
            out += String(t" raddr {rel.ip_string()} rport {rel.port}")
        out += String(
            t" generation 0 ufrag {ufrag} network-id {network_id}"
            t" network-cost 0"
        )
        return out

    def signal_value(self, ufrag: StringSpan, network_id: Int) -> String:
        """Formats the candidate as `CANDIDATEADD` signal data.

        Args:
            ufrag: The local ICE username fragment.
            network_id: The index of the candidate among the local ones.

        Returns:
            The candidate line with its `candidate:` prefix.
        """
        return "candidate:" + self.attribute_value(ufrag, network_id)


def _split_spaces(text: StringSpan) -> List[String]:
    var out = List[String]()
    var bytes = text.as_bytes()
    var start = -1
    for i in range(len(bytes)):
        var is_space = bytes[i] == 0x20 or bytes[i] == 0x09
        if is_space:
            if start >= 0:
                out.append(String(unsafe_from_utf8=bytes[start:i]))
                start = -1
        elif start < 0:
            start = i
    if start >= 0:
        out.append(String(unsafe_from_utf8=bytes[start : len(bytes)]))
    return out^


def _parse_uint(text: StringSpan, max_digits: Int) raises -> UInt64:
    var bytes = text.as_bytes()
    if len(bytes) == 0 or len(bytes) > max_digits:
        raise Error("invalid number in candidate")
    var v = UInt64(0)
    for c in bytes:
        if c < 0x30 or c > 0x39:
            raise Error("invalid number in candidate")
        v = v * 10 + UInt64(c - 0x30)
    return v


def parse_candidate(text: StringSpan) raises -> IceCandidate:
    """Parses a candidate line.

    Accepts the forms `a=candidate:…`, `candidate:…` and the bare attribute
    value. Unknown extension pairs are ignored.

    Args:
        text: The candidate line.

    Returns:
        The parsed candidate.

    Raises:
        Error: If the line is malformed, or the candidate is not a UDP
            candidate with an IPv4 address (TCP, IPv6 and mDNS hostnames).
    """
    var s = text.strip()
    if s.startswith("a="):
        s = s[byte = 2 : s.byte_length()]
    if s.startswith("candidate:"):
        s = s[byte = 10 : s.byte_length()]
    var f = _split_spaces(s)
    if len(f) < 8:
        raise Error("candidate has too few fields")
    if f[0].byte_length() > 32:
        raise Error("candidate foundation too long")
    var component = Int(_parse_uint(f[1], 5))
    var transport = f[2].lower()
    if transport != "udp":
        raise Error("unsupported candidate transport")
    var priority = _parse_uint(f[3], 10)
    if priority > 0xFFFF_FFFF:
        raise Error("candidate priority out of range")
    var ip = SocketAddr.parse_ip(f[4])
    var port = _parse_uint(f[5], 5)
    if port > 65535:
        raise Error("candidate port out of range")
    if f[6] != "typ":
        raise Error("candidate is missing 'typ'")
    var kind = f[7].copy()
    if (
        kind != "host"
        and kind != "srflx"
        and kind != "prflx"
        and kind != "relay"
    ):
        raise Error("unknown candidate type")
    var cand = IceCandidate(
        f[0], UInt32(priority), SocketAddr(ip, UInt16(port)), kind
    )
    cand.component = component
    var i = 8
    var raddr: Optional[UInt32] = None
    while i + 1 < len(f):
        if f[i] == "raddr":
            try:
                raddr = SocketAddr.parse_ip(f[i + 1])
            except:
                raddr = None
        elif f[i] == "rport":
            if case .Some(rip) = raddr:
                var rport = _parse_uint(f[i + 1], 5)
                if rport <= 65535:
                    cand.related = SocketAddr(rip, UInt16(rport))
        i += 2
    return cand^
