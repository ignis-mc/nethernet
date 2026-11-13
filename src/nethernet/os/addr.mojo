"""IPv4 socket addresses."""


@fieldwise_init
struct SocketAddr(Equatable, Hashable, ImplicitlyCopyable, Writable):
    """An IPv4 address and port, both in host byte order."""

    var ip: UInt32
    """The IPv4 address with the first octet in the top byte."""
    var port: UInt16
    """The port number."""

    @staticmethod
    def v4(a: UInt8, b: UInt8, c: UInt8, d: UInt8, port: UInt16) -> Self:
        """Builds an address from four octets and a port.

        Args:
            a: The first octet.
            b: The second octet.
            c: The third octet.
            d: The fourth octet.
            port: The port number.

        Returns:
            The address `a.b.c.d:port`.
        """
        return Self(
            (UInt32(a) << 24)
            | (UInt32(b) << 16)
            | (UInt32(c) << 8)
            | UInt32(d),
            port,
        )

    @staticmethod
    def parse_ip(text: StringSpan) raises -> UInt32:
        """Parses a dotted-quad IPv4 address.

        Args:
            text: The address, for example `192.168.1.10`.

        Returns:
            The address with the first octet in the top byte.

        Raises:
            Error: If `text` is not four decimal octets separated by dots.
        """
        var bytes = text.as_bytes()
        var ip = UInt32(0)
        var octet = 0
        var digits = 0
        var parts = 0
        for c in bytes:
            if c >= 0x30 and c <= 0x39:
                octet = octet * 10 + Int(c - 0x30)
                digits += 1
                if digits > 3 or octet > 255:
                    raise Error("invalid IPv4 address")
            elif c == 0x2E:
                if digits == 0 or parts >= 3:
                    raise Error("invalid IPv4 address")
                ip = (ip << 8) | UInt32(octet)
                octet = 0
                digits = 0
                parts += 1
            else:
                raise Error("invalid IPv4 address")
        if digits == 0 or parts != 3:
            raise Error("invalid IPv4 address")
        return (ip << 8) | UInt32(octet)

    @staticmethod
    def parse(text: StringSpan) raises -> Self:
        """Parses `a.b.c.d:port`.

        Args:
            text: The address and port separated by a colon.

        Returns:
            The parsed address.

        Raises:
            Error: If the address or port is malformed.
        """
        var bytes = text.as_bytes()
        var colon = -1
        for i in range(len(bytes)):
            if bytes[i] == 0x3A:
                colon = i
        if colon < 0:
            raise Error("missing port in socket address")
        var port = 0
        if colon + 1 >= len(bytes):
            raise Error("invalid port")
        for i in range(colon + 1, len(bytes)):
            var c = bytes[i]
            if c < 0x30 or c > 0x39:
                raise Error("invalid port")
            port = port * 10 + Int(c - 0x30)
            if port > 65535:
                raise Error("invalid port")
        var ip = Self.parse_ip(StringSpan(unsafe_from_utf8=bytes[0:colon]))
        return Self(ip, UInt16(port))

    def ip_string(self) -> String:
        """Formats the address part as a dotted quad.

        Returns:
            The address, for example `192.168.1.10`.
        """
        return String(
            t"{self.ip >> 24}.{(self.ip >> 16) & 0xFF}.{(self.ip >> 8) & 0xFF}.{self.ip & 0xFF}"
        )

    def is_loopback(self) -> Bool:
        """Checks whether the address is in `127.0.0.0/8`.

        Returns:
            `True` for loopback addresses.
        """
        return (self.ip >> 24) == 127

    def write_to(self, mut writer: Some[Writer]):
        """Writes the address as `a.b.c.d:port`.

        Args:
            writer: The destination.
        """
        writer.write(self.ip_string(), ":", self.port)
