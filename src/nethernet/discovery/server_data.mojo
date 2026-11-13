"""The world description a discovery response carries (`ServerData`, version 7)."""

from ..wire import Reader, put_bytes

comptime SERVER_DATA_VERSION = 7

comptime GAME_TYPE_SURVIVAL = 0
comptime GAME_TYPE_CREATIVE = 1
comptime GAME_TYPE_ADVENTURE = 2

comptime CONNECTION_TYPE_LAN_SIGNALING = 4
"""`connection_type` of a world reachable through LAN signaling."""


def _put_varuint32(mut out: List[UInt8], value: UInt32):
    var v = value
    while v >= 0x80:
        out.append(UInt8(v & 0x7F) | 0x80)
        v >>= 7
    out.append(UInt8(v))


def _put_varint32(mut out: List[UInt8], value: Int32):
    # Zigzag: small magnitudes of either sign stay short.
    var zz = (UInt32(value) << 1) ^ UInt32(value >> 31)
    _put_varuint32(out, zz)


def _put_string(mut out: List[UInt8], text: StringSpan):
    _put_varuint32(out, UInt32(text.byte_length()))
    put_bytes(out, text.as_bytes())


def _varuint32[o: ImmOrigin](mut r: Reader[o]) raises -> UInt32:
    var v = UInt32(0)
    for i in range(5):
        var b = r.u8()
        v |= UInt32(b & 0x7F) << UInt32(7 * i)
        if (b & 0x80) == 0:
            return v
    raise Error("server data: varint is too long")


def _varint32[o: ImmOrigin](mut r: Reader[o]) raises -> Int32:
    var zz = _varuint32(r)
    return Int32(zz >> 1) ^ -Int32(zz & 1)


def _string[o: ImmOrigin](mut r: Reader[o]) raises -> String:
    var n = Int(_varuint32(r))
    return String(unsafe_from_utf8=r.bytes(n))


def _bool[o: ImmOrigin](mut r: Reader[o]) raises -> Bool:
    return r.u8() != 0


struct ServerData(Copyable):
    """What a world announces about itself on the LAN."""

    var server_name: String
    """The host's display name."""
    var protocol: Int32
    """The Minecraft network protocol version."""
    var version: String
    """The game version string, for example `1.26.50`."""
    var level_name: String
    """The world name."""
    var player_count: Int32
    """The number of players online."""
    var max_player_count: Int32
    """The player limit."""
    var game_type: Int32
    """One of the `GAME_TYPE_*` constants."""
    var editor_world: Bool
    """Whether the world is an Editor world."""
    var hardcore: Bool
    """Whether the world is hardcore."""
    var accepts_online_auth: Bool
    """Whether Xbox-authenticated clients may join."""
    var accepts_self_signed_auth: Bool
    """Whether offline (self-signed) clients may join."""
    var nonce: String
    """An opaque value some hosts set."""
    var connection_type: Int32
    """How to connect; `CONNECTION_TYPE_LAN_SIGNALING` for LAN worlds."""

    def __init__(out self):
        """Creates a description with LAN-signaling defaults."""
        self.server_name = String()
        self.protocol = 0
        self.version = String()
        self.level_name = String()
        self.player_count = 0
        self.max_player_count = 0
        self.game_type = GAME_TYPE_SURVIVAL
        self.editor_world = False
        self.hardcore = False
        self.accepts_online_auth = True
        self.accepts_self_signed_auth = True
        self.nonce = String()
        self.connection_type = CONNECTION_TYPE_LAN_SIGNALING

    def encode(self) -> List[UInt8]:
        """Encodes the description.

        Returns:
            The bytes carried (hex-encoded) by a response packet.
        """
        var out = List[UInt8]()
        out.append(SERVER_DATA_VERSION)
        _put_string(out, self.server_name)
        _put_varint32(out, self.protocol)
        _put_string(out, self.version)
        _put_string(out, self.level_name)
        _put_varint32(out, self.player_count)
        _put_varint32(out, self.max_player_count)
        _put_varint32(out, self.game_type)
        out.append(UInt8(1) if self.editor_world else UInt8(0))
        out.append(UInt8(1) if self.hardcore else UInt8(0))
        out.append(UInt8(1) if self.accepts_online_auth else UInt8(0))
        out.append(UInt8(1) if self.accepts_self_signed_auth else UInt8(0))
        _put_string(out, self.nonce)
        _put_varint32(out, self.connection_type)
        return out^

    @staticmethod
    def decode(data: Span[UInt8, _]) raises -> ServerData:
        """Decodes a version 7 description.

        Args:
            data: The bytes from a response packet.

        Returns:
            The decoded description.

        Raises:
            Error: If the version is not 7, the data is truncated, or bytes
                are left over.
        """
        var r = Reader(data)
        var version = r.u8()
        if version != SERVER_DATA_VERSION:
            raise Error(t"server data: unsupported version {version}")
        var d = ServerData()
        d.server_name = _string(r)
        d.protocol = _varint32(r)
        d.version = _string(r)
        d.level_name = _string(r)
        d.player_count = _varint32(r)
        d.max_player_count = _varint32(r)
        d.game_type = _varint32(r)
        d.editor_world = _bool(r)
        d.hardcore = _bool(r)
        d.accepts_online_auth = _bool(r)
        d.accepts_self_signed_auth = _bool(r)
        d.nonce = _string(r)
        d.connection_type = _varint32(r)
        if not r.at_end():
            raise Error("server data: trailing bytes")
        return d^
