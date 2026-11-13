"""The LAN discovery datagram format.

A datagram is `HMAC-SHA256(key, payload) || AES-256-ECB(key, PKCS7(payload))`
with a fixed, publicly known key (the SHA-256 of `0xdeadbeef` as a
little-endian 64-bit integer). The encryption is obfuscation, not security.

The payload, little-endian throughout:

    u16  length         whole payload, including these two bytes
    u16  packet ID      0 request, 1 response, 2 message
    u64  sender network ID
    8    zero bytes
    ...  body
"""

from ..crypto.ct import constant_time_eq
from ..crypto.ecb import ecb_decrypt_pkcs7, ecb_encrypt_pkcs7
from ..crypto.hmac import hmac
from ..crypto.sha256 import Sha256, sha256
from ..wire import (
    Reader,
    hex_decode_bytes,
    hex_encode,
    put_bytes,
    put_u16_le,
    put_u32_le,
    put_u64_le,
    put_zeros,
)

comptime DISCOVERY_PORT = 7551
"""The UDP port Minecraft uses for LAN discovery."""

comptime PACKET_REQUEST = 0
"""Asks every listener on the network to describe itself."""
comptime PACKET_RESPONSE = 1
"""Carries a listener's `ServerData`."""
comptime PACKET_MESSAGE = 2
"""Carries one signal to a specific network ID."""

comptime _MESSAGE_HEADER_LEN = 32
comptime _MAX_DECLARED_MESSAGE_DATA = 1140


def discovery_key() -> Array[UInt8, 32]:
    """Computes the fixed key every discovery datagram is sealed with.

    Returns:
        The SHA-256 of `0xdeadbeef` encoded as a little-endian `u64`.
    """
    var seed: List[UInt8] = [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]
    return sha256(Span(seed))


struct DiscoveryPacket(Copyable):
    """One discovery packet of any of the three kinds."""

    var kind: Int
    """One of `PACKET_REQUEST`, `PACKET_RESPONSE` and `PACKET_MESSAGE`."""
    var sender_id: UInt64
    """The network ID of the sender."""
    var application_data: List[UInt8]
    """Response only: the encoded `ServerData`."""
    var recipient_id: UInt64
    """Message only: the network ID the signal is addressed to."""
    var data: String
    """Message only: the signal text."""

    def __init__(out self, kind: Int, sender_id: UInt64):
        """Creates a packet with empty kind-specific fields.

        Args:
            kind: The packet kind.
            sender_id: The sender's network ID.
        """
        self.kind = kind
        self.sender_id = sender_id
        self.application_data = List[UInt8]()
        self.recipient_id = 0
        self.data = String()

    @staticmethod
    def request(sender_id: UInt64) -> DiscoveryPacket:
        """Creates a request packet.

        Args:
            sender_id: The sender's network ID.

        Returns:
            The packet.
        """
        return DiscoveryPacket(PACKET_REQUEST, sender_id)

    @staticmethod
    def response(
        sender_id: UInt64, application_data: Span[UInt8, _]
    ) -> DiscoveryPacket:
        """Creates a response packet.

        Args:
            sender_id: The sender's network ID.
            application_data: The encoded `ServerData`.

        Returns:
            The packet.
        """
        var pk = DiscoveryPacket(PACKET_RESPONSE, sender_id)
        pk.application_data = List[UInt8](application_data)
        return pk^

    @staticmethod
    def message(
        sender_id: UInt64, recipient_id: UInt64, data: StringSpan
    ) -> DiscoveryPacket:
        """Creates a message packet.

        Args:
            sender_id: The sender's network ID.
            recipient_id: The network ID the signal is for.
            data: The signal text.

        Returns:
            The packet.
        """
        var pk = DiscoveryPacket(PACKET_MESSAGE, sender_id)
        pk.recipient_id = recipient_id
        pk.data = String(data)
        return pk^

    def encode_payload(self) -> List[UInt8]:
        """Encodes the plaintext payload, before sealing.

        Returns:
            The payload bytes, starting with the length field.
        """
        var body = List[UInt8]()
        put_u16_le(body, UInt16(self.kind))
        put_u64_le(body, self.sender_id)
        put_zeros(body, 8)
        var length: Int
        if self.kind == PACKET_RESPONSE:
            var hex = hex_encode(Span(self.application_data))
            put_u32_le(body, UInt32(hex.byte_length()))
            put_bytes(body, hex.as_bytes())
            length = len(body) + 2
        elif self.kind == PACKET_MESSAGE:
            var declared = min(
                self.data.byte_length(), _MAX_DECLARED_MESSAGE_DATA
            )
            put_u64_le(body, self.recipient_id)
            put_u32_le(body, UInt32(declared))
            put_bytes(body, self.data.as_bytes())
            # Minecraft declares at most 1140 data bytes even when more
            # follow; readers take everything to the end regardless.
            length = _MESSAGE_HEADER_LEN + declared
        else:
            length = len(body) + 2
        var payload = List[UInt8](capacity=len(body) + 2)
        put_u16_le(payload, UInt16(length))
        put_bytes(payload, Span(body))
        return payload^


def seal_payload(payload: Span[UInt8, _]) raises -> List[UInt8]:
    """Authenticates and encrypts a plaintext payload into a datagram.

    Args:
        payload: The plaintext payload, starting with its length field.

    Returns:
        The datagram: a 32-byte HMAC followed by the encrypted payload.

    Raises:
        Error: If encryption fails.
    """
    var key = discovery_key()
    var tag = hmac[Sha256](Span(key), payload)
    var out = List[UInt8](capacity=32 + len(payload) + 16)
    put_bytes(out, Span(tag))
    ecb_encrypt_pkcs7(Span(key), payload, out)
    return out^


def open_payload(datagram: Span[UInt8, _]) raises -> List[UInt8]:
    """Decrypts a datagram and checks its HMAC.

    Args:
        datagram: The received datagram.

    Returns:
        The plaintext payload.

    Raises:
        Error: If the datagram is too short, fails decryption or its HMAC.
    """
    if len(datagram) < 32:
        raise Error("discovery: datagram too short")
    var key = discovery_key()
    var payload = List[UInt8]()
    ecb_decrypt_pkcs7(Span(key), datagram[32 : len(datagram)], payload)
    var tag = hmac[Sha256](Span(key), Span(payload))
    if not constant_time_eq(Span(tag), datagram[0:32]):
        raise Error("discovery: checksum mismatch")
    return payload^


def marshal_packet(pk: DiscoveryPacket) raises -> List[UInt8]:
    """Seals a packet into a datagram.

    Args:
        pk: The packet to send.

    Returns:
        The datagram: a 32-byte HMAC followed by the encrypted payload.

    Raises:
        Error: If encryption fails.
    """
    var payload = pk.encode_payload()
    return seal_payload(Span(payload))


def unmarshal_packet(datagram: Span[UInt8, _]) raises -> DiscoveryPacket:
    """Opens and decodes a datagram.

    The length fields nested inside response and message bodies are ignored:
    like the game, the reader takes everything up to the end of the payload.
    A declared payload length shorter than the payload is accepted, which
    covers older peers that did not count the length field itself.

    Args:
        datagram: The received datagram.

    Returns:
        The decoded packet.

    Raises:
        Error: If the datagram is too short, fails decryption or its HMAC,
            declares more bytes than it has, or has an unknown packet ID.
    """
    var payload = open_payload(datagram)
    if len(payload) < 4:
        raise Error("discovery: payload too short")
    var r = Reader(Span(payload))
    var declared = Int(r.u16_le())
    if len(payload) < declared:
        raise Error("discovery: payload shorter than its declared length")
    var kind = Int(r.u16_le())
    var sender = r.u64_le()
    r.skip(8)
    var pk = DiscoveryPacket(kind, sender)
    if kind == PACKET_REQUEST:
        return pk^
    if kind == PACKET_RESPONSE:
        _ = r.u32_le()
        var hex = r.rest()
        pk.application_data = hex_decode_bytes(hex)
        return pk^
    if kind == PACKET_MESSAGE:
        pk.recipient_id = r.u64_le()
        _ = r.u32_le()
        pk.data = String(from_utf8=r.rest())
        return pk^
    raise Error(t"discovery: unknown packet ID {kind}")
