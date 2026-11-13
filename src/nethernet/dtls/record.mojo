"""The DTLS record layer: headers, AES-GCM protection and replay detection."""

from std.memory import OwnedPointer

from ..crypto.gcm import AesGcm
from ..wire import put_bytes, put_u16, put_u48, put_u8
from .handshake import DTLS_VERSION_1_2

comptime CT_CHANGE_CIPHER_SPEC = 20
"""Record content type `change_cipher_spec`."""
comptime CT_ALERT = 21
"""Record content type `alert`."""
comptime CT_HANDSHAKE = 22
"""Record content type `handshake`."""
comptime CT_APPLICATION_DATA = 23
"""Record content type `application_data`."""

comptime RECORD_HEADER_LEN = 13
"""The size of a DTLS record header in bytes."""
comptime AEAD_OVERHEAD = 24
"""Bytes added by protection: an 8-byte explicit nonce and a 16-byte tag."""

comptime ALERT_LEVEL_WARNING = 1
"""Alert level `warning`."""
comptime ALERT_LEVEL_FATAL = 2
"""Alert level `fatal`."""
comptime ALERT_CLOSE_NOTIFY = 0
"""Alert `close_notify`: the sender is closing the connection."""
comptime ALERT_HANDSHAKE_FAILURE = 40
"""Alert `handshake_failure`."""
comptime ALERT_BAD_CERTIFICATE = 42
"""Alert `bad_certificate`."""
comptime ALERT_ILLEGAL_PARAMETER = 47
"""Alert `illegal_parameter`."""
comptime ALERT_DECRYPT_ERROR = 51
"""Alert `decrypt_error`."""
comptime ALERT_INTERNAL_ERROR = 80
"""Alert `internal_error`."""


def put_record_header(
    mut out: List[UInt8], content_type: UInt8, epoch: UInt16, seq: UInt64, length: Int
):
    """Appends a 13-byte DTLS 1.2 record header.

    Args:
        out: The buffer to append to.
        content_type: The record content type.
        epoch: The epoch.
        seq: The 48-bit record sequence number.
        length: The length of the record body that follows.
    """
    put_u8(out, content_type)
    put_u16(out, DTLS_VERSION_1_2)
    put_u16(out, epoch)
    put_u48(out, seq)
    put_u16(out, UInt16(length))


def put_plain_record(
    mut out: List[UInt8],
    content_type: UInt8,
    epoch: UInt16,
    seq: UInt64,
    body: Span[UInt8, _],
):
    """Appends an unprotected record.

    Args:
        out: The buffer to append to.
        content_type: The record content type.
        epoch: The epoch, 0 before keys are active.
        seq: The 48-bit record sequence number.
        body: The record body.
    """
    put_record_header(out, content_type, epoch, seq, len(body))
    put_bytes(out, body)


struct RecordCipher(Movable):
    """AES-128-GCM protection for one direction of a connection.

    The nonce is the 4-byte implicit IV from the key block followed by the
    8-byte explicit part carried in each record (RFC 5288).

    The cipher state lives on the heap: it is over a kilobyte, and keeping
    it inline would make every move of the owning connection expensive to
    compile and to run.
    """

    var _aead: OwnedPointer[AesGcm]
    var _iv: List[UInt8]

    def __init__(out self, key: Span[UInt8, _], iv: Span[UInt8, _]) raises:
        """Creates the cipher from key-block material.

        Args:
            key: The 16-byte write key.
            iv: The 4-byte implicit IV.

        Raises:
            Error: If the key length is not valid for AES.
        """
        self._aead = OwnedPointer(AesGcm(key))
        self._iv = List[UInt8](iv)

    def _aad(
        self, content_type: UInt8, epoch: UInt16, seq: UInt64, length: Int
    ) -> List[UInt8]:
        var aad = List[UInt8](capacity=13)
        put_u16(aad, epoch)
        put_u48(aad, seq)
        put_u8(aad, content_type)
        put_u16(aad, DTLS_VERSION_1_2)
        put_u16(aad, UInt16(length))
        return aad^

    def seal(
        self,
        mut out: List[UInt8],
        content_type: UInt8,
        epoch: UInt16,
        seq: UInt64,
        plaintext: Span[UInt8, _],
    ) raises:
        """Appends a protected record, header included.

        Args:
            out: The buffer to append to.
            content_type: The record content type.
            epoch: The epoch the keys belong to.
            seq: The 48-bit record sequence number; never reuse one.
            plaintext: The record payload.

        Raises:
            Error: If encryption fails.
        """
        put_record_header(
            out, content_type, epoch, seq, len(plaintext) + AEAD_OVERHEAD
        )
        var nonce = self._iv.copy()
        put_u16(nonce, epoch)
        put_u48(nonce, seq)
        put_bytes(out, Span(nonce)[4:12])
        var aad = self._aad(content_type, epoch, seq, len(plaintext))
        self._aead[].seal(Span(nonce), Span(aad), plaintext, out)

    def open(
        self,
        content_type: UInt8,
        epoch: UInt16,
        seq: UInt64,
        body: Span[UInt8, _],
    ) raises -> List[UInt8]:
        """Authenticates and decrypts a protected record body.

        Args:
            content_type: The content type from the record header.
            epoch: The epoch from the record header.
            seq: The sequence number from the record header.
            body: The record body: explicit nonce, ciphertext and tag.

        Returns:
            The plaintext payload.

        Raises:
            Error: If the body is too short or authentication fails.
        """
        if len(body) < AEAD_OVERHEAD:
            raise Error("dtls: protected record too short")
        var nonce = self._iv.copy()
        put_bytes(nonce, body[0:8])
        var plain_len = len(body) - AEAD_OVERHEAD
        var aad = self._aad(content_type, epoch, seq, plain_len)
        var out = List[UInt8](capacity=plain_len)
        self._aead[].open(Span(nonce), Span(aad), body[8 : len(body)], out)
        return out^


struct ReplayWindow(Copyable):
    """A 64-entry sliding window over record sequence numbers (RFC 6347 4.1.2.6)."""

    var _highest: UInt64
    var _bitmap: UInt64
    var _any: Bool

    def __init__(out self):
        """Creates a window that has seen nothing."""
        self._highest = 0
        self._bitmap = 0
        self._any = False

    def is_fresh(self, seq: UInt64) -> Bool:
        """Checks whether a sequence number is new and inside the window.

        Args:
            seq: The record sequence number.

        Returns:
            `False` for duplicates and for numbers older than the window.
        """
        if not self._any or seq > self._highest:
            return True
        var diff = self._highest - seq
        if diff >= 64:
            return False
        return (self._bitmap & (UInt64(1) << diff)) == 0

    def mark(mut self, seq: UInt64):
        """Records a sequence number as seen, after authentication succeeded.

        Args:
            seq: The record sequence number.
        """
        if not self._any:
            self._any = True
            self._highest = seq
            self._bitmap = 1
            return
        if seq > self._highest:
            var shift = seq - self._highest
            if shift >= 64:
                self._bitmap = 1
            else:
                self._bitmap = (self._bitmap << shift) | 1
            self._highest = seq
        else:
            var diff = self._highest - seq
            if diff < 64:
                self._bitmap |= UInt64(1) << diff
