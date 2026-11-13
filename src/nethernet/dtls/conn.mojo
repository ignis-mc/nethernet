"""The DTLS 1.2 connection state machine, for both client and server roles.

`DtlsConn` is sans-I/O: feed it datagrams with `handle_datagram()`, call
`handle_timeout()` when `next_timeout()` passes, send what `poll_transmit()`
returns, and read decrypted application data from `poll_app_data()`.

Handshake shape (RFC 6347 section 4.2.4), with mutual authentication:

    client                                   server
    ClientHello                    -->
                                   <--       [HelloVerifyRequest]
    [ClientHello + cookie]         -->
                                   <--       ServerHello, Certificate,
                                             ServerKeyExchange,
                                             CertificateRequest,
                                             ServerHelloDone
    Certificate, ClientKeyExchange,
    CertificateVerify,
    ChangeCipherSpec, Finished     -->
                                   <--       ChangeCipherSpec, Finished

As a server this implementation skips HelloVerifyRequest: ICE has already
proven the peer's address. As a client it honours one if the server sends it.
"""

from ..crypto.ct import constant_time_eq
from ..crypto.ecdsa_der import ecdsa_signature_from_der, ecdsa_signature_to_der
from ..crypto.p256 import (
    p256_ecdh,
    p256_private_key_from_bytes,
    p256_public_key,
    p256_sign,
    p256_verify,
)
from ..crypto.p384 import p384_verify
from ..crypto.sha256 import Sha256, sha256
from ..crypto.x509 import (
    KEY_ALGORITHM_EC_P256,
    KEY_ALGORITHM_EC_P384,
    KEY_ALGORITHM_UNKNOWN,
    PublicKeyInfo,
    certificate_public_key,
)
from ..wire import Reader, put_bytes
from .handshake import (
    CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256,
    CertificateVerify,
    ClientHello,
    GROUP_SECP256R1,
    HS_CERTIFICATE,
    HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY,
    HS_CLIENT_HELLO,
    HS_CLIENT_KEY_EXCHANGE,
    HS_FINISHED,
    HS_HEADER_LEN,
    HS_HELLO_VERIFY_REQUEST,
    HS_SERVER_HELLO,
    HS_SERVER_HELLO_DONE,
    HS_SERVER_KEY_EXCHANGE,
    SIG_ECDSA_SHA256,
    SRTP_AEAD_AES_128_GCM,
    SRTP_AEAD_AES_256_GCM,
    SRTP_AES128_CM_HMAC_SHA1_80,
    ServerHello,
    ServerKeyExchange,
    decode_certificate,
    decode_client_key_exchange,
    decode_hello_verify_request,
    encode_certificate,
    encode_certificate_request,
    encode_certificate_verify,
    encode_client_key_exchange,
    put_handshake_header,
)
from .prf import prf_sha256
from .record import (
    AEAD_OVERHEAD,
    ALERT_BAD_CERTIFICATE,
    ALERT_CLOSE_NOTIFY,
    ALERT_DECRYPT_ERROR,
    ALERT_HANDSHAKE_FAILURE,
    ALERT_ILLEGAL_PARAMETER,
    ALERT_LEVEL_FATAL,
    ALERT_LEVEL_WARNING,
    CT_ALERT,
    CT_APPLICATION_DATA,
    CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE,
    RECORD_HEADER_LEN,
    RecordCipher,
    ReplayWindow,
    put_plain_record,
)

comptime DTLS_STATE_NEW = 0
"""`start()` has not been called."""
comptime DTLS_STATE_HANDSHAKING = 1
"""The handshake is in progress."""
comptime DTLS_STATE_CONNECTED = 2
"""The handshake finished; application data may flow."""
comptime DTLS_STATE_CLOSED = 3
"""The connection was closed with `close_notify`."""
comptime DTLS_STATE_FAILED = 4
"""The handshake or the connection failed; see `failure_reason()`."""

comptime DTLS_RANDOM_LEN = 72
"""Random bytes a connection needs: 32 for the hello, 40 for the ECDHE key."""

comptime _C_WAIT_SERVER_HELLO = 1
comptime _C_WAIT_CERTIFICATE = 2
comptime _C_WAIT_SERVER_KEY_EXCHANGE = 3
comptime _C_WAIT_HELLO_DONE = 4
comptime _C_WAIT_FINISHED = 5
comptime _S_WAIT_CLIENT_HELLO = 10
comptime _S_WAIT_CERTIFICATE = 11
comptime _S_WAIT_CLIENT_KEY_EXCHANGE = 12
comptime _S_WAIT_CERTIFICATE_VERIFY = 13
comptime _S_WAIT_FINISHED = 14
comptime _STEP_DONE = 20

comptime _NEVER = 0x3FFF_FFFF_FFFF_FFFF
comptime _MAX_HANDSHAKE_MESSAGE = 16384
comptime _MAX_RECORD_PLAINTEXT = 16384
comptime _MAX_RETRANSMIT_MS = 8000
comptime _MAX_RETRANSMITS = 12
comptime _MIN_RETRANSMIT_GAP_MS = 100
comptime _MAX_BUFFERED_APP_DATA = 4096


struct DtlsConfig(Copyable):
    """Everything a `DtlsConn` needs from its owner."""

    var is_client: Bool
    """`True` to start the handshake, `False` to wait for a ClientHello."""
    var certificate: List[UInt8]
    """The local certificate in DER form."""
    var private_key: List[UInt8]
    """The local 32-byte P-256 private key matching the certificate."""
    var remote_fingerprint: List[UInt8]
    """The expected SHA-256 of the peer certificate; empty skips the check."""
    var random: List[UInt8]
    """At least `DTLS_RANDOM_LEN` bytes of fresh randomness."""
    var mtu: Int
    """The largest datagram to emit during the handshake."""
    var retransmit_ms: Int
    """The initial flight retransmission interval; it doubles on each retry."""

    def __init__(
        out self,
        is_client: Bool,
        certificate: Span[UInt8, _],
        private_key: Span[UInt8, _],
        random: Span[UInt8, _],
    ):
        """Creates a configuration with default timing.

        Args:
            is_client: `True` for the DTLS client role.
            certificate: The local certificate in DER form.
            private_key: The local 32-byte P-256 private key.
            random: At least `DTLS_RANDOM_LEN` fresh random bytes.
        """
        self.is_client = is_client
        self.certificate = List[UInt8](certificate)
        self.private_key = List[UInt8](private_key)
        self.remote_fingerprint = List[UInt8]()
        self.random = List[UInt8](random)
        self.mtu = 1200
        self.retransmit_ms = 500


@fieldwise_init
struct _FlightItem(Copyable):
    var content_type: UInt8
    var epoch: UInt16
    var body: List[UInt8]


struct _Partial(Copyable):
    var msg_type: UInt8
    var length: Int
    var data: List[UInt8]

    def __init__(out self, msg_type: UInt8, length: Int):
        self.msg_type = msg_type
        self.length = length
        self.data = List[UInt8]()


struct DtlsConn(Movable):
    """One DTLS association."""

    var _config: DtlsConfig
    var _state: Int
    var _step: Int
    var _failure: String

    var _local_random: List[UInt8]
    var _remote_random: List[UInt8]
    var _ecdh_private: List[UInt8]
    var _ecdh_public: List[UInt8]
    var _master_secret: List[UInt8]
    var _use_ems: Bool
    var _srtp_profile: UInt16
    var _cert_requested: Bool

    var _transcript: Sha256
    var _client_hello_msg: List[UInt8]
    var _next_send_seq: UInt16
    var _next_recv_seq: Int
    var _partials: Dict[Int, _Partial]

    var _write_epoch: UInt16
    var _write_seq0: UInt64
    var _write_seq1: UInt64
    var _read_epoch: UInt16
    var _write_cipher: Optional[RecordCipher]
    var _read_cipher: Optional[RecordCipher]
    var _pending_read_cipher: Optional[RecordCipher]
    var _replay: ReplayWindow

    var _flight: List[_FlightItem]
    var _retransmit_at: Int
    var _retransmit_interval: Int
    var _retransmits: Int
    var _last_flight_ms: Int

    var _peer_certificate: List[UInt8]
    var _peer_key: PublicKeyInfo

    var _out: List[List[UInt8]]
    var _app_in: List[List[UInt8]]

    def __init__(out self, config: DtlsConfig):
        """Creates a connection in the `DTLS_STATE_NEW` state.

        Args:
            config: The role, credentials and randomness.
        """
        self._config = config.copy()
        self._state = DTLS_STATE_NEW
        self._step = (
            _C_WAIT_SERVER_HELLO if config.is_client else _S_WAIT_CLIENT_HELLO
        )
        self._failure = String()
        self._local_random = List[UInt8]()
        self._remote_random = List[UInt8]()
        self._ecdh_private = List[UInt8]()
        self._ecdh_public = List[UInt8]()
        self._master_secret = List[UInt8]()
        self._use_ems = False
        self._srtp_profile = 0
        self._cert_requested = False
        self._transcript = Sha256()
        self._client_hello_msg = List[UInt8]()
        self._next_send_seq = 0
        self._next_recv_seq = 0
        self._partials = Dict[Int, _Partial]()
        self._write_epoch = 0
        self._write_seq0 = 0
        self._write_seq1 = 0
        self._read_epoch = 0
        self._write_cipher = None
        self._read_cipher = None
        self._pending_read_cipher = None
        self._replay = ReplayWindow()
        self._flight = List[_FlightItem]()
        self._retransmit_at = _NEVER
        self._retransmit_interval = config.retransmit_ms
        self._retransmits = 0
        self._last_flight_ms = -_MIN_RETRANSMIT_GAP_MS
        self._peer_certificate = List[UInt8]()
        self._peer_key = PublicKeyInfo(KEY_ALGORITHM_UNKNOWN, List[UInt8]())
        self._out = List[List[UInt8]]()
        self._app_in = List[List[UInt8]]()

    # ===------------------------------------------------------------------=== #
    # Public API
    # ===------------------------------------------------------------------=== #

    def start(mut self, now_ms: Int):
        """Begins the handshake.

        A client queues its ClientHello; a server starts waiting for one.

        Args:
            now_ms: The current monotonic time in milliseconds.
        """
        if self._state != DTLS_STATE_NEW:
            return
        self._state = DTLS_STATE_HANDSHAKING
        try:
            if len(self._config.random) < DTLS_RANDOM_LEN:
                raise Error("dtls: not enough random bytes in the config")
            self._local_random = List[UInt8](Span(self._config.random)[0:32])
            var key = p256_private_key_from_bytes(
                Span(self._config.random)[32:72]
            )
            self._ecdh_private = List[UInt8](Span(key))
            var pub = p256_public_key(Span(key))
            self._ecdh_public = List[UInt8](Span(pub))
            if self._config.is_client:
                self._send_client_hello(List[UInt8](), now_ms)
        except e:
            self._fail(String(e), ALERT_HANDSHAKE_FAILURE)

    def state(self) -> Int:
        """Gets the connection state.

        Returns:
            One of the `DTLS_STATE_*` constants.
        """
        return self._state

    def failure_reason(self) -> String:
        """Describes why the connection failed.

        Returns:
            A short reason, empty unless the state is `DTLS_STATE_FAILED`.
        """
        return self._failure.copy()

    def peer_certificate(self) -> List[UInt8]:
        """Gets the certificate the peer presented.

        Returns:
            The DER-encoded certificate, empty before it arrives.
        """
        return self._peer_certificate.copy()

    def srtp_profile(self) -> UInt16:
        """Gets the SRTP protection profile negotiated with `use_srtp`.

        No SRTP keys are derived; WebRTC peers merely insist on negotiating
        the extension.

        Returns:
            The profile identifier, or 0 if none was negotiated.
        """
        return self._srtp_profile

    def next_timeout(self) -> Int:
        """Computes when `handle_timeout()` next has work to do.

        Returns:
            An absolute monotonic time in milliseconds; a very large value if
            no retransmission is pending.
        """
        if self._state == DTLS_STATE_HANDSHAKING and len(self._flight) > 0:
            return self._retransmit_at
        return _NEVER

    def handle_timeout(mut self, now_ms: Int):
        """Retransmits the current flight if its timer expired.

        Args:
            now_ms: The current monotonic time in milliseconds.
        """
        if self._state != DTLS_STATE_HANDSHAKING or len(self._flight) == 0:
            return
        if now_ms < self._retransmit_at:
            return
        if self._retransmits >= _MAX_RETRANSMITS:
            self._fail("dtls: handshake timed out", ALERT_HANDSHAKE_FAILURE)
            return
        self._retransmits += 1
        self._retransmit_interval = min(
            self._retransmit_interval * 2, _MAX_RETRANSMIT_MS
        )
        self._emit_flight(now_ms)

    def poll_transmit(mut self) -> Optional[List[UInt8]]:
        """Takes the next datagram to send.

        Returns:
            A datagram, or `None` when nothing is queued.
        """
        if len(self._out) == 0:
            return None
        return self._out.pop(0)

    def poll_app_data(mut self) -> Optional[List[UInt8]]:
        """Takes the next decrypted application-data record.

        Returns:
            The payload of one record, or `None` when nothing is queued.
        """
        if len(self._app_in) == 0:
            return None
        return self._app_in.pop(0)

    def send_app_data(mut self, data: Span[UInt8, _]) raises:
        """Encrypts one application-data record and queues it as a datagram.

        Args:
            data: The payload, at most 16384 bytes.

        Raises:
            Error: If the connection is not established or the payload is too
                large.
        """
        if self._state != DTLS_STATE_CONNECTED:
            raise Error("dtls: connection is not established")
        if len(data) > _MAX_RECORD_PLAINTEXT:
            raise Error("dtls: application record too large")
        var datagram = List[UInt8](
            capacity=len(data) + RECORD_HEADER_LEN + AEAD_OVERHEAD
        )
        self._write_cipher.value().seal(
            datagram, CT_APPLICATION_DATA, 1, self._write_seq1, data
        )
        self._write_seq1 += 1
        self._out.append(datagram^)

    def close(mut self):
        """Sends `close_notify` and moves to `DTLS_STATE_CLOSED`."""
        if (
            self._state == DTLS_STATE_CLOSED
            or self._state == DTLS_STATE_FAILED
            or self._state == DTLS_STATE_NEW
        ):
            return
        self._send_alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY)
        self._state = DTLS_STATE_CLOSED
        self._flight.clear()

    def handle_datagram(mut self, data: Span[UInt8, _], now_ms: Int):
        """Processes one inbound datagram, which may hold several records.

        Records that fail to parse or authenticate are dropped silently.

        Args:
            data: The datagram.
            now_ms: The current monotonic time in milliseconds.
        """
        var pos = 0
        while pos + RECORD_HEADER_LEN <= len(data):
            var content_type = data[pos]
            var major = data[pos + 1]
            var epoch = (UInt16(data[pos + 3]) << 8) | UInt16(data[pos + 4])
            var seq = UInt64(0)
            for i in range(6):
                seq = (seq << 8) | UInt64(data[pos + 5 + i])
            var length = (Int(data[pos + 11]) << 8) | Int(data[pos + 12])
            var body_start = pos + RECORD_HEADER_LEN
            if major != 0xFE or body_start + length > len(data):
                return
            pos = body_start + length
            self._on_record(
                content_type,
                epoch,
                seq,
                data[body_start : body_start + length],
                now_ms,
            )
            if (
                self._state == DTLS_STATE_FAILED
                or self._state == DTLS_STATE_CLOSED
            ):
                return

    # ===------------------------------------------------------------------=== #
    # Record handling
    # ===------------------------------------------------------------------=== #

    def _on_record(
        mut self,
        content_type: UInt8,
        epoch: UInt16,
        seq: UInt64,
        body: Span[UInt8, _],
        now_ms: Int,
    ):
        if self._state == DTLS_STATE_NEW:
            return
        if epoch == 0:
            # Plaintext. Once protected records are flowing, only handshake
            # retransmissions are still meaningful in epoch 0.
            if self._read_epoch != 0 and content_type != CT_HANDSHAKE:
                return
            self._dispatch(content_type, epoch, body, now_ms)
            return
        if epoch != 1:
            return
        if self._read_epoch != 1:
            return
        if not self._replay.is_fresh(seq):
            return
        var plain: List[UInt8]
        try:
            plain = self._read_cipher.value().open(
                content_type, epoch, seq, body
            )
        except:
            return
        self._replay.mark(seq)
        self._dispatch(content_type, epoch, Span(plain), now_ms)

    def _dispatch(
        mut self,
        content_type: UInt8,
        epoch: UInt16,
        body: Span[UInt8, _],
        now_ms: Int,
    ):
        if content_type == CT_HANDSHAKE:
            self._on_handshake_record(body, now_ms)
        elif content_type == CT_CHANGE_CIPHER_SPEC:
            if (
                epoch == 0
                and self._pending_read_cipher is not None
                and (
                    self._step == _C_WAIT_FINISHED
                    or self._step == _S_WAIT_FINISHED
                )
            ):
                self._read_cipher = self._pending_read_cipher.take()
                self._read_epoch = 1
        elif content_type == CT_ALERT:
            if len(body) < 2:
                return
            if body[1] == ALERT_CLOSE_NOTIFY:
                if epoch == 1 and self._state == DTLS_STATE_CONNECTED:
                    self._send_alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY)
                self._state = DTLS_STATE_CLOSED
                self._flight.clear()
            elif body[0] == ALERT_LEVEL_FATAL:
                self._state = DTLS_STATE_FAILED
                self._failure = String(t"dtls: peer sent fatal alert {body[1]}")
                self._flight.clear()
        elif content_type == CT_APPLICATION_DATA:
            if epoch == 1 and self._state == DTLS_STATE_CONNECTED:
                if len(self._app_in) < _MAX_BUFFERED_APP_DATA:
                    self._app_in.append(List[UInt8](body))

    def _on_handshake_record(mut self, body: Span[UInt8, _], now_ms: Int):
        var pos = 0
        while pos + HS_HEADER_LEN <= len(body):
            var msg_type = body[pos]
            var length = (
                (Int(body[pos + 1]) << 16)
                | (Int(body[pos + 2]) << 8)
                | Int(body[pos + 3])
            )
            var message_seq = (Int(body[pos + 4]) << 8) | Int(body[pos + 5])
            var frag_off = (
                (Int(body[pos + 6]) << 16)
                | (Int(body[pos + 7]) << 8)
                | Int(body[pos + 8])
            )
            var frag_len = (
                (Int(body[pos + 9]) << 16)
                | (Int(body[pos + 10]) << 8)
                | Int(body[pos + 11])
            )
            var start = pos + HS_HEADER_LEN
            if start + frag_len > len(body):
                return
            pos = start + frag_len
            self._on_fragment(
                msg_type,
                length,
                message_seq,
                frag_off,
                body[start : start + frag_len],
                now_ms,
            )
            if self._state == DTLS_STATE_FAILED:
                return

    def _on_fragment(
        mut self,
        msg_type: UInt8,
        length: Int,
        message_seq: Int,
        frag_off: Int,
        frag: Span[UInt8, _],
        now_ms: Int,
    ):
        try:
            self._reassemble(
                msg_type, length, message_seq, frag_off, frag, now_ms
            )
        except e:
            var reason = String(e)
            var alert: UInt8 = ALERT_HANDSHAKE_FAILURE
            if "certificate" in reason or "fingerprint" in reason:
                alert = ALERT_BAD_CERTIFICATE
            elif "signature" in reason or "Finished" in reason:
                alert = ALERT_DECRYPT_ERROR
            elif "unsupported" in reason or "unexpected" in reason:
                alert = ALERT_ILLEGAL_PARAMETER
            self._fail(reason, alert)

    def _reassemble(
        mut self,
        msg_type: UInt8,
        length: Int,
        message_seq: Int,
        frag_off: Int,
        frag: Span[UInt8, _],
        now_ms: Int,
    ) raises:
        if message_seq < self._next_recv_seq:
            # The peer is repeating a flight we already processed, so ours
            # was lost: repeat it.
            self._retransmit_on_duplicate(now_ms)
            return
        if message_seq > self._next_recv_seq + 8:
            return
        if length > _MAX_HANDSHAKE_MESSAGE or frag_off + len(frag) > length:
            return
        if message_seq not in self._partials:
            if len(self._partials) >= 16:
                return
            self._partials[message_seq] = _Partial(msg_type, length)
        var have = len(self._partials[message_seq].data)
        if (
            self._partials[message_seq].msg_type != msg_type
            or self._partials[message_seq].length != length
        ):
            return
        if frag_off <= have and frag_off + len(frag) > have:
            put_bytes(
                self._partials[message_seq].data,
                frag[have - frag_off : len(frag)],
            )
        while self._next_recv_seq in self._partials:
            var seq = self._next_recv_seq
            if len(self._partials[seq].data) < self._partials[seq].length:
                break
            var msg = self._partials.pop(seq)
            self._next_recv_seq += 1
            self._on_message(msg.msg_type, seq, Span(msg.data), now_ms)
            if self._state != DTLS_STATE_HANDSHAKING:
                break

    # ===------------------------------------------------------------------=== #
    # Handshake messages
    # ===------------------------------------------------------------------=== #

    def _transcript_add(
        mut self, msg_type: UInt8, message_seq: Int, body: Span[UInt8, _]
    ):
        var header = List[UInt8](capacity=HS_HEADER_LEN)
        put_handshake_header(
            header, msg_type, len(body), UInt16(message_seq), 0, len(body)
        )
        self._transcript.update(Span(header))
        self._transcript.update(body)

    def _transcript_hash(self) -> Array[UInt8, 32]:
        var copy = self._transcript.copy()
        return copy.finish()

    def _on_message(
        mut self,
        msg_type: UInt8,
        message_seq: Int,
        body: Span[UInt8, _],
        now_ms: Int,
    ) raises:
        if self._config.is_client:
            self._on_message_client(msg_type, message_seq, body, now_ms)
        else:
            self._on_message_server(msg_type, message_seq, body, now_ms)

    def _on_message_client(
        mut self,
        msg_type: UInt8,
        message_seq: Int,
        body: Span[UInt8, _],
        now_ms: Int,
    ) raises:
        if self._step == _C_WAIT_SERVER_HELLO:
            if msg_type == HS_HELLO_VERIFY_REQUEST:
                var cookie = decode_hello_verify_request(body)
                self._send_client_hello(cookie^, now_ms)
                return
            if msg_type != HS_SERVER_HELLO:
                raise Error("dtls: unexpected message, wanted ServerHello")
            var sh = ServerHello.decode(body)
            if sh.cipher_suite != CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256:
                raise Error("dtls: unsupported cipher suite selected")
            self._remote_random = sh.random.copy()
            self._use_ems = sh.extended_master_secret
            self._srtp_profile = sh.srtp_profile
            self._transcript.update(Span(self._client_hello_msg))
            self._transcript_add(msg_type, message_seq, body)
            self._step = _C_WAIT_CERTIFICATE
        elif self._step == _C_WAIT_CERTIFICATE:
            if msg_type != HS_CERTIFICATE:
                raise Error("dtls: unexpected message, wanted Certificate")
            self._accept_peer_certificate(body)
            self._transcript_add(msg_type, message_seq, body)
            self._step = _C_WAIT_SERVER_KEY_EXCHANGE
        elif self._step == _C_WAIT_SERVER_KEY_EXCHANGE:
            if msg_type != HS_SERVER_KEY_EXCHANGE:
                raise Error(
                    "dtls: unexpected message, wanted ServerKeyExchange"
                )
            var ske = ServerKeyExchange.decode(body)
            if ske.named_curve != GROUP_SECP256R1:
                raise Error("dtls: unsupported key exchange group")
            if ske.signature_algorithm != SIG_ECDSA_SHA256:
                raise Error("dtls: unsupported signature algorithm")
            var signed = self._local_random.copy()
            put_bytes(signed, Span(self._remote_random))
            ske.encode_params(signed)
            var digest = sha256(Span(signed))
            self._verify_peer_signature(Span(digest), Span(ske.signature))
            self._compute_premaster(Span(ske.public_key))
            self._transcript_add(msg_type, message_seq, body)
            self._step = _C_WAIT_HELLO_DONE
        elif self._step == _C_WAIT_HELLO_DONE:
            if msg_type == HS_CERTIFICATE_REQUEST:
                self._cert_requested = True
                self._transcript_add(msg_type, message_seq, body)
                return
            if msg_type != HS_SERVER_HELLO_DONE:
                raise Error("dtls: unexpected message, wanted ServerHelloDone")
            self._transcript_add(msg_type, message_seq, body)
            self._send_client_key_flight(now_ms)
            self._step = _C_WAIT_FINISHED
        elif self._step == _C_WAIT_FINISHED:
            if msg_type != HS_FINISHED:
                raise Error("dtls: unexpected message, wanted Finished")
            if self._read_epoch != 1:
                raise Error("dtls: Finished arrived unprotected")
            self._check_finished(body, "server finished")
            self._step = _STEP_DONE
            self._state = DTLS_STATE_CONNECTED
            self._flight.clear()
        else:
            raise Error("dtls: unexpected handshake message")

    def _on_message_server(
        mut self,
        msg_type: UInt8,
        message_seq: Int,
        body: Span[UInt8, _],
        now_ms: Int,
    ) raises:
        if self._step == _S_WAIT_CLIENT_HELLO:
            if msg_type != HS_CLIENT_HELLO:
                raise Error("dtls: unexpected message, wanted ClientHello")
            var ch = ClientHello.decode(body)
            var has_suite = False
            for cs in ch.cipher_suites:
                if cs == CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256:
                    has_suite = True
            if not has_suite:
                raise Error("dtls: unsupported cipher suites offered")
            if len(ch.supported_groups) > 0:
                var has_group = False
                for g in ch.supported_groups:
                    if g == GROUP_SECP256R1:
                        has_group = True
                if not has_group:
                    raise Error("dtls: unsupported key exchange groups offered")
            self._remote_random = ch.random.copy()
            self._use_ems = ch.extended_master_secret
            for p in ch.srtp_profiles:
                if self._srtp_profile == 0 and (
                    p == SRTP_AES128_CM_HMAC_SHA1_80
                    or p == SRTP_AEAD_AES_128_GCM
                    or p == SRTP_AEAD_AES_256_GCM
                ):
                    self._srtp_profile = p
            self._transcript_add(msg_type, message_seq, body)
            self._send_server_hello_flight(ch, now_ms)
            self._step = _S_WAIT_CERTIFICATE
        elif self._step == _S_WAIT_CERTIFICATE:
            if msg_type != HS_CERTIFICATE:
                raise Error("dtls: unexpected message, wanted Certificate")
            self._accept_peer_certificate(body)
            self._transcript_add(msg_type, message_seq, body)
            self._step = _S_WAIT_CLIENT_KEY_EXCHANGE
        elif self._step == _S_WAIT_CLIENT_KEY_EXCHANGE:
            if msg_type != HS_CLIENT_KEY_EXCHANGE:
                raise Error(
                    "dtls: unexpected message, wanted ClientKeyExchange"
                )
            var peer_public = decode_client_key_exchange(body)
            self._transcript_add(msg_type, message_seq, body)
            var premaster = p256_ecdh(
                Span(self._ecdh_private), Span(peer_public)
            )
            self._derive_keys(Span(premaster))
            self._step = _S_WAIT_CERTIFICATE_VERIFY
        elif self._step == _S_WAIT_CERTIFICATE_VERIFY:
            if msg_type != HS_CERTIFICATE_VERIFY:
                raise Error(
                    "dtls: unexpected message, wanted CertificateVerify"
                )
            var cv = CertificateVerify.decode(body)
            if cv.signature_algorithm != SIG_ECDSA_SHA256:
                raise Error("dtls: unsupported signature algorithm")
            var digest = self._transcript_hash()
            self._verify_peer_signature(Span(digest), Span(cv.signature))
            self._transcript_add(msg_type, message_seq, body)
            self._step = _S_WAIT_FINISHED
        elif self._step == _S_WAIT_FINISHED:
            if msg_type != HS_FINISHED:
                raise Error("dtls: unexpected message, wanted Finished")
            if self._read_epoch != 1:
                raise Error("dtls: Finished arrived unprotected")
            self._check_finished(body, "client finished")
            self._transcript_add(msg_type, message_seq, body)
            self._send_server_finished_flight(now_ms)
            self._step = _STEP_DONE
            self._state = DTLS_STATE_CONNECTED
        else:
            raise Error("dtls: unexpected handshake message")

    def _accept_peer_certificate(mut self, body: Span[UInt8, _]) raises:
        var cert = decode_certificate(body)
        if len(cert) == 0:
            raise Error("dtls: peer sent no certificate")
        if len(self._config.remote_fingerprint) > 0:
            var digest = sha256(Span(cert))
            if not constant_time_eq(
                Span(digest), Span(self._config.remote_fingerprint)
            ):
                raise Error("dtls: certificate fingerprint mismatch")
        self._peer_key = certificate_public_key(Span(cert))
        if (
            self._peer_key.algorithm != KEY_ALGORITHM_EC_P256
            and self._peer_key.algorithm != KEY_ALGORITHM_EC_P384
        ):
            raise Error("dtls: unsupported certificate key type")
        self._peer_certificate = cert^

    def _verify_peer_signature(
        self, digest: Span[UInt8, _], signature_der: Span[UInt8, _]
    ) raises:
        var ok = False
        if self._peer_key.algorithm == KEY_ALGORITHM_EC_P256:
            var raw = ecdsa_signature_from_der(signature_der, 32)
            ok = p256_verify(Span(self._peer_key.key), digest, Span(raw))
        elif self._peer_key.algorithm == KEY_ALGORITHM_EC_P384:
            var raw = ecdsa_signature_from_der(signature_der, 48)
            ok = p384_verify(Span(self._peer_key.key), digest, Span(raw))
        if not ok:
            raise Error("dtls: bad handshake signature")

    def _compute_premaster(mut self, peer_public: Span[UInt8, _]) raises:
        # Client side: the premaster is stashed until ClientKeyExchange has
        # been added to the transcript (the extended master secret covers it).
        var premaster = p256_ecdh(Span(self._ecdh_private), peer_public)
        self._master_secret = List[UInt8](Span(premaster))

    def _derive_keys(mut self, premaster: Span[UInt8, _]) raises:
        var master: List[UInt8]
        if self._use_ems:
            var session_hash = self._transcript_hash()
            master = prf_sha256(
                premaster, "extended master secret", Span(session_hash), 48
            )
        else:
            var ms_seed = self._client_random()
            var ms_tail = self._server_random()
            put_bytes(ms_seed, Span(ms_tail))
            master = prf_sha256(premaster, "master secret", Span(ms_seed), 48)
        var seed = self._server_random()
        var seed_tail = self._client_random()
        put_bytes(seed, Span(seed_tail))
        var kb = prf_sha256(Span(master), "key expansion", Span(seed), 40)
        var client_key = List[UInt8](Span(kb)[0:16])
        var server_key = List[UInt8](Span(kb)[16:32])
        var client_iv = List[UInt8](Span(kb)[32:36])
        var server_iv = List[UInt8](Span(kb)[36:40])
        var client = RecordCipher(Span(client_key), Span(client_iv))
        var server = RecordCipher(Span(server_key), Span(server_iv))
        if self._config.is_client:
            self._write_cipher = client^
            self._pending_read_cipher = server^
        else:
            self._write_cipher = server^
            self._pending_read_cipher = client^
        self._master_secret = master^

    def _client_random(self) -> List[UInt8]:
        if self._config.is_client:
            return self._local_random.copy()
        return self._remote_random.copy()

    def _server_random(self) -> List[UInt8]:
        if self._config.is_client:
            return self._remote_random.copy()
        return self._local_random.copy()

    def _finished_data(self, label: StringSpan) -> List[UInt8]:
        var digest = self._transcript_hash()
        return prf_sha256(Span(self._master_secret), label, Span(digest), 12)

    def _check_finished(self, body: Span[UInt8, _], label: StringSpan) raises:
        var expected = self._finished_data(label)
        if not constant_time_eq(Span(expected), body):
            raise Error("dtls: Finished verification failed")

    # ===------------------------------------------------------------------=== #
    # Flights
    # ===------------------------------------------------------------------=== #

    def _queue_handshake(
        mut self, msg_type: UInt8, body: Span[UInt8, _], in_transcript: Bool
    ):
        var seq = self._next_send_seq
        self._next_send_seq += 1
        if in_transcript:
            self._transcript_add(msg_type, Int(seq), body)
        var max_fragment = (
            self._config.mtu - RECORD_HEADER_LEN - HS_HEADER_LEN - AEAD_OVERHEAD
        )
        var offset = 0
        while True:
            var n = min(max_fragment, len(body) - offset)
            var item = List[UInt8](capacity=HS_HEADER_LEN + n)
            put_handshake_header(item, msg_type, len(body), seq, offset, n)
            put_bytes(item, body[offset : offset + n])
            self._flight.append(
                _FlightItem(CT_HANDSHAKE, self._write_epoch, item^)
            )
            offset += n
            if offset >= len(body):
                break

    def _queue_change_cipher_spec(mut self):
        var one: List[UInt8] = [1]
        self._flight.append(_FlightItem(CT_CHANGE_CIPHER_SPEC, 0, one^))
        self._write_epoch = 1

    def _begin_flight(mut self):
        self._flight.clear()
        self._retransmits = 0
        self._retransmit_interval = self._config.retransmit_ms

    def _emit_flight(mut self, now_ms: Int):
        var datagram = List[UInt8]()
        for i in range(len(self._flight)):
            var record = List[UInt8]()
            if self._flight[i].epoch == 0:
                put_plain_record(
                    record,
                    self._flight[i].content_type,
                    0,
                    self._write_seq0,
                    Span(self._flight[i].body),
                )
                self._write_seq0 += 1
            else:
                try:
                    self._write_cipher.value().seal(
                        record,
                        self._flight[i].content_type,
                        1,
                        self._write_seq1,
                        Span(self._flight[i].body),
                    )
                except:
                    continue
                self._write_seq1 += 1
            if len(datagram) > 0 and (
                len(datagram) + len(record) > self._config.mtu
            ):
                var full = List[UInt8]()
                swap(full, datagram)
                self._out.append(full^)
            put_bytes(datagram, Span(record))
        if len(datagram) > 0:
            self._out.append(datagram^)
        self._last_flight_ms = now_ms
        self._retransmit_at = now_ms + self._retransmit_interval

    def _retransmit_on_duplicate(mut self, now_ms: Int):
        if len(self._flight) == 0:
            return
        if now_ms - self._last_flight_ms < _MIN_RETRANSMIT_GAP_MS:
            return
        self._emit_flight(now_ms)

    def _send_client_hello(mut self, var cookie: List[UInt8], now_ms: Int):
        var ch = ClientHello()
        ch.random = self._local_random.copy()
        ch.cookie = cookie^
        ch.cipher_suites.append(CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256)
        ch.supported_groups.append(GROUP_SECP256R1)
        ch.signature_algorithms.append(SIG_ECDSA_SHA256)
        ch.srtp_profiles.append(SRTP_AEAD_AES_128_GCM)
        ch.srtp_profiles.append(SRTP_AES128_CM_HMAC_SHA1_80)
        ch.extended_master_secret = True
        ch.renegotiation_info = True
        ch.ec_point_formats = True
        var body = List[UInt8]()
        ch.encode(body)
        # Kept aside: the transcript starts with the ClientHello the server
        # finally answers, which is this one unless a HelloVerifyRequest
        # arrives.
        self._client_hello_msg = List[UInt8]()
        put_handshake_header(
            self._client_hello_msg,
            HS_CLIENT_HELLO,
            len(body),
            self._next_send_seq,
            0,
            len(body),
        )
        put_bytes(self._client_hello_msg, Span(body))
        self._begin_flight()
        self._queue_handshake(HS_CLIENT_HELLO, Span(body), False)
        self._emit_flight(now_ms)

    def _send_server_hello_flight(
        mut self, ch: ClientHello, now_ms: Int
    ) raises:
        self._begin_flight()
        var sh = ServerHello()
        sh.random = self._local_random.copy()
        sh.cipher_suite = CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256
        sh.srtp_profile = self._srtp_profile
        sh.extended_master_secret = self._use_ems
        sh.renegotiation_info = ch.renegotiation_info
        sh.ec_point_formats = ch.ec_point_formats
        var body = List[UInt8]()
        sh.encode(body)
        self._queue_handshake(HS_SERVER_HELLO, Span(body), True)

        var cert = List[UInt8]()
        encode_certificate(cert, Span(self._config.certificate))
        self._queue_handshake(HS_CERTIFICATE, Span(cert), True)

        var ske = ServerKeyExchange()
        ske.named_curve = GROUP_SECP256R1
        ske.public_key = self._ecdh_public.copy()
        ske.signature_algorithm = SIG_ECDSA_SHA256
        var signed = self._remote_random.copy()
        put_bytes(signed, Span(self._local_random))
        ske.encode_params(signed)
        var digest = sha256(Span(signed))
        var raw = p256_sign(Span(self._config.private_key), Span(digest))
        ske.signature = ecdsa_signature_to_der(Span(raw))
        var ske_body = List[UInt8]()
        ske.encode(ske_body)
        self._queue_handshake(HS_SERVER_KEY_EXCHANGE, Span(ske_body), True)

        var algs: List[UInt16] = [SIG_ECDSA_SHA256]
        var cr = List[UInt8]()
        encode_certificate_request(cr, Span(algs))
        self._queue_handshake(HS_CERTIFICATE_REQUEST, Span(cr), True)

        var empty = List[UInt8]()
        self._queue_handshake(HS_SERVER_HELLO_DONE, Span(empty), True)
        self._emit_flight(now_ms)

    def _send_client_key_flight(mut self, now_ms: Int) raises:
        self._begin_flight()
        if self._cert_requested:
            var cert = List[UInt8]()
            encode_certificate(cert, Span(self._config.certificate))
            self._queue_handshake(HS_CERTIFICATE, Span(cert), True)

        var cke = List[UInt8]()
        encode_client_key_exchange(cke, Span(self._ecdh_public))
        self._queue_handshake(HS_CLIENT_KEY_EXCHANGE, Span(cke), True)

        # `_master_secret` holds the premaster until now (see
        # `_compute_premaster`).
        var premaster = self._master_secret.copy()
        self._derive_keys(Span(premaster))

        if self._cert_requested:
            var digest = self._transcript_hash()
            var raw = p256_sign(Span(self._config.private_key), Span(digest))
            var sig = ecdsa_signature_to_der(Span(raw))
            var cv = List[UInt8]()
            encode_certificate_verify(cv, SIG_ECDSA_SHA256, Span(sig))
            self._queue_handshake(HS_CERTIFICATE_VERIFY, Span(cv), True)

        self._queue_change_cipher_spec()
        var finished = self._finished_data("client finished")
        self._queue_handshake(HS_FINISHED, Span(finished), True)
        self._emit_flight(now_ms)

    def _send_server_finished_flight(mut self, now_ms: Int):
        self._begin_flight()
        self._queue_change_cipher_spec()
        var finished = self._finished_data("server finished")
        self._queue_handshake(HS_FINISHED, Span(finished), True)
        self._emit_flight(now_ms)

    # ===------------------------------------------------------------------=== #
    # Alerts and failure
    # ===------------------------------------------------------------------=== #

    def _send_alert(mut self, level: UInt8, description: UInt8):
        var body: List[UInt8] = [level, description]
        var datagram = List[UInt8]()
        if self._write_epoch == 1 and self._write_cipher is not None:
            try:
                self._write_cipher.value().seal(
                    datagram, CT_ALERT, 1, self._write_seq1, Span(body)
                )
                self._write_seq1 += 1
            except:
                return
        else:
            put_plain_record(
                datagram, CT_ALERT, 0, self._write_seq0, Span(body)
            )
            self._write_seq0 += 1
        self._out.append(datagram^)

    def _fail(mut self, reason: StringSpan, alert: UInt8):
        if self._state == DTLS_STATE_FAILED:
            return
        self._send_alert(ALERT_LEVEL_FATAL, alert)
        self._state = DTLS_STATE_FAILED
        self._failure = String(reason)
        self._flight.clear()
