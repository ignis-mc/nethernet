"""DTLS handshake message bodies and the 12-byte handshake header.

Each message type has a small struct with `encode()` and a static `decode()`.
Only the fields and extensions WebRTC needs are modelled; unknown extensions
are skipped.
"""

from ..wire import Reader, put_bytes, put_u16, put_u24, put_u8

comptime DTLS_VERSION_1_2 = 0xFEFD
comptime DTLS_VERSION_1_0 = 0xFEFF

comptime HS_CLIENT_HELLO = 1
comptime HS_SERVER_HELLO = 2
comptime HS_HELLO_VERIFY_REQUEST = 3
comptime HS_CERTIFICATE = 11
comptime HS_SERVER_KEY_EXCHANGE = 12
comptime HS_CERTIFICATE_REQUEST = 13
comptime HS_SERVER_HELLO_DONE = 14
comptime HS_CERTIFICATE_VERIFY = 15
comptime HS_CLIENT_KEY_EXCHANGE = 16
comptime HS_FINISHED = 20

comptime HS_HEADER_LEN = 12

comptime CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xC02B
comptime GROUP_SECP256R1 = 0x0017
comptime SIG_ECDSA_SHA256 = 0x0403
comptime SIG_ECDSA_SHA384 = 0x0503
comptime SIG_ECDSA_SHA512 = 0x0603

comptime EXT_SUPPORTED_GROUPS = 0x000A
comptime EXT_EC_POINT_FORMATS = 0x000B
comptime EXT_SIGNATURE_ALGORITHMS = 0x000D
comptime EXT_USE_SRTP = 0x000E
comptime EXT_EXTENDED_MASTER_SECRET = 0x0017
comptime EXT_RENEGOTIATION_INFO = 0xFF01

comptime SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
comptime SRTP_AEAD_AES_128_GCM = 0x0007
comptime SRTP_AEAD_AES_256_GCM = 0x0008

comptime CERT_TYPE_RSA_SIGN = 1
comptime CERT_TYPE_ECDSA_SIGN = 64


def put_handshake_header(
    mut out: List[UInt8],
    msg_type: UInt8,
    length: Int,
    message_seq: UInt16,
    fragment_offset: Int,
    fragment_length: Int,
):
    """Appends a DTLS handshake header.

    Args:
        out: The buffer to append to.
        msg_type: The handshake message type.
        length: The length of the whole message body.
        message_seq: The message sequence number.
        fragment_offset: The offset of this fragment within the body.
        fragment_length: The length of this fragment.
    """
    put_u8(out, msg_type)
    put_u24(out, UInt32(length))
    put_u16(out, message_seq)
    put_u24(out, UInt32(fragment_offset))
    put_u24(out, UInt32(fragment_length))


def _put_extension(mut out: List[UInt8], kind: UInt16, body: Span[UInt8, _]):
    put_u16(out, kind)
    put_u16(out, UInt16(len(body)))
    put_bytes(out, body)


struct ClientHello(Copyable):
    """A ClientHello body."""

    var version: UInt16
    """The offered protocol version."""
    var random: List[UInt8]
    """The 32-byte client random."""
    var session_id: List[UInt8]
    """The session identifier, empty for a new session."""
    var cookie: List[UInt8]
    """The cookie echoed from a HelloVerifyRequest, or empty."""
    var cipher_suites: List[UInt16]
    """The offered cipher suites, most preferred first."""
    var supported_groups: List[UInt16]
    """The offered elliptic-curve groups; empty if the extension is absent."""
    var signature_algorithms: List[UInt16]
    """The offered signature algorithms; empty if the extension is absent."""
    var srtp_profiles: List[UInt16]
    """The offered SRTP protection profiles from `use_srtp`."""
    var extended_master_secret: Bool
    """Whether `extended_master_secret` was offered."""
    var renegotiation_info: Bool
    """Whether an empty `renegotiation_info` was offered."""
    var ec_point_formats: Bool
    """Whether `ec_point_formats` was offered."""

    def __init__(out self):
        """Creates an empty ClientHello for DTLS 1.2."""
        self.version = DTLS_VERSION_1_2
        self.random = List[UInt8]()
        self.session_id = List[UInt8]()
        self.cookie = List[UInt8]()
        self.cipher_suites = List[UInt16]()
        self.supported_groups = List[UInt16]()
        self.signature_algorithms = List[UInt16]()
        self.srtp_profiles = List[UInt16]()
        self.extended_master_secret = False
        self.renegotiation_info = False
        self.ec_point_formats = False

    def encode(self, mut out: List[UInt8]):
        """Appends the encoded body.

        Args:
            out: The buffer to append to.
        """
        put_u16(out, self.version)
        put_bytes(out, Span(self.random))
        put_u8(out, UInt8(len(self.session_id)))
        put_bytes(out, Span(self.session_id))
        put_u8(out, UInt8(len(self.cookie)))
        put_bytes(out, Span(self.cookie))
        put_u16(out, UInt16(2 * len(self.cipher_suites)))
        for cs in self.cipher_suites:
            put_u16(out, cs)
        put_u8(out, 1)
        put_u8(out, 0)

        var ext = List[UInt8]()
        if len(self.supported_groups) > 0:
            var b = List[UInt8]()
            put_u16(b, UInt16(2 * len(self.supported_groups)))
            for g in self.supported_groups:
                put_u16(b, g)
            _put_extension(ext, EXT_SUPPORTED_GROUPS, Span(b))
        if self.ec_point_formats:
            var b: List[UInt8] = [1, 0]
            _put_extension(ext, EXT_EC_POINT_FORMATS, Span(b))
        if len(self.signature_algorithms) > 0:
            var b = List[UInt8]()
            put_u16(b, UInt16(2 * len(self.signature_algorithms)))
            for s in self.signature_algorithms:
                put_u16(b, s)
            _put_extension(ext, EXT_SIGNATURE_ALGORITHMS, Span(b))
        if len(self.srtp_profiles) > 0:
            var b = List[UInt8]()
            put_u16(b, UInt16(2 * len(self.srtp_profiles)))
            for p in self.srtp_profiles:
                put_u16(b, p)
            put_u8(b, 0)
            _put_extension(ext, EXT_USE_SRTP, Span(b))
        if self.extended_master_secret:
            var b = List[UInt8]()
            _put_extension(ext, EXT_EXTENDED_MASTER_SECRET, Span(b))
        if self.renegotiation_info:
            var b: List[UInt8] = [0]
            _put_extension(ext, EXT_RENEGOTIATION_INFO, Span(b))
        if len(ext) > 0:
            put_u16(out, UInt16(len(ext)))
            put_bytes(out, Span(ext))

    @staticmethod
    def decode(body: Span[UInt8, _]) raises -> ClientHello:
        """Decodes a ClientHello body.

        Args:
            body: The message body without the handshake header.

        Returns:
            The decoded message.

        Raises:
            Error: If the body is malformed.
        """
        var r = Reader(body)
        var ch = ClientHello()
        ch.version = r.u16()
        ch.random = List[UInt8](r.bytes(32))
        ch.session_id = List[UInt8](r.bytes(Int(r.u8())))
        ch.cookie = List[UInt8](r.bytes(Int(r.u8())))
        var cs_len = Int(r.u16())
        if cs_len % 2 != 0:
            raise Error("ClientHello: odd cipher suite length")
        var cs = Reader(r.bytes(cs_len))
        while not cs.at_end():
            ch.cipher_suites.append(cs.u16())
        r.skip(Int(r.u8()))
        if r.at_end():
            return ch^
        var ext = Reader(r.bytes(Int(r.u16())))
        while not ext.at_end():
            var kind = ext.u16()
            var e = Reader(ext.bytes(Int(ext.u16())))
            if kind == EXT_SUPPORTED_GROUPS:
                var g = Reader(e.bytes(Int(e.u16())))
                while g.remaining() >= 2:
                    ch.supported_groups.append(g.u16())
            elif kind == EXT_SIGNATURE_ALGORITHMS:
                var s = Reader(e.bytes(Int(e.u16())))
                while s.remaining() >= 2:
                    ch.signature_algorithms.append(s.u16())
            elif kind == EXT_USE_SRTP:
                var p = Reader(e.bytes(Int(e.u16())))
                while p.remaining() >= 2:
                    ch.srtp_profiles.append(p.u16())
            elif kind == EXT_EXTENDED_MASTER_SECRET:
                ch.extended_master_secret = True
            elif kind == EXT_RENEGOTIATION_INFO:
                ch.renegotiation_info = True
            elif kind == EXT_EC_POINT_FORMATS:
                ch.ec_point_formats = True
        return ch^


struct ServerHello(Copyable):
    """A ServerHello body."""

    var version: UInt16
    """The selected protocol version."""
    var random: List[UInt8]
    """The 32-byte server random."""
    var session_id: List[UInt8]
    """The session identifier."""
    var cipher_suite: UInt16
    """The selected cipher suite."""
    var srtp_profile: UInt16
    """The selected SRTP profile, or 0 if `use_srtp` is absent."""
    var extended_master_secret: Bool
    """Whether the server accepted `extended_master_secret`."""
    var renegotiation_info: Bool
    """Whether `renegotiation_info` is present."""
    var ec_point_formats: Bool
    """Whether `ec_point_formats` is present."""

    def __init__(out self):
        """Creates an empty ServerHello for DTLS 1.2."""
        self.version = DTLS_VERSION_1_2
        self.random = List[UInt8]()
        self.session_id = List[UInt8]()
        self.cipher_suite = 0
        self.srtp_profile = 0
        self.extended_master_secret = False
        self.renegotiation_info = False
        self.ec_point_formats = False

    def encode(self, mut out: List[UInt8]):
        """Appends the encoded body.

        Args:
            out: The buffer to append to.
        """
        put_u16(out, self.version)
        put_bytes(out, Span(self.random))
        put_u8(out, UInt8(len(self.session_id)))
        put_bytes(out, Span(self.session_id))
        put_u16(out, self.cipher_suite)
        put_u8(out, 0)
        var ext = List[UInt8]()
        if self.renegotiation_info:
            var b: List[UInt8] = [0]
            _put_extension(ext, EXT_RENEGOTIATION_INFO, Span(b))
        if self.extended_master_secret:
            var b = List[UInt8]()
            _put_extension(ext, EXT_EXTENDED_MASTER_SECRET, Span(b))
        if self.srtp_profile != 0:
            var b = List[UInt8]()
            put_u16(b, 2)
            put_u16(b, self.srtp_profile)
            put_u8(b, 0)
            _put_extension(ext, EXT_USE_SRTP, Span(b))
        if self.ec_point_formats:
            var b: List[UInt8] = [1, 0]
            _put_extension(ext, EXT_EC_POINT_FORMATS, Span(b))
        if len(ext) > 0:
            put_u16(out, UInt16(len(ext)))
            put_bytes(out, Span(ext))

    @staticmethod
    def decode(body: Span[UInt8, _]) raises -> ServerHello:
        """Decodes a ServerHello body.

        Args:
            body: The message body without the handshake header.

        Returns:
            The decoded message.

        Raises:
            Error: If the body is malformed.
        """
        var r = Reader(body)
        var sh = ServerHello()
        sh.version = r.u16()
        sh.random = List[UInt8](r.bytes(32))
        sh.session_id = List[UInt8](r.bytes(Int(r.u8())))
        sh.cipher_suite = r.u16()
        if r.u8() != 0:
            raise Error("ServerHello: compression is not supported")
        if r.at_end():
            return sh^
        var ext = Reader(r.bytes(Int(r.u16())))
        while not ext.at_end():
            var kind = ext.u16()
            var e = Reader(ext.bytes(Int(ext.u16())))
            if kind == EXT_USE_SRTP:
                var p = Reader(e.bytes(Int(e.u16())))
                if p.remaining() >= 2:
                    sh.srtp_profile = p.u16()
            elif kind == EXT_EXTENDED_MASTER_SECRET:
                sh.extended_master_secret = True
            elif kind == EXT_RENEGOTIATION_INFO:
                sh.renegotiation_info = True
            elif kind == EXT_EC_POINT_FORMATS:
                sh.ec_point_formats = True
        return sh^


def encode_hello_verify_request(mut out: List[UInt8], cookie: Span[UInt8, _]):
    """Appends a HelloVerifyRequest body.

    Args:
        out: The buffer to append to.
        cookie: The cookie the client must echo, at most 255 bytes.
    """
    put_u16(out, DTLS_VERSION_1_2)
    put_u8(out, UInt8(len(cookie)))
    put_bytes(out, cookie)


def decode_hello_verify_request(body: Span[UInt8, _]) raises -> List[UInt8]:
    """Decodes a HelloVerifyRequest body.

    Args:
        body: The message body without the handshake header.

    Returns:
        The cookie to echo in the next ClientHello.

    Raises:
        Error: If the body is malformed.
    """
    var r = Reader(body)
    r.skip(2)
    return List[UInt8](r.bytes(Int(r.u8())))


def encode_certificate(mut out: List[UInt8], cert_der: Span[UInt8, _]):
    """Appends a Certificate body holding one certificate.

    Args:
        out: The buffer to append to.
        cert_der: The DER-encoded certificate; empty encodes an empty list.
    """
    if len(cert_der) == 0:
        put_u24(out, 0)
        return
    put_u24(out, UInt32(len(cert_der) + 3))
    put_u24(out, UInt32(len(cert_der)))
    put_bytes(out, cert_der)


def decode_certificate(body: Span[UInt8, _]) raises -> List[UInt8]:
    """Decodes a Certificate body and returns the end-entity certificate.

    Args:
        body: The message body without the handshake header.

    Returns:
        The first certificate in DER form, or an empty list if the peer sent
        no certificate.

    Raises:
        Error: If the body is malformed.
    """
    var r = Reader(body)
    var list = Reader(r.bytes(Int(r.u24())))
    if list.at_end():
        return List[UInt8]()
    return List[UInt8](list.bytes(Int(list.u24())))


struct ServerKeyExchange(Copyable):
    """An ECDHE ServerKeyExchange body."""

    var named_curve: UInt16
    """The named group of the ephemeral key."""
    var public_key: List[UInt8]
    """The server's ephemeral public key as an uncompressed point."""
    var signature_algorithm: UInt16
    """The signature scheme, for example `SIG_ECDSA_SHA256`."""
    var signature: List[UInt8]
    """The signature over the randoms and the parameters."""

    def __init__(out self):
        """Creates an empty message."""
        self.named_curve = 0
        self.public_key = List[UInt8]()
        self.signature_algorithm = 0
        self.signature = List[UInt8]()

    def encode_params(self, mut out: List[UInt8]):
        """Appends the signed `ServerECDHParams` portion.

        Args:
            out: The buffer to append to.
        """
        put_u8(out, 3)
        put_u16(out, self.named_curve)
        put_u8(out, UInt8(len(self.public_key)))
        put_bytes(out, Span(self.public_key))

    def encode(self, mut out: List[UInt8]):
        """Appends the encoded body.

        Args:
            out: The buffer to append to.
        """
        self.encode_params(out)
        put_u16(out, self.signature_algorithm)
        put_u16(out, UInt16(len(self.signature)))
        put_bytes(out, Span(self.signature))

    @staticmethod
    def decode(body: Span[UInt8, _]) raises -> ServerKeyExchange:
        """Decodes an ECDHE ServerKeyExchange body.

        Args:
            body: The message body without the handshake header.

        Returns:
            The decoded message.

        Raises:
            Error: If the body is malformed or not a named-curve exchange.
        """
        var r = Reader(body)
        var ske = ServerKeyExchange()
        if r.u8() != 3:
            raise Error("ServerKeyExchange: only named curves are supported")
        ske.named_curve = r.u16()
        ske.public_key = List[UInt8](r.bytes(Int(r.u8())))
        ske.signature_algorithm = r.u16()
        ske.signature = List[UInt8](r.bytes(Int(r.u16())))
        return ske^


def encode_certificate_request(
    mut out: List[UInt8], signature_algorithms: Span[UInt16, _]
):
    """Appends a CertificateRequest body asking for an ECDSA or RSA certificate.

    Args:
        out: The buffer to append to.
        signature_algorithms: The signature schemes the server can verify.
    """
    put_u8(out, 2)
    put_u8(out, CERT_TYPE_ECDSA_SIGN)
    put_u8(out, CERT_TYPE_RSA_SIGN)
    put_u16(out, UInt16(2 * len(signature_algorithms)))
    for s in signature_algorithms:
        put_u16(out, s)
    put_u16(out, 0)


def encode_client_key_exchange(mut out: List[UInt8], public_key: Span[UInt8, _]):
    """Appends an ECDHE ClientKeyExchange body.

    Args:
        out: The buffer to append to.
        public_key: The client's ephemeral public key, uncompressed.
    """
    put_u8(out, UInt8(len(public_key)))
    put_bytes(out, public_key)


def decode_client_key_exchange(body: Span[UInt8, _]) raises -> List[UInt8]:
    """Decodes an ECDHE ClientKeyExchange body.

    Args:
        body: The message body without the handshake header.

    Returns:
        The client's ephemeral public key.

    Raises:
        Error: If the body is malformed.
    """
    var r = Reader(body)
    return List[UInt8](r.bytes(Int(r.u8())))


def encode_certificate_verify(
    mut out: List[UInt8], signature_algorithm: UInt16, signature: Span[UInt8, _]
):
    """Appends a CertificateVerify body.

    Args:
        out: The buffer to append to.
        signature_algorithm: The signature scheme used.
        signature: The signature over the handshake transcript.
    """
    put_u16(out, signature_algorithm)
    put_u16(out, UInt16(len(signature)))
    put_bytes(out, signature)


struct CertificateVerify(Copyable):
    """A CertificateVerify body."""

    var signature_algorithm: UInt16
    """The signature scheme used."""
    var signature: List[UInt8]
    """The signature over the handshake transcript."""

    def __init__(out self):
        """Creates an empty message."""
        self.signature_algorithm = 0
        self.signature = List[UInt8]()

    @staticmethod
    def decode(body: Span[UInt8, _]) raises -> CertificateVerify:
        """Decodes a CertificateVerify body.

        Args:
            body: The message body without the handshake header.

        Returns:
            The decoded message.

        Raises:
            Error: If the body is malformed.
        """
        var r = Reader(body)
        var cv = CertificateVerify()
        cv.signature_algorithm = r.u16()
        cv.signature = List[UInt8](r.bytes(Int(r.u16())))
        return cv^
