"""The `a=identity` assertion: binding a DTLS fingerprint to a P-384 key.

NetherNet peers prove who they are by signing their DTLS certificate
fingerprint with an ECDSA P-384 key and shipping the result in the SDP:

    a=identity:<base64 of {"assertion":"<JSON string>","idp":{...}}>

The assertion string is itself JSON with two members:

- `fingerprints`: a detached ES384 JWS (`header..signature`) whose payload is
  `{"fingerprint":[{"algorithm":"sha-256","digest":"AA:BB:…"}]}`, rebuilt by
  the verifier from the SDP it received.
- `token`: an ES384 JWT whose `cpk` claim carries the public key, either as a
  JWK object or as base64 PKIX DER.

A self-signed token proves only possession of the key. Deciding whether that
key is trusted (first use, a pinned key, an Xbox-issued chain) is the
caller's business.
"""

from ..crypto.base64 import (
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
)
from ..crypto.p384 import p384_public_key, p384_sign, p384_verify
from ..crypto.sha512 import sha384
from ..crypto.x509 import (
    KEY_ALGORITHM_EC_P384,
    encode_ec_public_key_info,
    parse_public_key_info,
)
from ..json import json_parse_int, json_parse_object, json_parse_string, json_quote

comptime IDENTITY_DOMAIN_SERVER: StaticString = "self"
"""The identity-provider domain go-nethernet servers use."""
comptime IDENTITY_DOMAIN_CLIENT: StaticString = "https://authorization.franchise.minecraft-services.net/"
"""The identity-provider domain clients use."""
comptime TOKEN_LIFETIME_S = 60
"""How long a freshly issued token is valid."""
comptime CLOCK_LEEWAY_S = 60
"""The clock difference tolerated when checking a token's time claims."""

comptime _ES384_HEADER: StaticString = "{\"alg\":\"ES384\"}"


def fingerprint_payload(algorithm: StringSpan, digest: StringSpan) -> String:
    """Builds the JWS payload that binds one DTLS fingerprint.

    Args:
        algorithm: The hash name exactly as in `a=fingerprint`.
        digest: The colon-separated hex exactly as in `a=fingerprint`.

    Returns:
        The canonical JSON text both sides sign and verify.
    """
    return String(
        t"{{\"fingerprint\":[{{\"algorithm\":{json_quote(algorithm)},\"digest\":{json_quote(digest)}}}]}}"
    )


def _sign_es384(
    private_key: Span[UInt8, _], header_b64: StringSpan, payload_b64: StringSpan
) raises -> String:
    var input = String(t"{header_b64}.{payload_b64}")
    var digest = sha384(input.as_bytes())
    var signature = p384_sign(private_key, Span(digest))
    return base64url_encode(Span(signature))


def _verify_es384(
    public_key: Span[UInt8, _],
    header_b64: StringSpan,
    payload_b64: StringSpan,
    signature_b64: StringSpan,
) raises -> Bool:
    var header = json_parse_object(
        String(unsafe_from_utf8=Span(base64url_decode(header_b64)))
    )
    if "alg" not in header or json_parse_string(header["alg"]) != "ES384":
        raise Error("identity: unsupported signature algorithm")
    var signature = base64url_decode(signature_b64)
    var input = String(t"{header_b64}.{payload_b64}")
    var digest = sha384(input.as_bytes())
    return p384_verify(public_key, Span(digest), Span(signature))


def _split3(text: StringSpan) raises -> List[String]:
    var parts = List[String]()
    for p in text.split("."):
        parts.append(String(p))
    if len(parts) != 3:
        raise Error("identity: expected three dot-separated parts")
    return parts^


struct Identity(Copyable):
    """A local identity: a P-384 key and a token that presents its public half."""

    var private_key: List[UInt8]
    """The 48-byte P-384 private scalar."""
    var token: String
    """The JWT carrying the public key in its `cpk` claim."""
    var domain: String
    """The identity-provider domain announced with the assertion."""

    def __init__(
        out self, private_key: Span[UInt8, _], token: StringSpan, domain: StringSpan
    ):
        """Wraps an existing key and token, for example an Xbox-issued one.

        Args:
            private_key: The 48-byte P-384 private scalar.
            token: The JWT that presents the matching public key.
            domain: The identity-provider domain.
        """
        self.private_key = List[UInt8](private_key)
        self.token = String(token)
        self.domain = String(domain)

    @staticmethod
    def self_signed(
        private_key: Span[UInt8, _],
        domain: StringSpan,
        now_unix_s: Int,
        jwk: Bool,
    ) raises -> Identity:
        """Issues a token signed by the key it presents.

        Args:
            private_key: The 48-byte P-384 private scalar.
            domain: The identity-provider domain.
            now_unix_s: The current wall-clock time in Unix seconds.
            jwk: `True` to write the `cpk` claim as a JWK object (what
                servers do), `False` for base64 PKIX DER (what clients do).

        Returns:
            The identity, valid for `TOKEN_LIFETIME_S` seconds.

        Raises:
            Error: If the private key is invalid.
        """
        var point = p384_public_key(private_key)
        var pkix = encode_ec_public_key_info(KEY_ALGORITHM_EC_P384, Span(point))
        var pkix_b64 = base64_encode(Span(pkix))
        var cpk: String
        if jwk:
            var x = base64url_encode(Span(point)[1:49])
            var y = base64url_encode(Span(point)[49:97])
            cpk = String(
                t"{{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"{x}\",\"y\":\"{y}\"}}"
            )
        else:
            cpk = json_quote(pkix_b64)
        var header = String(
            t"{{\"alg\":\"ES384\",\"x5u\":{json_quote(pkix_b64)}}}"
        )
        var claims = String(
            t"{{\"exp\":{now_unix_s + TOKEN_LIFETIME_S},\"iat\":{now_unix_s},\"cpk\":{cpk}}}"
        )
        var header_b64 = base64url_encode(header.as_bytes())
        var claims_b64 = base64url_encode(claims.as_bytes())
        var signature = _sign_es384(private_key, header_b64, claims_b64)
        return Identity(
            private_key, String(t"{header_b64}.{claims_b64}.{signature}"), domain
        )

    def sign(self, algorithm: StringSpan, digest: StringSpan) raises -> String:
        """Produces the `a=identity` value for a DTLS fingerprint.

        Args:
            algorithm: The hash name exactly as it will appear in
                `a=fingerprint`.
            digest: The colon-separated hex exactly as it will appear in
                `a=fingerprint`.

        Returns:
            The base64 text that follows `a=identity:`.

        Raises:
            Error: If signing fails.
        """
        var header_b64 = base64url_encode(_ES384_HEADER.as_bytes())
        var payload = fingerprint_payload(algorithm, digest)
        var payload_b64 = base64url_encode(payload.as_bytes())
        var signature = _sign_es384(
            Span(self.private_key), header_b64, payload_b64
        )
        var assertion = String(
            t"{{\"fingerprints\":{json_quote(String(t'{header_b64}..{signature}'))},\"token\":{json_quote(self.token)}}}"
        )
        var document = String(
            t"{{\"assertion\":{json_quote(assertion)},\"idp\":{{\"domain\":{json_quote(self.domain)},\"protocol\":\"default\"}}}}"
        )
        return base64_encode(document.as_bytes())


struct RemoteIdentity(Copyable):
    """An identity assertion received in a peer's SDP."""

    var fingerprints: String
    """The detached JWS over the fingerprint payload."""
    var token: String
    """The JWT that presents the peer's public key."""
    var domain: String
    """The identity-provider domain the peer announced."""
    var protocol: String
    """The identity-provider protocol; always `default`."""

    def __init__(out self):
        """Creates an empty assertion."""
        self.fingerprints = String()
        self.token = String()
        self.domain = String()
        self.protocol = String()

    @staticmethod
    def parse(value: StringSpan) raises -> RemoteIdentity:
        """Decodes the value of an `a=identity` attribute.

        Args:
            value: The base64 text that follows `a=identity:`.

        Returns:
            The decoded assertion.

        Raises:
            Error: If the base64 or the JSON inside is malformed, or the
                assertion is not well formed.
        """
        var document = json_parse_object(
            String(unsafe_from_utf8=Span(base64_decode(value)))
        )
        var id = RemoteIdentity()
        if "assertion" not in document or "idp" not in document:
            raise Error("identity: missing assertion or provider")
        var assertion = json_parse_object(
            json_parse_string(document["assertion"])
        )
        if "fingerprints" in assertion:
            id.fingerprints = json_parse_string(assertion["fingerprints"])
        if "token" in assertion:
            id.token = json_parse_string(assertion["token"])
        var idp = json_parse_object(document["idp"])
        if "domain" in idp:
            id.domain = json_parse_string(idp["domain"])
        if "protocol" in idp:
            id.protocol = json_parse_string(idp["protocol"])
        if not id.is_valid():
            raise Error("identity: malformed assertion")
        return id^

    def is_valid(self) -> Bool:
        """Checks the shape of the assertion without verifying signatures.

        Returns:
            `True` if both parts are three-part compact JWS strings and the
            provider protocol is `default`.
        """

        def dots(text: StringSpan) {} -> Int:
            var n = 0
            for c in text.as_bytes():
                if c == 0x2E:
                    n += 1
            return n

        return (
            self.token.byte_length() > 0
            and dots(self.token) == 2
            and self.fingerprints.byte_length() > 0
            and dots(self.fingerprints) == 2
            and self.protocol == "default"
        )

    def public_key(self, self_signed: Bool, now_unix_s: Int) raises -> List[UInt8]:
        """Extracts the P-384 public key the token presents.

        Args:
            self_signed: `True` to require that the token is signed by the
                key it presents (time claims are then not checked); `False`
                to check the time claims only, leaving the token's signature
                to whoever trusts its issuer.
            now_unix_s: The current wall-clock time in Unix seconds.

        Returns:
            The uncompressed 97-byte P-384 point.

        Raises:
            Error: If the token is malformed, uses another key type, fails
                its own signature check, or is expired or not yet valid.
        """
        var parts = _split3(self.token)
        var claims = json_parse_object(
            String(unsafe_from_utf8=Span(base64url_decode(parts[1])))
        )
        if "cpk" not in claims:
            raise Error("identity: token has no cpk claim")
        var cpk = claims["cpk"].copy()
        var point: List[UInt8]
        if cpk.startswith("{"):
            var jwk = json_parse_object(cpk)
            if (
                "kty" not in jwk
                or "crv" not in jwk
                or "x" not in jwk
                or "y" not in jwk
                or json_parse_string(jwk["kty"]) != "EC"
                or json_parse_string(jwk["crv"]) != "P-384"
            ):
                raise Error("identity: unsupported key in cpk claim")
            var x = base64url_decode(json_parse_string(jwk["x"]))
            var y = base64url_decode(json_parse_string(jwk["y"]))
            if len(x) != 48 or len(y) != 48:
                raise Error("identity: malformed key in cpk claim")
            point = List[UInt8](capacity=97)
            point.append(0x04)
            point.extend(Span(x))
            point.extend(Span(y))
        else:
            var info = parse_public_key_info(
                Span(base64_decode(json_parse_string(cpk)))
            )
            if info.algorithm != KEY_ALGORITHM_EC_P384:
                raise Error("identity: unsupported key in cpk claim")
            point = info.key.copy()
        if self_signed:
            if not _verify_es384(Span(point), parts[0], parts[1], parts[2]):
                raise Error("identity: token is not signed by its own key")
        else:
            if "exp" in claims:
                if now_unix_s > json_parse_int(claims["exp"]) + CLOCK_LEEWAY_S:
                    raise Error("identity: token has expired")
            if "nbf" in claims:
                if now_unix_s + CLOCK_LEEWAY_S < json_parse_int(claims["nbf"]):
                    raise Error("identity: token is not valid yet")
            if "iat" in claims:
                if now_unix_s + CLOCK_LEEWAY_S < json_parse_int(claims["iat"]):
                    raise Error("identity: token was issued in the future")
        return point^

    def verify(
        self,
        algorithm: StringSpan,
        digest: StringSpan,
        public_key: Span[UInt8, _],
    ) raises:
        """Checks that the key signed the given DTLS fingerprint.

        Args:
            algorithm: The hash name exactly as received in `a=fingerprint`.
            digest: The digest text exactly as received in `a=fingerprint`.
            public_key: The uncompressed P-384 point from `public_key()`.

        Raises:
            Error: If the JWS is malformed or the signature does not match.
        """
        var parts = _split3(self.fingerprints)
        if parts[1].byte_length() != 0:
            raise Error("identity: fingerprints assertion is not detached")
        var payload = fingerprint_payload(algorithm, digest)
        var payload_b64 = base64url_encode(payload.as_bytes())
        if not _verify_es384(public_key, parts[0], payload_b64, parts[2]):
            raise Error("identity: fingerprint signature mismatch")
