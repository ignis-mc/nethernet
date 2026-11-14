"""HTTP signaling: one request carries the offer, its response the answer.

This is the signaling Minecraft uses to join a server by address. The client
first probes `GET /v1/join`, then sends its whole offer, candidates included,
as `POST /v1/join/<client network ID>`; the response body is the answer SDP,
or a decimal error code. There is no trickle ICE and no further signaling.

`EndpointServer` is the server side, to hand to a `Listener`.
`EndpointClient` is the client side, to hand to `dial()` together with
`EndpointClient.url()` as the network ID. Both speak plain HTTP/1.1 over
IPv4; TLS and host-name resolution are out of scope.
"""

from ..json import json_quote
from ..os.addr import SocketAddr
from ..os.poll import PollSet, wait_readable
from ..os.random import random_u64
from ..os.tcp import TcpListener, TcpStream
from ..os.time import monotonic_ms
from ..wire import bytes_equal, put_bytes
from .signal import (
    ERROR_GENERIC_FAILURE,
    ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE,
    SIGNAL_ANSWER,
    SIGNAL_ERROR,
    SIGNAL_OFFER,
    Signal,
    Signaling,
)

comptime MAX_SDP_BODY_SIZE = 1 << 20
"""The largest offer or answer body accepted, as in go-nethernet."""
comptime ENDPOINT_NEGOTIATION_TIMEOUT_MS = 15000
"""How long the server holds a join request waiting for the answer."""

comptime _MAX_HEADER_SIZE = 16384
comptime _READ_HEADER_TIMEOUT_MS = 5000
comptime _READ_TIMEOUT_MS = 10000
comptime _WRITE_TIMEOUT_MS = 2000
comptime _MAX_CONNECTIONS = 256
comptime _NEVER = 0x3FFF_FFFF_FFFF_FFFF

comptime _READING = 0
comptime _WAITING = 1


def _find_header_end(buf: Span[UInt8, _]) -> Int:
    """Returns the index just past the blank line, or -1."""
    var i = 0
    while i + 3 < len(buf):
        if (
            buf[i] == 0x0D
            and buf[i + 1] == 0x0A
            and buf[i + 2] == 0x0D
            and buf[i + 3] == 0x0A
        ):
            return i + 4
        i += 1
    return -1


def _lower(c: UInt8) -> UInt8:
    if c >= 0x41 and c <= 0x5A:
        return c + 0x20
    return c


def _header_value(head: Span[UInt8, _], name: StringSpan) -> Optional[String]:
    """Finds a header by case-insensitive name in a block of header lines."""
    var want = name.as_bytes()
    var line_start = 0
    var i = 0
    while i + 1 < len(head):
        if head[i] == 0x0D and head[i + 1] == 0x0A:
            var line = head[line_start:i]
            if len(line) > len(want) and line[len(want)] == 0x3A:
                var same = True
                for k in range(len(want)):
                    if _lower(line[k]) != _lower(want[k]):
                        same = False
                if same:
                    return String(
                        String(
                            from_utf8_lossy=line[len(want) + 1 : len(line)]
                        ).strip()
                    )
            line_start = i + 2
            i += 2
            continue
        i += 1
    return None


def _parse_uint(text: StringSpan, max_digits: Int) -> Optional[UInt64]:
    var bytes = text.as_bytes()
    if len(bytes) == 0 or len(bytes) > max_digits:
        return None
    var v = UInt64(0)
    for c in bytes:
        if c < 0x30 or c > 0x39:
            return None
        var digit = UInt64(c - 0x30)
        if v > (0xFFFF_FFFF_FFFF_FFFF - digit) // 10:
            return None
        v = v * 10 + digit
    return v


def _response(
    status: StringSpan, content_type: StringSpan, body: StringSpan
) -> List[UInt8]:
    var head = String(t"HTTP/1.1 {status}\r\n")
    if content_type.byte_length() > 0:
        head += String(t"Content-Type: {content_type}\r\n")
    head += String(
        t"Content-Length: {body.byte_length()}\r\nConnection: close\r\n\r\n"
    )
    var out = List[UInt8](head.as_bytes())
    put_bytes(out, body.as_bytes())
    return out^


struct EndpointStatus(Copyable):
    """The server description returned by the `GET /v1/join` probe."""

    var name: String
    """The server name."""
    var protocol: Int
    """The Minecraft network protocol version."""
    var version: String
    """The game version string."""
    var level: String
    """The world name."""
    var players: Int
    """The number of players online."""
    var max_players: Int
    """The player limit."""
    var game_type: Int
    """The game mode: 0 survival, 1 creative, 2 adventure."""

    def __init__(out self):
        """Creates an empty status."""
        self.name = String()
        self.protocol = 0
        self.version = String()
        self.level = String()
        self.players = 0
        self.max_players = 0
        self.game_type = 0

    def encode(self) -> String:
        """Formats the status as the JSON object go-nethernet serves."""
        return String(
            t"{{\"name\":{json_quote(self.name)},\"protocol\":{self.protocol},\"version\":{json_quote(self.version)},\"level\":{json_quote(self.level)},\"players\":{self.players},\"maxPlayers\":{self.max_players},\"gameType\":{self.game_type}}}"
        )


struct _HttpConn(Movable):
    var stream: TcpStream
    var buf: List[UInt8]
    var state: Int
    var started_ms: Int
    var deadline_ms: Int
    var network_id: String
    var connection_id: UInt64

    def __init__(out self, var stream: TcpStream, now_ms: Int):
        self.stream = stream^
        self.buf = List[UInt8]()
        self.state = _READING
        self.started_ms = now_ms
        self.deadline_ms = now_ms + _READ_HEADER_TIMEOUT_MS
        self.network_id = String()
        self.connection_id = 0

    def respond(self, response: Span[UInt8, _]):
        try:
            self.stream.write_all(response, _WRITE_TIMEOUT_MS)
        except:
            pass


struct EndpointServer(Signaling):
    """The server side of HTTP signaling.

    Each `POST /v1/join/<id>` becomes a `CONNECTREQUEST` signal from network
    ID `<id>` with a connection ID invented here; the HTTP response is held
    until the listener signals the answer or an error for that connection.
    """

    var _listener: TcpListener
    var _network_id: String
    var _status: String
    var _conns: List[_HttpConn]
    var _signals: List[Signal]
    var _chunk: List[UInt8]

    def __init__(out self, bind_addr: SocketAddr) raises:
        """Starts listening for HTTP connections."""
        var listener = TcpListener(bind_addr)
        var id = String(random_u64())
        self._listener = listener^
        self._network_id = id
        self._status = String()
        self._conns = List[_HttpConn]()
        self._signals = List[Signal]()
        self._chunk = List[UInt8](length=16384, fill=0)

    def local_addr(self) raises -> SocketAddr:
        """Reads the bound TCP address."""
        return self._listener.local_addr()

    def set_status(mut self, status: EndpointStatus):
        """Sets the body served to the `GET /v1/join` probe.

        Without a status the probe is answered with an empty body, which
        clients accept as well.
        """
        self._status = status.encode()

    def pending_requests(self) -> Int:
        """Counts HTTP connections that are open right now."""
        return len(self._conns)

    # ===------------------------------------------------------------------=== #
    # Signaling
    # ===------------------------------------------------------------------=== #

    def network_id(self) -> String:
        """Gets this server's network ID."""
        return self._network_id.copy()

    def poll_fd(self) -> Int:
        """Gets the listening socket's descriptor."""
        return self._listener.fd()

    def trickle(self) -> Bool:
        """Says that candidates must be embedded in the descriptions."""
        return False

    def add_poll_fds(self, mut set: PollSet):
        """Adds the listening socket and every open HTTP connection."""
        _ = set.add(self._listener.fd())
        for i in range(len(self._conns)):
            if self._conns[i].state == _READING:
                _ = set.add(self._conns[i].stream.fd())

    def poll_signal(mut self) -> Optional[Signal]:
        """Takes the next offer received over HTTP."""
        if len(self._signals) == 0:
            return None
        return self._signals.pop(0)

    def send_signal(mut self, signal: Signal) raises:
        """Completes the HTTP request the signal's connection came from.

        An answer becomes a `200` response with the SDP as its body; an
        error becomes a `500` response with the decimal error code.
        """
        if signal.kind != SIGNAL_ANSWER and signal.kind != SIGNAL_ERROR:
            raise Error("endpoint: only answers and errors can be signaled")
        for i in range(len(self._conns)):
            if (
                self._conns[i].state == _WAITING
                and self._conns[i].connection_id == signal.connection_id
                and self._conns[i].network_id == signal.network_id
            ):
                var conn = self._conns.pop(i)
                if signal.kind == SIGNAL_ANSWER:
                    conn.respond(
                        Span(
                            _response("200 OK", "application/sdp", signal.data)
                        )
                    )
                else:
                    conn.respond(
                        Span(
                            _response(
                                "500 Internal Server Error",
                                "text/plain",
                                String(signal.error_code()),
                            )
                        )
                    )
                return
        raise Error("endpoint: no pending request for this connection")

    def service(mut self, now_ms: Int) raises:
        """Accepts connections, reads requests and expires stale ones."""
        while len(self._conns) < _MAX_CONNECTIONS:
            var accepted = self._listener.accept()
            if accepted is None:
                break
            self._conns.append(_HttpConn(accepted.take(), now_ms))
        var i = 0
        while i < len(self._conns):
            var keep = True
            if self._conns[i].state == _READING:
                keep = self._read(i, now_ms)
            if keep and now_ms >= self._conns[i].deadline_ms:
                if self._conns[i].state == _WAITING:
                    self._conns[i].respond(
                        Span(_response("502 Bad Gateway", "", ""))
                    )
                keep = False
            if keep:
                i += 1
            else:
                _ = self._conns.pop(i)

    def next_timeout(self) -> Int:
        """Computes when `service()` next has a request to expire."""
        var t = _NEVER
        for i in range(len(self._conns)):
            t = min(t, self._conns[i].deadline_ms)
        return t

    def _read(mut self, index: Int, now_ms: Int) -> Bool:
        """Reads what is available; returns False to drop the connection."""
        while True:
            var n: Int
            try:
                n = self._conns[index].stream.read(Span(self._chunk))
            except:
                return False
            if n < 0:
                break
            if n == 0:
                return False
            put_bytes(self._conns[index].buf, Span(self._chunk)[0:n])
            if (
                len(self._conns[index].buf)
                > _MAX_HEADER_SIZE + MAX_SDP_BODY_SIZE
            ):
                self._conns[index].respond(
                    Span(_response("413 Content Too Large", "", ""))
                )
                return False
        if len(self._conns[index].buf) == 0:
            return True
        # A TLS ClientHello (or anything that is not an HTTP method) is
        # dropped at once: clients try HTTPS first and only fall back to
        # plain HTTP after that attempt has failed.
        var first = self._conns[index].buf[0]
        if first < 0x41 or first > 0x5A:
            return False
        var head_end = _find_header_end(Span(self._conns[index].buf))
        if head_end < 0:
            if len(self._conns[index].buf) > _MAX_HEADER_SIZE:
                self._conns[index].respond(
                    Span(
                        _response("431 Request Header Fields Too Large", "", "")
                    )
                )
                return False
            return True
        return self._handle(index, head_end, now_ms)

    def _handle(mut self, index: Int, head_end: Int, now_ms: Int) -> Bool:
        var head = Span(self._conns[index].buf)[0:head_end]
        var line_end = 0
        while line_end + 1 < len(head) and not (
            head[line_end] == 0x0D and head[line_end + 1] == 0x0A
        ):
            line_end += 1
        var request_line = String(from_utf8_lossy=head[0:line_end])
        var parts = request_line.split(" ")
        if len(parts) != 3:
            self._conns[index].respond(
                Span(_response("400 Bad Request", "", ""))
            )
            return False
        var method = String(parts[0])
        var raw_target = String(parts[1])
        var target = raw_target.copy()
        var query = raw_target.find("?")
        if query >= 0:
            target = String(raw_target[byte=0:query])

        if target == "/v1/join" or target == "/v1/join/":
            if method != "GET" and method != "HEAD":
                self._conns[index].respond(
                    Span(_response("405 Method Not Allowed", "", ""))
                )
                return False
            var content_type = ""
            if self._status.byte_length() > 0:
                content_type = "application/json"
            self._conns[index].respond(
                Span(_response("200 OK", content_type, self._status))
            )
            return False

        if not target.startswith("/v1/join/"):
            self._conns[index].respond(Span(_response("404 Not Found", "", "")))
            return False
        if method != "POST":
            self._conns[index].respond(
                Span(_response("405 Method Not Allowed", "", ""))
            )
            return False
        var id_text = String(target[byte = 9 : target.byte_length()])
        if _parse_uint(id_text, 20) is None:
            self._conns[index].respond(
                Span(_response("400 Bad Request", "", ""))
            )
            return False
        var length_header = _header_value(head, "Content-Length")
        if length_header is None:
            self._conns[index].respond(
                Span(_response("411 Length Required", "", ""))
            )
            return False
        var length = _parse_uint(length_header.value(), 10)
        if length is None or length.value() == 0:
            self._conns[index].respond(
                Span(_response("400 Bad Request", "", ""))
            )
            return False
        if length.value() > MAX_SDP_BODY_SIZE:
            self._conns[index].respond(
                Span(_response("413 Content Too Large", "", ""))
            )
            return False
        var body_len = Int(length.value())
        if len(self._conns[index].buf) < head_end + body_len:
            # The body is still arriving; allow the full read timeout.
            self._conns[index].deadline_ms = (
                self._conns[index].started_ms + _READ_TIMEOUT_MS
            )
            return True
        var body: String
        try:
            body = String(
                from_utf8=Span(self._conns[index].buf)[
                    head_end : head_end + body_len
                ]
            )
        except:
            self._conns[index].respond(
                Span(_response("400 Bad Request", "", ""))
            )
            return False
        var connection_id: UInt64
        try:
            connection_id = random_u64()
        except:
            self._conns[index].respond(
                Span(_response("500 Internal Server Error", "", ""))
            )
            return False
        self._conns[index].state = _WAITING
        self._conns[index].network_id = id_text.copy()
        self._conns[index].connection_id = connection_id
        self._conns[index].deadline_ms = (
            now_ms + ENDPOINT_NEGOTIATION_TIMEOUT_MS
        )
        self._signals.append(Signal(SIGNAL_OFFER, connection_id, body, id_text))
        return True


def _decode_chunked(body: Span[UInt8, _]) raises -> List[UInt8]:
    """Decodes a complete `Transfer-Encoding: chunked` body."""
    var out = List[UInt8]()
    var pos = 0
    while True:
        var size = 0
        var digits = 0
        while pos < len(body) and body[pos] != 0x0D and body[pos] != 0x3B:
            var c = _lower(body[pos])
            var d: Int
            if c >= 0x30 and c <= 0x39:
                d = Int(c - 0x30)
            elif c >= 0x61 and c <= 0x66:
                d = Int(c - 0x61) + 10
            else:
                raise Error("endpoint: malformed chunk size")
            size = size * 16 + d
            digits += 1
            if digits > 8:
                raise Error("endpoint: chunk too large")
            pos += 1
        while pos < len(body) and body[pos] != 0x0A:
            pos += 1
        pos += 1
        if digits == 0 or pos > len(body):
            raise Error("endpoint: truncated chunked body")
        if size == 0:
            return out^
        if pos + size + 2 > len(body):
            raise Error("endpoint: truncated chunked body")
        put_bytes(out, body[pos : pos + size])
        pos += size + 2


def _chunked_complete(body: Span[UInt8, _]) -> Bool:
    var tail: List[UInt8] = [0x30, 0x0D, 0x0A, 0x0D, 0x0A]
    if len(body) == 5:
        return bytes_equal(body, Span(tail))
    if len(body) < 7:
        return False
    return (
        body[len(body) - 7] == 0x0D
        and body[len(body) - 6] == 0x0A
        and bytes_equal(body[len(body) - 5 : len(body)], Span(tail))
    )


struct HttpResponse(Copyable):
    """A decoded HTTP response."""

    var status: Int
    """The status code."""
    var body: List[UInt8]
    """The response body."""

    def __init__(out self, status: Int):
        """Creates a response with an empty body."""
        self.status = status
        self.body = List[UInt8]()


def _parse_response(
    buf: Span[UInt8, _], eof: Bool
) raises -> Optional[HttpResponse]:
    """Parses a response if it is complete; `None` means keep reading."""
    var head_end = _find_header_end(buf)
    if head_end < 0:
        if eof:
            raise Error("endpoint: connection closed before the response")
        if len(buf) > _MAX_HEADER_SIZE:
            raise Error("endpoint: response headers too large")
        return None
    var head = buf[0:head_end]
    if len(head) < 12 or head[0] != 0x48:
        raise Error("endpoint: malformed status line")
    var status = 0
    for i in range(9, 12):
        if head[i] < 0x30 or head[i] > 0x39:
            raise Error("endpoint: malformed status line")
        status = status * 10 + Int(head[i] - 0x30)
    var response = HttpResponse(status)
    var body = buf[head_end : len(buf)]
    var encoding = _header_value(head, "Transfer-Encoding").or_else(String())
    if "chunked" in encoding.lower():
        if _chunked_complete(body):
            response.body = _decode_chunked(body)
            return response^
        if eof:
            raise Error("endpoint: truncated chunked body")
        return None
    if case .Some(length_text) = _header_value(head, "Content-Length"):
        var length = _parse_uint(length_text, 10)
        if length is None or length.value() > MAX_SDP_BODY_SIZE:
            raise Error("endpoint: unacceptable Content-Length")
        var n = Int(length.value())
        if len(body) >= n:
            response.body = List[UInt8](body[0:n])
            return response^
        if eof:
            raise Error("endpoint: truncated response body")
        return None
    if eof:
        response.body = List[UInt8](body)
        return response^
    if len(body) > MAX_SDP_BODY_SIZE:
        raise Error("endpoint: response body too large")
    return None


struct EndpointClient(Signaling):
    """The client side of HTTP signaling, for one server.

    Give it to `dial()` with `url()` as the network ID. The offer is sent as
    one POST; the response is delivered back as the answer signal.
    """

    var _server: SocketAddr
    var _network_id: String
    var _connect_timeout_ms: Int
    var _stream: Optional[TcpStream]
    var _buf: List[UInt8]
    var _connection_id: UInt64
    var _deadline_ms: Int
    var _signals: List[Signal]
    var _chunk: List[UInt8]

    def __init__(out self, server: SocketAddr) raises:
        """Creates a client for the server at an IPv4 address and port."""
        var id = String(random_u64())
        self._server = server
        self._network_id = id
        self._connect_timeout_ms = 5000
        self._stream = None
        self._buf = List[UInt8]()
        self._connection_id = 0
        self._deadline_ms = _NEVER
        self._signals = List[Signal]()
        self._chunk = List[UInt8](length=16384, fill=0)

    def url(self) -> String:
        """Gets the network ID to dial: the server's base URL."""
        return String(t"http://{self._server}")

    def probe(self, timeout_ms: Int) raises -> String:
        """Sends the `GET /v1/join` probe and returns the response body."""
        var deadline = monotonic_ms() + timeout_ms
        var stream = TcpStream.connect(self._server, timeout_ms)
        var request = String(
            t"GET /v1/join HTTP/1.1\r\nHost: {self._server}\r\nUser-Agent:"
            t" libhttpclient/1.0.0.0\r\nConnection: close\r\n\r\n"
        )
        stream.write_all(request.as_bytes(), timeout_ms)
        var buf = List[UInt8]()
        var chunk = List[UInt8](length=4096, fill=0)
        while True:
            var n = stream.read(Span(chunk))
            var eof = n == 0
            if n > 0:
                put_bytes(buf, Span(chunk)[0:n])
            var parsed = _parse_response(Span(buf), eof)
            if case .Some(response) = parsed:
                if response.status < 200 or response.status > 299:
                    raise Error(
                        t"endpoint: probe answered with status"
                        t" {response.status}"
                    )
                return String(from_utf8=Span(response.body))
            if n < 0:
                var left = deadline - monotonic_ms()
                if left <= 0 or not wait_readable(stream.fd(), left):
                    raise Error("endpoint: probe timed out")

    # ===------------------------------------------------------------------=== #
    # Signaling
    # ===------------------------------------------------------------------=== #

    def network_id(self) -> String:
        """Gets the client's network ID, sent in the request path."""
        return self._network_id.copy()

    def poll_fd(self) -> Int:
        """Gets the descriptor of the request in flight."""
        if self._stream is None:
            return -1
        return self._stream.value().fd()

    def trickle(self) -> Bool:
        """Says that candidates must be embedded in the descriptions."""
        return False

    def poll_signal(mut self) -> Optional[Signal]:
        """Takes the answer or error the server responded with."""
        if len(self._signals) == 0:
            return None
        return self._signals.pop(0)

    def send_signal(mut self, signal: Signal) raises:
        """Posts an offer to the server.

        Error signals are dropped, because the protocol has no way to carry
        them to the server.
        """
        if signal.kind == SIGNAL_ERROR:
            return
        if signal.kind != SIGNAL_OFFER:
            raise Error("endpoint: only offers can be signaled to a server")
        if self._stream is not None:
            raise Error("endpoint: a request is already in flight")
        var stream = TcpStream.connect(self._server, self._connect_timeout_ms)
        var head = String(
            t"POST /v1/join/{self._network_id} HTTP/1.1\r\nHost:"
            t" {self._server}\r\nUser-Agent:"
            t" libhttpclient/1.0.0.0\r\nContent-Type:"
            t" application/sdp\r\nContent-Length:"
            t" {signal.data.byte_length()}\r\nConnection: close\r\n\r\n"
        )
        var request = List[UInt8](head.as_bytes())
        put_bytes(request, signal.data.as_bytes())
        stream.write_all(Span(request), self._connect_timeout_ms)
        self._stream = stream^
        self._buf = List[UInt8]()
        self._connection_id = signal.connection_id
        self._deadline_ms = (
            monotonic_ms() + ENDPOINT_NEGOTIATION_TIMEOUT_MS + 5000
        )

    def service(mut self, now_ms: Int) raises:
        """Reads the response of the request in flight, if any."""
        if self._stream is None:
            return
        var eof = False
        while True:
            var n: Int
            try:
                n = self._stream.value().read(Span(self._chunk))
            except:
                eof = True
                break
            if n < 0:
                break
            if n == 0:
                eof = True
                break
            put_bytes(self._buf, Span(self._chunk)[0:n])
        var code = -1
        try:
            var parsed = _parse_response(Span(self._buf), eof)
            if parsed is None:
                if now_ms < self._deadline_ms:
                    return
                code = ERROR_NEGOTIATION_TIMEOUT_WAITING_FOR_RESPONSE
            else:
                var response = parsed.take()
                var body = String(from_utf8=Span(response.body))
                var numeric = _parse_uint(body.strip(), 10)
                if numeric is not None and numeric.value() <= 0xFFFF_FFFF:
                    # A body that is just a number is an error code, whatever
                    # the status.
                    code = Int(numeric.value())
                elif response.status < 200 or response.status > 299:
                    code = ERROR_GENERIC_FAILURE
                elif len(response.body) == 0:
                    code = ERROR_GENERIC_FAILURE
                else:
                    self._signals.append(
                        Signal(
                            SIGNAL_ANSWER, self._connection_id, body, self.url()
                        )
                    )
        except:
            code = ERROR_GENERIC_FAILURE
        if code >= 0:
            self._signals.append(
                Signal(
                    SIGNAL_ERROR, self._connection_id, String(code), self.url()
                )
            )
        self._stream = None
        self._deadline_ms = _NEVER
