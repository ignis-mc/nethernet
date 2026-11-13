"""An echo client: finds a NetherNet server through LAN discovery and checks it.

Sends messages of the given sizes and verifies that each comes back
unchanged, then optionally exchanges messages on the unreliable channel.

    mojo run -I src examples/echo_client.mojo --target 192.168.1.10:7551

Options:
    --target ADDR:PORT  where to send discovery requests
                        (default 255.255.255.255:7551)
    --http ADDR:PORT    use HTTP signaling with this server instead
    --sizes A,B,C       reliable message sizes (default 1,2,100,1000)
    --unreliable N      unreliable messages to exchange (default 0)
    --bind-ip IP        local address for the connection (default route)
    --anonymous         send no identity assertion with the offer
    --allow-identityless accept a server that sends no identity assertion
    --expect-fail       succeed only if the server rejects the connection
    --bye               ask the server to close the connection
    --close-after-write N  finally send N bytes and close without waiting
    --stats             print SCTP retransmission counters before closing
    --timeout SECONDS   give up after this long (default 30)
"""

from nethernet.conn import RELIABLE, UNRELIABLE, Conn
from nethernet.dialer import DialConfig, dial
from nethernet.discovery.listener import DiscoveryListener
from nethernet.discovery.server_data import ServerData
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import wait_readable
from nethernet.os.time import monotonic_ms
from nethernet.signaling.endpoint import EndpointClient
from nethernet.signaling.signal import Signaling
from std.sys import argv


def option(name: StringSpan, default: StringSpan) -> String:
    var args = argv()
    for i in range(len(args) - 1):
        if args[i] == name:
            return String(args[i + 1])
    return String(default)


def flag(name: StringSpan) -> Bool:
    for arg in argv():
        if arg == name:
            return True
    return False


def print_stats(conn: Conn):
    """Prints the connection's SCTP recovery counters when `--stats` is set."""
    if not flag("--stats"):
        return
    var s = conn.sctp_stats()
    print(
        t"SCTP data_out={s.data_chunks_out} retransmits={s.retransmits}"
        t" fast={s.fast_retransmits} rack={s.rack_losses}"
        t" probes={s.loss_probes} t3={s.t3_expiries}"
        t" dup_in={s.duplicate_tsns} data_in={s.data_chunks_in}"
    )


def payload(size: Int) -> List[UInt8]:
    """The deterministic test message; the Go harness generates the same."""
    var out = List[UInt8](capacity=size)
    for i in range(size):
        out.append(UInt8((i * 7 + i // 251 + size) & 0xFF))
    return out^


def exercise(mut conn: Conn, deadline: Int) raises:
    """Checks echoes on an open connection, then closes it."""
    print("CONNECTED", conn.remote_addr().value())
    if len(conn.peer_public_key()) > 0:
        print("PEER_IDENTITY", len(conn.peer_public_key()), "byte P-384 key")
    var unreliable_count = Int(option("--unreliable", "0"))

    for field in option("--sizes", "1,2,100,1000").split(","):
        if field.byte_length() == 0:
            continue
        var size = Int(field)
        var want = payload(size)
        conn.write(Span(want))
        var got = conn.read(max(1000, deadline - monotonic_ms()))
        if len(got) != size:
            raise Error(t"echo of {size} bytes came back as {len(got)} bytes")
        for i in range(size):
            if got[i] != want[i]:
                raise Error(t"echo of {size} bytes differs at offset {i}")
        print("ECHO", size)

    if unreliable_count > 0:
        var datagram = payload(32)
        for _ in range(unreliable_count):
            conn.send(Span(datagram), UNRELIABLE)
            conn.drive(5)
        var received = 0
        var until = monotonic_ms() + 3000
        while received < unreliable_count and monotonic_ms() < until:
            conn.drive(20)
            while True:
                var got = conn.receive(UNRELIABLE)
                if got is None:
                    break
                if len(got.value()) != 32:
                    raise Error("unreliable echo has the wrong size")
                received += 1
        # Loopback does not lose packets, so anything missing is a bug.
        if received != unreliable_count:
            raise Error(
                t"unreliable: received {received} of {unreliable_count}"
            )
        print("UNRELIABLE", received)

    var final_size = Int(option("--close-after-write", "0"))
    if final_size > 0:
        # Write and close at once: close() must still deliver the message.
        var last = payload(final_size)
        conn.send(Span(last))
        conn.close()
        print("WROTE_AND_CLOSED", final_size)
        print("OK")
        return

    print_stats(conn)
    if flag("--bye"):
        var bye: List[UInt8] = [0x42, 0x59, 0x45]
        conn.write(Span(bye))
        var closed = False
        try:
            _ = conn.read(5000)
        except e:
            closed = conn.is_closed()
        if not closed:
            raise Error("expected the server to close the connection")
        print("CLOSED_BY_PEER", conn.close_reason())
    else:
        conn.close()
    print("OK")


def connect[
    S: Signaling
](mut signaling: S, network_id: StringSpan, deadline: Int) raises:
    """Dials `network_id` and runs the echo checks (or expects rejection)."""
    var config = DialConfig()
    config.timeout_ms = max(1000, deadline - monotonic_ms())
    var bind_ip = option("--bind-ip", "")
    if bind_ip.byte_length() > 0:
        config.conn.bind_ip = SocketAddr.parse_ip(bind_ip)
    config.anonymous = flag("--anonymous")
    config.allow_identityless_server = flag("--allow-identityless")
    if flag("--expect-fail"):
        var failed = False
        try:
            var unexpected = dial(signaling, network_id, config)
            unexpected.abort()
        except e:
            failed = True
            print("FAILED_AS_EXPECTED", e)
        if not failed:
            raise Error("dial succeeded but was expected to fail")
        print("OK")
        return
    var conn = dial(signaling, network_id, config)
    exercise(conn, deadline)


def main() raises:
    var timeout_ms = Int(option("--timeout", "30")) * 1000
    var deadline = monotonic_ms() + timeout_ms

    var http = option("--http", "")
    if http.byte_length() > 0:
        var client = EndpointClient(SocketAddr.parse(http))
        print("STATUS", client.probe(5000))
        connect(client, client.url(), deadline)
        return

    var target = SocketAddr.parse(option("--target", "255.255.255.255:7551"))
    var discovery = DiscoveryListener(SocketAddr(0, 0), 0, target)
    var network_id = String()
    while network_id.byte_length() == 0:
        if monotonic_ms() > deadline:
            raise Error("no server answered discovery")
        discovery.service(monotonic_ms())
        for server in discovery.responses():
            var data = ServerData.decode(Span(server.data))
            print("FOUND", server.network_id, data.server_name, data.level_name)
            network_id = String(server.network_id)
            break
        _ = wait_readable(discovery.poll_fd(), 100)
    connect(discovery, network_id, deadline)
