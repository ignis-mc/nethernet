"""End-to-end transport benchmark over loopback, both ends in this process.

Measures what an application sees: the time to open a connection (signaling,
ICE, DTLS handshake, SCTP handshake, channel open), the round trip of a small
message, and bulk throughput on the reliable channel.

    mojo run -I src benchmarks/nethernet/bench_transport.mojo
"""

from nethernet.conn import Conn
from nethernet.dialer import DialAttempt, DialConfig
from nethernet.discovery.listener import DiscoveryListener
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet
from nethernet.os.time import monotonic_ms, monotonic_ns

comptime LOOPBACK = 0x7F000001


struct Pair(Movable):
    var dialer: Conn
    var acceptor: Conn

    def __init__(out self, var dialer: Conn, var acceptor: Conn):
        self.dialer = dialer^
        self.acceptor = acceptor^


def connect(
    mut listener: Listener[DiscoveryListener], mut client: DiscoveryListener
) raises -> Pair:
    var host_id = listener.signaling().id()
    client.add_peer(host_id, listener.signaling().local_addr(), monotonic_ms())
    var config = DialConfig()
    config.conn.bind_ip = LOOPBACK
    var attempt = DialAttempt(client, String(host_id), config)
    var accepted: Optional[Conn] = None
    while True:
        var now = monotonic_ms()
        attempt.poll(client, now)
        listener.poll(now)
        if accepted is None:
            accepted = listener.try_accept()
        if attempt.is_done() and accepted is not None:
            break
        var set = PollSet()
        _ = set.add(attempt.fd())
        _ = set.add(client.poll_fd())
        _ = set.add(listener.signaling().poll_fd())
        _ = set.wait(1)
    return Pair(attempt^.finish(), accepted.take())


def step(mut pair: Pair, wait_ms: Int) raises:
    var now = monotonic_ms()
    pair.dialer.poll(now)
    pair.acceptor.poll(now)
    if wait_ms > 0:
        var set = PollSet()
        _ = set.add(pair.dialer.fd())
        _ = set.add(pair.acceptor.fd())
        _ = set.wait(wait_ms)


def main() raises:
    var discovery = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    discovery.disable_broadcast()
    var listen_config = ListenConfig()
    listen_config.conn.bind_ip = LOOPBACK
    var listener = Listener[DiscoveryListener](discovery^, listen_config)
    var client = DiscoveryListener(SocketAddr(LOOPBACK, 0), 0, None)
    client.disable_broadcast()

    # Connection establishment.
    comptime CONNECTIONS = 20
    var t0 = monotonic_ns()
    for _ in range(CONNECTIONS):
        var p = connect(listener, client)
        p.dialer.abort()
        p.acceptor.abort()
    var t1 = monotonic_ns()
    print(
        "connect:   ",
        (t1 - t0) // CONNECTIONS // 1000,
        "us per connection (identity, ICE, DTLS, SCTP, channels)",
    )

    var pair = connect(listener, client)

    # Small-message round trip.
    comptime ROUND_TRIPS = 2000
    var ping = List[UInt8](length=64, fill=1)
    t0 = monotonic_ns()
    for _ in range(ROUND_TRIPS):
        pair.dialer.send(Span(ping))
        while True:
            step(pair, 0)
            var got = pair.acceptor.receive()
            if got is not None:
                pair.acceptor.send(Span(got.value()))
                break
        while True:
            step(pair, 0)
            if pair.dialer.receive() is not None:
                break
    t1 = monotonic_ns()
    print(
        "round trip:", (t1 - t0) // ROUND_TRIPS // 1000, "us per 64-byte echo"
    )

    # Bulk throughput, dialer to acceptor.
    comptime MESSAGE = 64 * 1024
    comptime MESSAGES = 512
    var block = List[UInt8](length=MESSAGE, fill=0x5A)
    var received = 0
    var sent = 0
    t0 = monotonic_ns()
    while received < MESSAGES:
        # Keep a few megabytes in flight without queueing everything at once.
        while (
            sent < MESSAGES and pair.dialer.buffered_amount() < 4 * 1024 * 1024
        ):
            pair.dialer.send(Span(block))
            sent += 1
        step(pair, 0)
        while pair.acceptor.receive() is not None:
            received += 1
    t1 = monotonic_ns()
    var megabytes = MESSAGE * MESSAGES // (1024 * 1024)
    var millis = (t1 - t0) // 1_000_000
    print(
        "throughput:",
        megabytes * 1000 // max(1, millis),
        "MiB/s over",
        megabytes,
        "MiB in 64 KiB messages",
    )
    pair.dialer.close(0)
