"""A relay: accepts NetherNet connections over HTTP signaling and forwards
every message, on both channels, to an upstream server reached the same way.

Both hops run on this library, so a game client joining through the relay
exercises it as listener and as dialer at once. The upstream connection is
anonymous: a Bedrock server compares the connection's identity key with the
player's login key, which a relay cannot match.

    mojo run -I src examples/relay.mojo --http 127.0.0.1:19150 \
        --upstream 127.0.0.1:7554

Options:
    --http ADDR:PORT      address to accept connections on
                          (default 127.0.0.1:19151)
    --upstream ADDR:PORT  HTTP signaling address of the real server
                          (default 127.0.0.1:7560)
    --timeout SECONDS     exit after this long (default 900)

Prints the first messages each way and a status line every two seconds with
both connections' SCTP counters.
"""

from nethernet.conn import RELIABLE, UNRELIABLE, Conn
from nethernet.dialer import DialConfig, dial
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet
from nethernet.os.time import monotonic_ms
from nethernet.signaling.endpoint import (
    EndpointClient,
    EndpointServer,
    EndpointStatus,
)
from std.sys import argv


def option(name: StringSpan, default: StringSpan) -> String:
    var args = argv()
    for i in range(len(args) - 1):
        if args[i] == name:
            return String(args[i + 1])
    return String(default)


def first_byte(msg: List[UInt8]) -> Int:
    """Returns a message's first byte, or -1 if it is empty."""
    if len(msg) == 0:
        return -1
    return Int(msg[0])


def pump(
    mut src: Conn, mut dst: Conn, label: StringSpan, mut count: Int
) raises:
    """Forwards every message waiting on `src` to `dst`."""
    while True:
        var m = src.receive(RELIABLE)
        if m is None:
            break
        var bytes = m.take()
        count += 1
        if count <= 12 or count % 500 == 0:
            print(label, count, len(bytes), "bytes, first", first_byte(bytes))
        if not dst.is_closed():
            dst.send(Span(bytes), RELIABLE)
    while True:
        var u = src.receive(UNRELIABLE)
        if u is None:
            break
        if not dst.is_closed():
            dst.send(Span(u.value()), UNRELIABLE)


def main() raises:
    var server = EndpointServer(
        SocketAddr.parse(option("--http", "127.0.0.1:19151"))
    )
    var status = EndpointStatus()
    status.name = "Mojo NetherNet relay"
    status.level = "relay"
    status.max_players = 8
    server.set_status(status)
    print("READY", server.local_addr().port)
    var listener = Listener[EndpointServer](server^, ListenConfig())
    var upstream_addr = SocketAddr.parse(option("--upstream", "127.0.0.1:7560"))
    var deadline = monotonic_ms() + Int(option("--timeout", "900")) * 1000

    while monotonic_ms() < deadline:
        listener.poll(monotonic_ms())
        var accepted = listener.try_accept()
        if accepted is None:
            var set = PollSet()
            listener.add_poll_fds(set)
            var wake = min(listener.next_timeout(), monotonic_ms() + 20)
            _ = set.wait(max(0, wake - monotonic_ms()))
            continue
        var client = accepted.take()
        print("ACCEPTED", client.remote_network_id())
        var signaling = EndpointClient(upstream_addr)
        var config = DialConfig()
        config.timeout_ms = 15000
        # Present no identity upstream: the server compares a connection's
        # identity key with the login's, which a relay cannot match.
        config.anonymous = True
        var up = dial(signaling, signaling.url(), config)
        print("UPSTREAM CONNECTED")
        var to_up = 0
        var to_client = 0
        var next_status = monotonic_ms() + 2000
        while not client.is_closed() and not up.is_closed():
            var now = monotonic_ms()
            if now >= next_status:
                next_status = now + 2000
                var c = client.sctp_stats()
                var u = up.sctp_stats()
                print(
                    t"STATUS up={to_up} down={to_client} | client-side:"
                    t" out={c.data_chunks_out} in={c.data_chunks_in}"
                    t" rtx={c.retransmits} t3={c.t3_expiries}"
                    t" probes={c.loss_probes} pkts_in={c.packets_in}"
                    t" pkts_out={c.packets_out} dropped={c.packets_dropped}"
                    t"/{c.chunks_dropped} dup={c.duplicate_tsns}"
                    t" msgs_in={c.messages_in} | server-side:"
                    t" out={u.data_chunks_out} in={u.data_chunks_in}"
                    t" rtx={u.retransmits} t3={u.t3_expiries}"
                )
            listener.poll(now)
            client.poll(now)
            up.poll(now)
            pump(client, up, "client->server", to_up)
            pump(up, client, "server->client", to_client)
            client.poll(now)
            up.poll(now)
            var set = PollSet()
            _ = set.add(client.fd())
            _ = set.add(up.fd())
            listener.add_poll_fds(set)
            var wake = min(client.next_timeout(), up.next_timeout())
            wake = min(wake, now + 20)
            _ = set.wait(max(0, wake - monotonic_ms()))
        print(
            "CLOSED client:",
            client.close_reason(),
            "| server:",
            up.close_reason(),
            "| messages",
            to_up,
            "up",
            to_client,
            "down",
        )
        if not client.is_closed():
            client.close()
        if not up.is_closed():
            up.close()
