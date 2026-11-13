"""An echo server: accepts NetherNet connections found through LAN discovery.

Every message received on either data channel is sent back on the same
channel. The message `BYE` makes the server close that connection.

    mojo run -I src examples/echo_server.mojo --bind 0.0.0.0:7551

Options:
    --bind ADDR:PORT   discovery address (default 0.0.0.0:7551)
    --http ADDR:PORT   serve HTTP signaling here instead of LAN discovery
    --network-id N     network ID to announce (default random)
    --bind-ip IP       local address for connections (default: default route)
    --allow-anonymous  accept offers without an identity assertion
    --conns N          exit after N connections have closed (default: never)
    --expect-last N    fail unless each connection's last message has N bytes
    --stats            print SCTP retransmission counters for each closed
                       connection
    --timeout SECONDS  exit with an error after this long (default: never)
"""

from nethernet.conn import RELIABLE, UNRELIABLE, Conn
from nethernet.discovery.listener import DiscoveryListener
from nethernet.discovery.server_data import ServerData
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet
from nethernet.os.time import monotonic_ms
from nethernet.signaling.endpoint import EndpointServer, EndpointStatus
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


def serve[
    S: Signaling
](mut listener: Listener[S], max_conns: Int, timeout_s: Int) raises:
    """Accepts connections and echoes messages until `max_conns` have closed."""
    var expect_last = Int(option("--expect-last", "0"))
    var last_sizes = List[Int]()
    var conns = List[Conn]()
    var closed = 0
    var started = monotonic_ms()
    while max_conns == 0 or closed < max_conns:
        var now = monotonic_ms()
        if timeout_s > 0 and now - started > timeout_s * 1000:
            raise Error("echo server timed out")
        listener.poll(now)
        while True:
            var accepted = listener.try_accept()
            if accepted is None:
                break
            var conn = accepted.take()
            print("ACCEPTED", conn.remote_network_id(), conn.connection_id())
            conns.append(conn^)
            last_sizes.append(0)

        var i = 0
        while i < len(conns):
            conns[i].poll(now)
            while True:
                var message = conns[i].receive(RELIABLE)
                if message is None:
                    break
                var bytes = message.take()
                last_sizes[i] = len(bytes)
                # "BYE" asks the server to hang up.
                if (
                    len(bytes) == 3
                    and bytes[0] == 0x42
                    and bytes[1] == 0x59
                    and bytes[2] == 0x45
                ):
                    conns[i].close()
                    break
                if not conns[i].is_closed():
                    conns[i].send(Span(bytes), RELIABLE)
            while not conns[i].is_closed():
                var datagram = conns[i].receive(UNRELIABLE)
                if datagram is None:
                    break
                conns[i].send(Span(datagram.value()), UNRELIABLE)
            if not conns[i].is_closed():
                conns[i].poll(now)
            if conns[i].is_closed():
                # Messages that arrived together with the close are still
                # readable.
                while True:
                    var late = conns[i].receive(RELIABLE)
                    if late is None:
                        break
                    last_sizes[i] = len(late.value())
                var done = conns.pop(i)
                print_stats(done)
                var last_size = last_sizes.pop(i)
                print("CLOSED", done.close_reason(), "last message", last_size)
                if expect_last > 0 and last_size != expect_last:
                    raise Error(
                        t"last message had {last_size} bytes, expected"
                        t" {expect_last}"
                    )
                closed += 1
                continue
            i += 1

        var set = PollSet()
        listener.add_poll_fds(set)
        var wake = now + 20
        for j in range(len(conns)):
            _ = set.add(conns[j].fd())
            wake = min(wake, conns[j].next_timeout())
        wake = min(wake, listener.next_timeout())
        _ = set.wait(max(0, wake - monotonic_ms()))
    print("DONE")


def main() raises:
    var max_conns = Int(option("--conns", "0"))
    var timeout_s = Int(option("--timeout", "0"))
    var bind_ip = option("--bind-ip", "")
    var config = ListenConfig()
    config.allow_anonymous = flag("--allow-anonymous")
    if bind_ip.byte_length() > 0:
        config.conn.bind_ip = SocketAddr.parse_ip(bind_ip)

    var http = option("--http", "")
    if http.byte_length() > 0:
        var server = EndpointServer(SocketAddr.parse(http))
        var status = EndpointStatus()
        status.name = "nethernet (Mojo)"
        status.level = "echo"
        status.max_players = 8
        server.set_status(status)
        print("READY", server.local_addr().port, server.network_id())
        var listener = Listener[EndpointServer](server^, config)
        serve(listener, max_conns, timeout_s)
        return

    var bind = SocketAddr.parse(option("--bind", "0.0.0.0:7551"))
    var network_id = UInt64(Int(option("--network-id", "0")))
    var discovery = DiscoveryListener(bind, network_id, None)
    var data = ServerData()
    data.server_name = "nethernet (Mojo)"
    data.level_name = "echo"
    data.max_player_count = 8
    discovery.set_server_data(data)
    print("READY", discovery.local_addr().port, discovery.network_id())
    var listener = Listener[DiscoveryListener](discovery^, config)
    serve(listener, max_conns, timeout_s)
