"""An echo server: accepts NetherNet connections found through LAN discovery.

Every message received on either data channel is sent back on the same
channel. The message `BYE` makes the server close that connection.

    mojo run -I src examples/echo_server.mojo --bind 0.0.0.0:7551

Options:
    --bind ADDR:PORT   discovery address (default 0.0.0.0:7551)
    --network-id N     network ID to announce (default random)
    --bind-ip IP       local address for connections (default: default route)
    --conns N          exit after N connections have closed (default: never)
    --timeout SECONDS  exit with an error after this long (default: never)
"""

from nethernet.conn import RELIABLE, UNRELIABLE, Conn
from nethernet.discovery.listener import DiscoveryListener
from nethernet.discovery.server_data import ServerData
from nethernet.listener import ListenConfig, Listener
from nethernet.os.addr import SocketAddr
from nethernet.os.poll import PollSet
from nethernet.os.time import monotonic_ms
from std.sys import argv


def option(name: StringSpan, default: StringSpan) -> String:
    var args = argv()
    for i in range(len(args) - 1):
        if args[i] == name:
            return String(args[i + 1])
    return String(default)


def main() raises:
    var bind = SocketAddr.parse(option("--bind", "0.0.0.0:7551"))
    var network_id = UInt64(Int(option("--network-id", "0")))
    var max_conns = Int(option("--conns", "0"))
    var timeout_s = Int(option("--timeout", "0"))
    var bind_ip = option("--bind-ip", "")

    var discovery = DiscoveryListener(bind, network_id, None)
    var data = ServerData()
    data.server_name = "nethernet (Mojo)"
    data.level_name = "echo"
    data.max_player_count = 8
    discovery.set_server_data(data)
    var config = ListenConfig()
    if bind_ip.byte_length() > 0:
        config.conn.bind_ip = SocketAddr.parse_ip(bind_ip)
    var listener = Listener[DiscoveryListener](discovery^, config)
    print("READY", listener.signaling().local_addr().port, listener.network_id())

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

        var i = 0
        while i < len(conns):
            conns[i].poll(now)
            while True:
                var message = conns[i].receive(RELIABLE)
                if message is None:
                    break
                var bytes = message.take()
                if len(bytes) == 3 and bytes[0] == 0x42 and bytes[1] == 0x59 and bytes[2] == 0x45:
                    conns[i].close()
                    break
                conns[i].send(Span(bytes), RELIABLE)
            while not conns[i].is_closed():
                var datagram = conns[i].receive(UNRELIABLE)
                if datagram is None:
                    break
                conns[i].send(Span(datagram.value()), UNRELIABLE)
            if not conns[i].is_closed():
                conns[i].poll(now)
            if conns[i].is_closed():
                var done = conns.pop(i)
                print("CLOSED", done.close_reason())
                closed += 1
                continue
            i += 1

        var set = PollSet()
        _ = set.add(listener.signaling().poll_fd())
        var wake = now + 50
        for j in range(len(conns)):
            _ = set.add(conns[j].fd())
            wake = min(wake, conns[j].next_timeout())
        wake = min(wake, listener.next_timeout())
        _ = set.wait(max(0, wake - monotonic_ms()))
    print("DONE")
