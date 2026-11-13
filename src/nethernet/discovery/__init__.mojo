"""LAN discovery and signaling over UDP port 7551.

Minecraft finds NetherNet worlds on the local network by broadcasting an
encrypted request and reading the unicast responses. The same socket then
carries the connection signals. `DiscoveryListener` implements both and
conforms to `nethernet.signaling.signal.Signaling`.
"""
