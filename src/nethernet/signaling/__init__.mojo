"""Signals exchanged while negotiating a NetherNet connection.

A signaling channel carries the offer, the answer, trickled ICE candidates
and error codes between two peers that know each other by a network ID.
`nethernet.discovery` provides the LAN channel; anything else that conforms
to the `Signaling` trait can be plugged in.
"""
