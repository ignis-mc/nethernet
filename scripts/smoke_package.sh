#!/usr/bin/env bash
# Checks that the precompiled package can be imported by a consumer that has
# no access to the sources: builds build/nethernet.mojoc if needed, then
# compiles and runs a small program against it from an empty directory.
set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"
if [[ ! -f build/nethernet.mojoc ]]; then
    mkdir -p build
    mojo precompile src/nethernet -o build/nethernet.mojoc
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp build/nethernet.mojoc "$tmp/"
cat >"$tmp/consumer.mojo" <<'MOJO'
from nethernet.crypto.sha256 import sha256
from nethernet.sdp.description import Description, parse_description
from nethernet.signaling.signal import SIGNAL_OFFER, Signal, parse_signal
from nethernet.wire import hex_encode


def main() raises:
    var abc: List[UInt8] = [0x61, 0x62, 0x63]
    var digest = sha256(Span(abc))
    if not hex_encode(Span(digest)).startswith("ba7816bf"):
        raise Error("sha256 through the precompiled package is wrong")
    var d = Description()
    d.ice_ufrag = "ufrag"
    d.ice_pwd = "password"
    d.fingerprint = "AA:BB"
    var back = parse_description(d.encode())
    var signal = Signal(SIGNAL_OFFER, 7, back.encode(), "peer")
    var parsed = parse_signal(signal.encode(), "peer")
    if parsed.connection_id != 7:
        raise Error("signal round trip through the precompiled package failed")
    print("precompiled package works")
MOJO
(cd "$tmp" && mojo run -I . consumer.mojo)
