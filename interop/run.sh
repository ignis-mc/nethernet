#!/usr/bin/env bash
# Interoperability tests against go-nethernet (pion) on loopback.
#
# Builds the Go harness and the Mojo echo examples, then runs every
# combination of listener and dialer through LAN discovery signaling.
#
# Usage: interop/run.sh [-v] [-k PATTERN]
#   -v          keep and print the logs of passing cases too
#   -k PATTERN  run only cases whose name contains PATTERN
set -uo pipefail

cd "$(dirname "$0")/.."
root="$(pwd)"
verbose=0
pattern=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v) verbose=1; shift ;;
        -k) pattern="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

logs="$(mktemp -d)"
trap 'rm -rf "$logs"' EXIT

echo "== building"
mkdir -p build
(cd interop/go && GOFLAGS=-mod=mod go build -o bin/interop .) || exit 1
mojo build -I src examples/echo_server.mojo -o build/echo_server 2>"$logs/build.log" \
    || { grep -v Crashpad "$logs/build.log"; exit 1; }
mojo build -I src examples/echo_client.mojo -o build/echo_client 2>"$logs/build.log" \
    || { grep -v Crashpad "$logs/build.log"; exit 1; }

GO="$root/interop/go/bin/interop"
MOJO_SERVER="$root/build/echo_server"
MOJO_CLIENT="$root/build/echo_client"

free_port() {
    python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1])"
}

passed=0
failed=0
failures=()

# run_case NAME CLIENTS "LISTENER COMMAND" "DIALER COMMAND"
# {PORT} in either command is replaced by a free UDP port. The case passes
# when every dialer prints OK and exits 0, and the listener exits 0.
run_case() {
    local name="$1" clients="$2" listener="$3" dialer="$4"
    if [[ -n "$pattern" && "$name" != *"$pattern"* ]]; then
        return
    fi
    local port
    port="$(free_port)"
    listener="${listener//\{PORT\}/$port}"
    dialer="${dialer//\{PORT\}/$port}"
    local llog="$logs/$name.listener.log"
    # shellcheck disable=SC2086
    timeout 90 $listener >"$llog" 2>&1 &
    local lpid=$!
    for _ in $(seq 1 100); do
        grep -q '^READY' "$llog" 2>/dev/null && break
        sleep 0.05
    done
    local ok=1 pids=()
    for i in $(seq 1 "$clients"); do
        # shellcheck disable=SC2086
        timeout 90 $dialer >"$logs/$name.dialer$i.log" 2>&1 &
        pids+=($!)
    done
    for i in $(seq 1 "$clients"); do
        wait "${pids[$((i - 1))]}" || ok=0
        grep -q '^OK' "$logs/$name.dialer$i.log" || ok=0
    done
    if [[ "$listener" == *"-conns"* ]]; then
        wait "$lpid" || ok=0
    else
        kill "$lpid" 2>/dev/null
        wait "$lpid" 2>/dev/null
    fi
    if [[ $ok -eq 1 ]]; then
        passed=$((passed + 1))
        echo "ok    $name"
        if [[ $verbose -eq 1 ]]; then
            grep -hv Crashpad "$logs/$name."*.log | sed 's/^/        /'
        fi
    else
        failed=$((failed + 1))
        failures+=("$name")
        echo "FAIL  $name"
        for f in "$logs/$name."*.log; do
            echo "    --- $(basename "$f")"
            grep -v Crashpad "$f" | tail -25 | sed 's/^/    /'
        done
    fi
}

SIZES="1,2,100,1160,1161,5000,70000,262143,262144,600000"

echo "== Mojo dials, go-nethernet listens"
run_case mojo-to-go.identity 1 \
    "$GO listen -bind 127.0.0.1:{PORT} -conns 1 -timeout 60s" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --sizes $SIZES --unreliable 8 --timeout 60"
run_case mojo-to-go.anonymous 1 \
    "$GO listen -bind 127.0.0.1:{PORT} -anonymous -conns 1 -timeout 60s" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --anonymous --sizes 1,1000,70000 --timeout 60"
run_case mojo-to-go.anonymous-rejected 1 \
    "$GO listen -bind 127.0.0.1:{PORT} -timeout 60s" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --anonymous --expect-fail --timeout 30"
run_case mojo-to-go.server-closes 1 \
    "$GO listen -bind 127.0.0.1:{PORT} -conns 1 -timeout 60s" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --sizes 1,5000 --bye --timeout 60"
run_case mojo-to-go.three-clients 3 \
    "$GO listen -bind 127.0.0.1:{PORT} -conns 3 -timeout 60s" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --sizes 1,70000,300000 --unreliable 4 --timeout 60"

echo "== go-nethernet dials, Mojo listens"
run_case go-to-mojo.identity 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --conns 1 --timeout 60" \
    "$GO dial -target 127.0.0.1:{PORT} -identity -sizes $SIZES -unreliable 8 -timeout 60s"
run_case go-to-mojo.anonymous 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --allow-anonymous --conns 1 --timeout 60" \
    "$GO dial -target 127.0.0.1:{PORT} -sizes 1,1000,70000 -timeout 60s"
run_case go-to-mojo.anonymous-rejected 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --timeout 60" \
    "$GO dial -target 127.0.0.1:{PORT} -expect-fail -timeout 30s"
run_case go-to-mojo.server-closes 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --conns 1 --timeout 60" \
    "$GO dial -target 127.0.0.1:{PORT} -identity -sizes 1,5000 -bye -timeout 60s"
run_case go-to-mojo.three-clients 3 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --conns 3 --timeout 60" \
    "$GO dial -target 127.0.0.1:{PORT} -identity -sizes 1,70000,300000 -unreliable 4 -timeout 60s"

echo "== Mojo dials, Mojo listens"
run_case mojo-to-mojo.identity 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --conns 1 --timeout 60" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --sizes $SIZES --unreliable 8 --timeout 60"
run_case mojo-to-mojo.server-closes 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --conns 1 --timeout 60" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --sizes 1,5000 --bye --timeout 60"
run_case mojo-to-mojo.anonymous-rejected 1 \
    "$MOJO_SERVER --bind 127.0.0.1:{PORT} --timeout 60" \
    "$MOJO_CLIENT --target 127.0.0.1:{PORT} --anonymous --expect-fail --timeout 30"

echo "== control: go-nethernet both sides"
run_case go-to-go.control 1 \
    "$GO listen -bind 127.0.0.1:{PORT} -conns 1 -timeout 60s" \
    "$GO dial -target 127.0.0.1:{PORT} -identity -sizes 1,70000,600000 -unreliable 8 -timeout 60s"

echo
echo "$passed passed, $failed failed"
if [[ $failed -ne 0 ]]; then
    printf 'failed: %s\n' "${failures[@]}"
    exit 1
fi
