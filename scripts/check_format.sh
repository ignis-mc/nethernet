#!/usr/bin/env bash
# Fails if `mojo format` would change any tracked Mojo file.
#
# `mojo format` has no check mode, so this formats copies in a temporary
# directory and compares them with the originals.
set -uo pipefail

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mapfile -d '' files < <(find src test examples benchmarks -name '*.mojo' -print0 | sort -z)
for f in "${files[@]}"; do
    mkdir -p "$tmp/$(dirname "$f")"
    cp "$f" "$tmp/$f"
done
(cd "$tmp" && mojo format -q src test examples benchmarks) || exit 1

status=0
for f in "${files[@]}"; do
    if ! cmp -s "$f" "$tmp/$f"; then
        echo "needs formatting: $f"
        status=1
    fi
done
if [[ $status -ne 0 ]]; then
    echo "run 'pixi run format'" >&2
fi
exit $status
