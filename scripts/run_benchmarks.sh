#!/usr/bin/env bash
# Runs every bench_*.mojo under benchmarks/ (or the paths given), one at a
# time so they do not disturb each other's timings.
set -euo pipefail

cd "$(dirname "$0")/.."

roots=("$@")
if [[ ${#roots[@]} -eq 0 ]]; then
    roots=(benchmarks)
fi
mapfile -d '' files < <(find "${roots[@]}" -name 'bench_*.mojo' -print0 | sort -z)
for f in "${files[@]}"; do
    echo "== $f"
    mojo run -I src "$f"
done
