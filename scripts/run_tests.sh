#!/usr/bin/env bash
# Runs every test_*.mojo under test/ (or the paths given) and fails if any fails.
#
# Usage: scripts/run_tests.sh [-j N] [path ...]
set -uo pipefail

cd "$(dirname "$0")/.."

jobs="${NETHERNET_TEST_JOBS:-4}"
if [[ "${1:-}" == "-j" ]]; then
    jobs="$2"
    shift 2
fi

roots=("$@")
if [[ ${#roots[@]} -eq 0 ]]; then
    roots=(test)
fi

mapfile -d '' files < <(find "${roots[@]}" -name 'test_*.mojo' -print0 | sort -z)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "no test files found under: ${roots[*]}" >&2
    exit 1
fi

run_one() {
    local file="$1"
    local log
    log="$(mktemp)"
    if mojo run -I src -D ASSERT=all "$file" >"$log" 2>&1; then
        grep -E '^Summary' "$log" | sed "s|^|ok   $file  |"
        rm -f "$log"
        return 0
    fi
    echo "FAIL $file"
    grep -v 'Crashpad' "$log" | sed 's/^/    /'
    rm -f "$log"
    return 1
}
export -f run_one

printf '%s\0' "${files[@]}" | xargs -0 -n 1 -P "$jobs" bash -c 'run_one "$0"'
status=$?
if [[ $status -ne 0 ]]; then
    echo "some test files failed" >&2
    exit 1
fi
echo "all ${#files[@]} test files passed"
