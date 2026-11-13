#!/usr/bin/env bash
# Builds every example program into build/.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p build
for src in examples/*.mojo; do
    name="$(basename "$src" .mojo)"
    echo "building $name"
    mojo build -I src "$src" -o "build/$name"
done
