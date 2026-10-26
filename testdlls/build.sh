#!/usr/bin/env bash
# Compile testlib.c into the four variants the evaluation section calls for.
# Run on the Linux VM (needs mingw-w64: sudo apt install -y mingw-w64).
set -euo pipefail
cd "$(dirname "$0")"

CC=x86_64-w64-mingw32-gcc
SRC=testlib.c
mkdir -p build

$CC -shared -O0 -g -o build/test_O0.dll           "$SRC"
$CC -shared -O2 -g -o build/test_O2.dll           "$SRC"
$CC -shared -O0 -s -o build/test_O0_stripped.dll  "$SRC"
$CC -shared -O2 -s -o build/test_O2_stripped.dll  "$SRC"

echo "Built 4 variants in build/:"
ls -1 build/
