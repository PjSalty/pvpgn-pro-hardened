#!/usr/bin/env bash
# run-handler-regression.sh - build and run the packet handler regressions
# (src/test/regression_*.cc that drive real bnetd sources) under ASan + UBSan,
# so an out-of-bounds access or a leak on a reject path fails hard instead of
# passing by luck in the plain build that ctest runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$HERE/.." && pwd)}"
OUT="${OUT:-/tmp/handler-regression}"
CXX="${CXX:-clang++}"
mkdir -p "$OUT"

# generate config.h (cmake configure only; no compile of the tree).
BUILD="${BUILD:-$OUT/cmake}"
if [ ! -f "$(find "$BUILD" -name config.h 2>/dev/null | head -1)" ]; then
	cmake -S "$ROOT" -B "$BUILD" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DWITH_LUA=false >/dev/null
fi
CFG="$(dirname "$(find "$BUILD" -name config.h | head -1)")"

FLAGS=(-g -O1 -std=c++17 -fsanitize=address,undefined -fno-sanitize-recover=all
       -I"$ROOT/src" -I"$CFG" -I"$ROOT/lib")
COMMON=(packet bn_type xalloc eventlog hexdump)

run() { # $1=test name, rest=the bnetd sources it drives
	local name="$1"; shift
	local srcs=("$ROOT/src/test/$name.cc" "$ROOT/lib/fmt/format.cc")
	for f in "${COMMON[@]}"; do srcs+=("$ROOT/src/common/$f.cpp"); done
	for f in "$@"; do srcs+=("$ROOT/src/bnetd/$f"); done
	echo "== $name under ASan+UBSan =="
	"$CXX" "${FLAGS[@]}" "${srcs[@]}" -o "$OUT/$name"
	"$OUT/$name"
}

run regression_anongame_inforeq
echo "HANDLER REGRESSION: PASS"
