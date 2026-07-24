#!/usr/bin/env bash
# run-fmt-regression.sh - build and run the fmt lifetime regression under
# ASan + UBSan, so a reintroduced dangling format pointer fails hard instead of
# silently producing a corrupt string.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$HERE/.." && pwd)}"
OUT="${OUT:-/tmp/fmt-regression}"
CXX="${CXX:-clang++}"
mkdir -p "$OUT"

echo "== building test/regression_fmt_lifetime.cc under ASan+UBSan =="
"$CXX" -g -O2 -std=c++17 \
	-fsanitize=address,undefined -fno-sanitize-recover=all \
	-I"$ROOT/lib" \
	"$ROOT/src/test/regression_fmt_lifetime.cc" "$ROOT/lib/fmt/format.cc" \
	-o "$OUT/regression_fmt_lifetime"

echo "== running =="
ASAN_OPTIONS=detect_leaks=0 "$OUT/regression_fmt_lifetime"
