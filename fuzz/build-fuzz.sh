#!/usr/bin/env bash
# build-fuzz.sh - compile the pvpgn fuzz harnesses under libFuzzer + ASan + UBSan.
# runs anywhere clang + cmake + zlib/lua headers are present (dev container or CI).
#
#   ROOT   source tree root      (default: script's repo root)
#   OUT    output dir for binaries (default: $ROOT/fuzz/out)
#   CXX    compiler              (default: clang++)
# harnesses to build are the fuzz_*.cc files in fuzz/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$HERE/.." && pwd)}"
OUT="${OUT:-$ROOT/fuzz/out}"
CXX="${CXX:-clang++}"
mkdir -p "$OUT"
cd "$ROOT"

# generate config.h + version.h (cmake configure only; no compile of the tree).
BUILD="${BUILD:-$ROOT/.fuzz-cmake}"
if [ ! -f "$(find "$BUILD" -name config.h 2>/dev/null | head -1)" ]; then
	cmake -S "$ROOT" -B "$BUILD" \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
		-DWITH_LUA=false -DWITH_MYSQL=false >/dev/null
fi
CFG_DIR="$(dirname "$(find "$BUILD" -name config.h | head -1)")"
VER_DIR="$(dirname "$(find "$BUILD" -name version.h | head -1)")"

read -ra SAN <<< "${FUZZ_SAN:--fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -fsanitize-address-use-after-scope}"
FLAGS=(-g -O1 -std=c++17 "${SAN[@]}" -Isrc -I"$CFG_DIR" -I"$VER_DIR" -Ilib)

# faithful link set: the real byte-parsers + their transitive helpers. no stubs.
COMMON=(
	src/common/packet.cpp
	src/common/bn_type.cpp
	src/common/tag.cpp
	src/common/xalloc.cpp
	src/common/eventlog.cpp
	src/common/hexdump.cpp
	lib/fmt/format.cc
)
for f in src/compat/strcasecmp.cpp src/compat/strdup.cpp; do
	[ -f "$f" ] && COMMON+=("$f")
done

status=0
for src in "$HERE"/fuzz_*.cc; do
	name="$(basename "$src" .cc)"
	echo "=== building $name ==="
	if "$CXX" "${FLAGS[@]}" "$src" "${COMMON[@]}" -o "$OUT/$name"; then
		echo "  -> $OUT/$name"
	else
		echo "  BUILD FAILED: $name"; status=1
	fi
done
exit $status
