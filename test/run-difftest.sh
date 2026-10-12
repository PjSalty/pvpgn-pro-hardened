#!/usr/bin/env bash
# run-difftest.sh - behavior-preservation gate for the hardened parsers.
# builds test/difftest_parsers.cc against (a) the current working tree and
# (b) the pristine upstream sources from the upstream-base branch, runs both,
# and fails unless the digests are byte-identical. also runs the fixed build
# under ASan+UBSan to prove it is memory-safe on the valid-input corpus.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$HERE/.." && pwd)}"
BUILD="${BUILD:-$ROOT/.fuzz-cmake}"
CXX="${CXX:-clang++}"
WORK="${WORK:-/tmp/difftest}"
mkdir -p "$WORK"
cd "$ROOT"

if [ ! -f "$(find "$BUILD" -name config.h 2>/dev/null | head -1)" ]; then
	cmake -S "$ROOT" -B "$BUILD" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DWITH_LUA=false >/dev/null
fi
CFG="$(dirname "$(find "$BUILD" -name config.h | head -1)")"
INC=(-Isrc -I"$CFG" -Ilib)
COMMON=(common/packet.cpp common/bn_type.cpp common/tag.cpp common/xalloc.cpp
        common/eventlog.cpp common/hexdump.cpp bnetd/anongame_gameresult.cpp)

build_variant() { # $1=srcdir $2=out [extraflags...]
	local sd="$1" out="$2"; shift 2
	local srcs=("$HERE/difftest_parsers.cc")
	for f in "${COMMON[@]}"; do srcs+=("$sd/src/$f"); done
	[ -f "$sd/src/compat/strcasecmp.cpp" ] && srcs+=("$sd/src/compat/strcasecmp.cpp")
	srcs+=("$sd/lib/fmt/format.cc")
	"$CXX" -g -O1 -std=c++17 "$@" -I"$sd/src" "${INC[@]}" "${srcs[@]}" -o "$out"
}

# fixed = working tree; pristine = upstream-base checkout into $WORK/pristine.
# GITREPO holds the .git (may differ from ROOT when ROOT is a git-less copy).
GITREPO="${GITREPO:-$ROOT}"
git config --global --add safe.directory "$GITREPO" 2>/dev/null || true
mkdir -p "$WORK/pristine"
# resolve the pristine base ref: a local branch on a dev box, origin/... in CI
# where checkout only leaves remote-tracking refs.
BASE_REF="${BASE_REF:-upstream-base}"
if ! git -C "$GITREPO" rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
	BASE_REF="origin/${BASE_REF#origin/}"
fi
git -C "$GITREPO" archive "$BASE_REF" | tar -x -C "$WORK/pristine"

echo "== building fixed (working tree) =="
build_variant "$ROOT" "$WORK/oracle_fixed"
echo "== building pristine (upstream-base) =="
build_variant "$WORK/pristine" "$WORK/oracle_pristine"

DF="$("$WORK/oracle_fixed")"
DP="$("$WORK/oracle_pristine")"
echo "fixed:    $DF"
echo "pristine: $DP"
if [ "$DF" != "$DP" ]; then echo "DIFFTEST: FAIL - behavior changed for valid input"; exit 1; fi
echo "DIFFTEST: PASS - identical output for valid input"

echo "== fixed build under ASan+UBSan on the valid corpus =="
build_variant "$ROOT" "$WORK/oracle_fixed_san" -fsanitize=address,undefined -fno-sanitize-recover=all
if ASAN_OPTIONS=detect_leaks=0 "$WORK/oracle_fixed_san" >/dev/null 2>"$WORK/san.err"; then
	echo "SANITIZER: PASS - no ASan/UBSan finding on valid inputs"
else
	echo "SANITIZER: FAIL"; cat "$WORK/san.err"; exit 1
fi
