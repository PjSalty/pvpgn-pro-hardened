#!/usr/bin/env bash
# run-regression.sh - the fuzz gate. every committed seed must run clean under
# ASan+UBSan (the pre-fix reproducers are expected to pass now that the bugs are
# fixed; a crash means a regression). optionally runs a short blind campaign.
#   FUZZ_SECONDS=N  per-harness campaign time after the seed check (default 0)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd "$HERE/.." && pwd)}"
OUT="${OUT:-$ROOT/fuzz/out}"
CAMPAIGN="${FUZZ_SECONDS:-0}"

if [ ! -x "$OUT/fuzz_packet" ]; then
	OUT="$OUT" ROOT="$ROOT" bash "$HERE/build-fuzz.sh"
fi

status=0
for h in packet tag; do
	bin="$OUT/fuzz_$h"
	seeds="$ROOT/fuzz/seeds/$h"
	[ -d "$seeds" ] || continue
	for s in "$seeds"/*.bin; do
		[ -f "$s" ] || continue
		if ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$bin" "$s" >/tmp/reg.log 2>&1; then
			echo "  PASS  $(basename "$s")"
		else
			echo "  CRASH $s"; sed -n '1,20p' /tmp/reg.log; status=1
		fi
	done
	if [ "$CAMPAIGN" -gt 0 ]; then
		echo "== $h: ${CAMPAIGN}s campaign =="
		ASAN_OPTIONS=detect_leaks=0 "$bin" -max_total_time="$CAMPAIGN" -rss_limit_mb=2048 \
			-print_final_stats=1 "$seeds" || { echo "campaign crash: $h"; status=1; }
	fi
done

if [ "$status" -ne 0 ]; then echo "FUZZ REGRESSION: FAIL"; exit 1; fi
echo "FUZZ REGRESSION: PASS"
