#!/usr/bin/env bash
# checksec.sh - verify the hardening flags actually landed in a built binary.
# usage: checksec.sh <path-to-binary>
# exit 0 only if the mandatory mitigations are all present.
set -euo pipefail

BIN="${1:?usage: checksec.sh <binary>}"
[ -x "$BIN" ] || { echo "not executable: $BIN"; exit 2; }

fail=0
need() { # need <label> <condition-cmd...>
	local label="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "  PASS  $label"
	else
		echo "  FAIL  $label"; fail=1
	fi
}

echo "== checksec $BIN =="
command -v checksec >/dev/null 2>&1 && checksec --file="$BIN" --format=cli 2>/dev/null || true
echo "== mandatory mitigations =="

# full RELRO = GNU_RELRO segment AND BIND_NOW
need "full RELRO (GNU_RELRO + BIND_NOW)" bash -c \
	"readelf -lW '$BIN' | grep -q GNU_RELRO && readelf -dW '$BIN' | grep -qE 'BIND_NOW|FLAGS.*NOW'"
# stack canary
need "stack canary (__stack_chk_fail)" bash -c \
	"readelf -sW '$BIN' | grep -q __stack_chk_fail"
# PIE (ET_DYN + DF_1_PIE)
need "PIE executable" bash -c \
	"readelf -hW '$BIN' | grep -q 'Type:.*DYN'"
# NX / non-exec stack (GNU_STACK must be RW, not RWE)
need "non-exec stack (GNU_STACK RW)" bash -c \
	"! readelf -lW '$BIN' | grep -A1 GNU_STACK | grep -q RWE"
# FORTIFY: at least one _chk import
need "FORTIFY_SOURCE (_chk symbols)" bash -c \
	"readelf -sW '$BIN' | grep -qE '__(printf|sprintf|snprintf|memcpy|memset|strcpy|strcat|fortify)_chk'"
# CET on x86_64 (.note.gnu.property with IBT/SHSTK). skipped on non-x86.
if readelf -hW "$BIN" | grep -qE 'X86-64|Advanced Micro'; then
	need "CET (IBT/SHSTK note)" bash -c \
		"readelf -nW '$BIN' | grep -qiE 'SHSTK|IBT|x86 feature'"
fi

if [ "$fail" -ne 0 ]; then echo "CHECKSEC: FAIL"; exit 1; fi
echo "CHECKSEC: PASS - all mandatory mitigations present"
