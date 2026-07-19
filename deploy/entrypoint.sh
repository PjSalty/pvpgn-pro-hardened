#!/usr/bin/env bash
# minimal launcher for the hardened pvpgn image. keeps bnetd in the foreground so
# the container runtime supervises it directly (PID 1), logs go to stdout, and a
# memory-safety abort surfaces as a container exit that the orchestrator restarts.
# this is a transparent default: point PVPGN_BNETD_CONF at your own config, or
# bind-mount over /usr/local/pvpgn/etc/pvpgn to keep the stock behaviour.
set -euo pipefail

PREFIX=/usr/local/pvpgn
BNETD="${PREFIX}/sbin/bnetd"
CONF="${PVPGN_BNETD_CONF:-${PREFIX}/etc/pvpgn/bnetd.conf}"

if [ ! -f "${CONF}" ]; then
	CONF="$(find "${PREFIX}" -type f -name bnetd.conf | head -n1 || true)"
fi
[ -n "${CONF}" ] && [ -f "${CONF}" ] || { echo "entrypoint: bnetd.conf not found under ${PREFIX}" >&2; exit 1; }

# -f: run in the foreground (no daemonize); -c: config file.
exec "${BNETD}" -f -c "${CONF}" "$@"
