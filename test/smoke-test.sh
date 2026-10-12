#!/usr/bin/env bash
# smoke-test.sh - boot the image and prove the daemon serves without crashing.
# drives a real bnet init handshake on 6112, floods both ports with malformed
# bytes, and asserts the process survived. pass extra `docker run` args to test
# under the sandbox (read-only rootfs, cap-drop, seccomp, ...).
#   test/smoke-test.sh <image> [extra docker run args...]
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh <image> [docker run args...]}"; shift || true
NAME="pvpgn-smoke-$$"
cleanup() { docker stop "$NAME" >/dev/null 2>&1 || true; docker rm "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== booting $IMAGE $* =="
docker run -d --name "$NAME" -P "$@" "$IMAGE" >/dev/null
P6112="$(docker port "$NAME" 6112/tcp | head -1 | sed 's/.*://')"
P6200="$(docker port "$NAME" 6200/tcp | head -1 | sed 's/.*://')"

# wait until the bnet port accepts a connection (max ~15s)
for i in $(seq 1 30); do
  if bash -c "exec 3<>/dev/tcp/127.0.0.1/${P6112}" 2>/dev/null; then break; fi
  sleep 0.5
  [ "$i" = 30 ] && { echo "FAIL: 6112 never came up"; docker logs "$NAME" 2>&1 | tail; exit 1; }
done
echo "  6112 listening (host port ${P6112}), 6200 -> ${P6200}"

python3 - "$P6112" "$P6200" <<'PY'
import socket, sys, os
p6112, p6200 = int(sys.argv[1]), int(sys.argv[2])

def conn(port, payload, read=True):
    s = socket.create_connection(("127.0.0.1", port), timeout=4)
    s.sendall(payload); got = b""
    if read:
        s.settimeout(2)
        # the packet body is random, so the server may answer, stay quiet, or
        # drop the connection. all three are fine: only the daemon dying is not.
        try: got = s.recv(256)
        except (socket.timeout, ConnectionError): pass
    s.close(); return got

# 1) real bnet init byte (CLASS_BNET) + a SID_AUTH_INFO-shaped packet.
#    type=0x50, size filled in; the exact fields do not matter, we only need the
#    daemon to parse it and not crash.
body = b"\x50\x00" + b"\x00\x00" + os.urandom(60)
pkt = body[:2] + len(body).to_bytes(2, "little") + body[4:]
r = conn(p6112, b"\x01" + pkt)
print(f"  bnet handshake: sent init+packet, server replied {len(r)} bytes")

# 2) malformed / hostile bytes at both listeners: the daemon must survive.
for port, name in ((p6112, "bnet"), (p6200, "w3route")):
    for payload in (b"\x01" + os.urandom(3072), b"\xff" * 4000, os.urandom(1500), b"\x01\xff\xff\xff\xff"):
        try: conn(port, payload, read=False)
        except Exception: pass
    print(f"  {name}: flooded with malformed packets")
print("  client done")
PY

sleep 1
running="$(docker inspect -f '{{.State.Running}}' "$NAME")"
echo "== daemon still running after handshake + malformed flood: ${running} =="
if [ "$running" != "true" ]; then
  echo "FAIL: daemon exited"; docker logs "$NAME" 2>&1 | tail -20; exit 1
fi
# re-check the port still serves (not just process alive).
bash -c "exec 3<>/dev/tcp/127.0.0.1/${P6112}" 2>/dev/null && echo "  6112 still accepting connections" \
  || { echo "FAIL: 6112 stopped serving"; exit 1; }
# a daemon can stay up and serve while part of it is dead: a syscall the sandbox
# denies shows up as a fatal line in its log, not as an exit. the seccomp profile
# shipped without setitimer for that reason, and this test passed. look in both
# places the log can be (stdout, or the default log file). cat is run directly,
# with no shell around it: sh needs vfork, which the profile does not allow.
fatal="$( { docker logs "$NAME" 2>&1; docker exec "$NAME" cat /usr/local/pvpgn/var/pvpgn/bnetd.log 2>/dev/null; } | grep -F '[fatal]' || true )"
if [ -n "$fatal" ]; then
  echo "FAIL: the daemon logged a fatal error"; printf '%s\n' "$fatal" | head -5; exit 1
fi
echo "  no fatal lines in the daemon log"
echo "SMOKE TEST: PASS"
