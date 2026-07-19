#!/usr/bin/env bash
# build-and-verify.sh - full hardened build + mitigation gate + upstream tests.
# runs in a clean debian:13 container (the CI "build & verify" job locally).
set -euo pipefail
REPO="${REPO:-/home/salty/GIT/pvpgn-pro-hardened}"
docker run --rm -i -v "$REPO":/ro:ro debian:13-slim bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install --no-install-recommends -y build-essential cmake git zlib1g-dev \
	liblua5.1-0-dev checksec binutils file >/dev/null
cp -a /ro /src
echo "== configure + build (hardening ON by default) =="
cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DWITH_LUA=true >/tmp/cfg.log 2>&1
grep -i 'hardening ENABLED' /tmp/cfg.log || true
cmake --build /build -j "$(nproc)" >/tmp/build.log 2>&1 && echo BUILD_OK \
	|| { echo BUILD_FAIL; tail -50 /tmp/build.log; exit 1; }
echo
echo "== mitigation gate (test/checksec.sh) =="
bash /src/test/checksec.sh /build/src/bnetd/bnetd
echo
echo "== endbr64 IBT landing pads =="
echo -n "  endbr64 count: "; objdump -d /build/src/bnetd/bnetd | grep -c endbr64
echo
echo "== upstream unit tests (ctest) =="
cd /build && ctest --output-on-failure
EOF
