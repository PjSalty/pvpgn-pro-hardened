# syntax=docker/dockerfile:1
#
# Reproducible, hardening-verified build of pvpgn-pro (bnetd), the Battle.net
# emulator for private Warcraft III realms. Multi-stage: compile with the full
# mitigation set, gate the build on checksec, then ship a slim non-root runtime.
#
# Drop-in: same bnetd, same default config, same 6112/tcp (bnet) + 6200/tcp
# (w3route) ports. Only the build and its provenance change.
#
# Base pinned by digest for reproducibility. Refresh with:
#   docker buildx imagetools inspect debian:13-slim
ARG DEBIAN_DIGEST=sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# ---- build stage ----------------------------------------------------------
FROM debian@${DEBIAN_DIGEST} AS build
ENV DEBIAN_FRONTEND=noninteractive
# SOURCE_DATE_EPOCH (passed by the release workflow) makes timestamps deterministic.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      build-essential cmake git ca-certificates \
      zlib1g-dev liblua5.1-0-dev \
      binutils checksec \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# hardening is ON by default (PVPGN_HARDENING). WITH_LUA matches the upstream
# default feature set; plain-file storage backend (no MySQL/SQLite).
RUN cmake -S . -B /build \
      -D CMAKE_BUILD_TYPE=Release \
      -D CMAKE_INSTALL_PREFIX=/usr/local/pvpgn \
      -D CMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -D PVPGN_HARDENING=ON \
      -D WITH_LUA=true \
 && cmake --build /build -j "$(nproc)" \
 && cmake --install /build

# fail the image build if the mitigations did not actually land in the binary.
RUN bash /src/test/checksec.sh /usr/local/pvpgn/sbin/bnetd

# ---- runtime stage --------------------------------------------------------
FROM debian@${DEBIAN_DIGEST} AS runtime

LABEL org.opencontainers.image.title="pvpgn-pro-hardened" \
      org.opencontainers.image.description="Security-hardened PvPGN-PRO Battle.net server for Warcraft III private realms" \
      org.opencontainers.image.licenses="GPL-2.0-or-later" \
      org.opencontainers.image.source="https://github.com/PjSalty/pvpgn-pro-hardened"

RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      zlib1g liblua5.1-0 libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 pvpgn \
 && useradd  --system --uid 1000 --gid 1000 --home-dir /usr/local/pvpgn \
      --shell /usr/sbin/nologin pvpgn

COPY --from=build /usr/local/pvpgn /usr/local/pvpgn
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

# runtime user owns only the writable state + config; binaries stay root:root,
# read+exec only, so a compromised process cannot rewrite them.
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R pvpgn:pvpgn /usr/local/pvpgn/etc /usr/local/pvpgn/var

USER pvpgn
WORKDIR /usr/local/pvpgn

# 6112/tcp = bnet client port; 6200/tcp = w3route (WC3 game-session relay).
EXPOSE 6112/tcp 6200/tcp

# account DB, clans, logs. mount a volume here to persist accounts (uid 1000).
VOLUME ["/usr/local/pvpgn/var/pvpgn"]

# liveness: the bnet listener must accept a TCP connection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/6112' || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
