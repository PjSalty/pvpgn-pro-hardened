# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Report a vulnerability](https://github.com/PjSalty/pvpgn-pro-hardened/security/advisories/new)
(Security tab, Advisories). Please do not open a public issue for a
memory-safety or authentication bug.

Include the client version, a packet capture or a fuzz input that reproduces it,
and the affected function if you know it. A reproducer that runs under one of the
harnesses in `fuzz/` is ideal.

If the bug is in upstream PvPGN-PRO code (most parser code is), it will also be
reported to `pvpgn/pvpgn-server` so every realm benefits, not just this fork.

## Scope

In scope: memory-safety and logic bugs reachable from the network, that is, the
bnet (`6112/tcp`) and w3route (`6200/tcp`) wire protocols and anything a client
can send pre-authentication. This is what the hardening and fuzzing target.

Out of scope: bugs that require operator-level access (editing config, the
account database, or the host), and the design decision that WC3 clients need a
client-side patch to connect (that is inherent to PvPGN, not a server bug).

## What this project does about it

- The build is hardened so a memory-safety bug fails closed (crash + restart)
  instead of becoming code execution. See [HARDENING.md](HARDENING.md).
- The packet parsers are fuzzed under ASan + UBSan in CI. See
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- Images are built reproducibly, scanned, signed (cosign, keyless), and shipped
  with an SBOM and build-provenance attestation.
- The daemon is meant to run contained: non-root, read-only rootfs, no
  capabilities, `no-new-privileges`, seccomp. See
  [`deploy/docker-compose.hardened.yml`](deploy/docker-compose.hardened.yml).

Containment is not a substitute for the code being correct; it is the layer that
holds if the code is wrong.
