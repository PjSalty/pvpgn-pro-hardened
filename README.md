# pvpgn-pro-hardened

A security-hardened build of [PvPGN-PRO](https://github.com/pvpgn/pvpgn-server),
the open-source Battle.net emulator that private Warcraft III (and other classic
Blizzard/Westwood game) realms run on.

It is a drop-in replacement for a stock PvPGN-PRO build: same `bnetd`, same
config, same `6112/tcp` (bnet) and `6200/tcp` (w3route) ports, same behaviour.
Only the build, the tests, and the release pipeline change. You can swap it in
and be materially safer with no config change.

## Why this exists

Everyone self-hosting a classic WC3 realm runs the same C++ daemon. It parses
untrusted network input, the bnet and w3route wire protocols, straight off the
internet, and the codebase has never had a modern security audit. The last
tagged PvPGN-PRO release is from 2018.

This fork does not rewrite that daemon. It hardens it:

- brings the tree current with upstream `master` (2026), 104 commits past the
  last tagged release,
- compiles it with the full modern mitigation set and proves the mitigations are
  actually in the binary,
- fuzzes the packet parsers under sanitizers and fixes the memory-safety bugs
  that turns up,
- ships a reproducible, signed container image with an SBOM and build provenance.

The goal is simple: a memory-safety bug in a packet parser should become a clean
crash-and-restart, not a remote code execution primitive.

## What the hardening buys you

The build is compiled per the [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html).
`test/checksec.sh` gates every build and the image refuses to build if a
mitigation is missing.

| Mitigation | Stock PvPGN-PRO | pvpgn-pro-hardened |
|---|---|---|
| RELRO | Partial | Full (GOT read-only) |
| Stack canary | none | `-fstack-protector-strong` |
| FORTIFY_SOURCE | none | `=3` (28 fortified calls) |
| Stack-clash protection | none | yes |
| CET (IBT + SHSTK) | none | yes (9255 endbr64 pads + property note) |
| PIE | yes | yes |
| NX / non-exec stack | yes | yes |
| libstdc++ assertions | none | `_GLIBCXX_ASSERTIONS` |
| auto-var-init | none | `-ftrivial-auto-var-init=zero` |

FORTIFY_SOURCE=3 plus the libstdc++ assertions retrofit bounds checks onto the
daemon's hundreds of legacy `sprintf`/`strcpy`/`strcat` call sites, so an
overflow aborts instead of corrupting memory. `-Werror=format-security` makes
format-string bugs a build failure.

See [HARDENING.md](HARDENING.md) for the full flag set and how to verify it.

## Bugs found and fixed by fuzzing

libFuzzer harnesses (`fuzz/`) drive the byte-level packet parsers under ASan +
UBSan. Every finding was fixed so the input is rejected safely, and each fix was
proved not to change behaviour for valid traffic (see Testing below).

- `packet_get_str_const`: an out-of-bounds read one byte past the packet buffer
  when a maximum-size packet carries no string terminator.
- `packet_get_data_const`: an `offset + len` unsigned integer overflow that let
  an out-of-bounds window slip past the length check.
- `tag_str_to_uint` / `tag_case_str_to_uint`: a short-input over-read and an
  uninitialised-scratch read in the 4-char client/arch tag decoders.

Details in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Bugs found and fixed by review

Two memory-safety bugs upstream introduced when it moved logging and i18n onto
the fmt library. Both are on hot paths, and neither crashes, so both fail
silently. Guarded now by `src/test/regression_fmt_lifetime.cc`, which aborts
under AddressSanitizer if either idiom comes back.

- `_localize` (`src/bnetd/i18n.h`) took `fmt::to_string(format_str).c_str()` as
  its format string. That temporary dies at the end of the statement, so
  formatting parsed freed heap memory, corrupting every localized message and
  leaking freed bytes to the client. It reaches every chat-command reply.
- `_client_motd_w3` (`src/bnetd/handle_bnet.cpp`) wrote `"{}" + '\n'`, which is
  pointer arithmetic on a 3-byte literal, not concatenation: fmt received a
  format pointer 7 bytes out of bounds and parsed whatever followed in `.rodata`.

Bugs in the packet handlers, each with a `regression_*` test in `src/test/`:

- `_client_anongame_infos` (`src/bnetd/handle_anongame.cpp`) trusted the item
  count byte of an anongame info request and passed a NULL accessor result to
  `memcpy`: one short packet from any logged-in client crashed the daemon.
- The raw-mode file request (`src/bnetd/handle_file.cpp`) read the filename
  off the socket into a buffer it could fill completely, so `file_send` got an
  unterminated string from a stack buffer. Reachable before login.
- `anongame_gameresult_parse` (`src/bnetd/anongame_gameresult.cpp`) sized an
  allocation from the hero count in a w3route game result before checking it: a
  negative count aborted the daemon, and a count past the end of the packet
  leaked three allocations per packet.
- `anongame_evaluate_results` (`src/bnetd/anongame.cpp`) indexed two 12-entry
  tables on its stack with the player number byte of a w3route game result: a
  player in a matched game could write outside them.

## Run it

Container (recommended):

```sh
docker run -d --name pvpgn \
  -p 6112:6112/tcp -p 6200:6200/tcp \
  -v pvpgn-data:/usr/local/pvpgn/var/pvpgn \
  ghcr.io/pjsalty/pvpgn-pro-hardened:latest
```

For the full runtime sandbox (read-only rootfs, dropped capabilities,
`no-new-privileges`, seccomp, resource limits) use
[`deploy/docker-compose.hardened.yml`](deploy/docker-compose.hardened.yml).

Build from source:

```sh
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release -D WITH_LUA=true
cmake --build build -j"$(nproc)"
bash test/checksec.sh build/src/bnetd/bnetd   # confirm the mitigations landed
```

Hardening is on by default. `-D PVPGN_HARDENING=OFF` disables it.

## Verify the image

```sh
# provenance + SBOM attestations
gh attestation verify oci://ghcr.io/pjsalty/pvpgn-pro-hardened:latest -R pjsalty/pvpgn-pro-hardened

# cosign keyless signature
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/PjSalty/pvpgn-pro-hardened/.github/workflows/.*' \
  ghcr.io/pjsalty/pvpgn-pro-hardened:latest
```

## Testing

The changes are proved not to break the daemon:

- `test/run-difftest.sh`: a differential oracle runs ~130k valid inputs through
  the patched parsers against the pristine upstream code and asserts identical
  output.
- `test/build-and-verify.sh`: full build, checksec gate, and the upstream unit
  tests (SRP3, bignum) on the hardened binary.
- `fuzz/run-regression.sh`: the crash reproducers run clean post-fix, plus a
  short campaign.

All of it runs in CI on every push and pull request.

## Relationship to upstream

This is a hardening fork, not a competing project. It tracks
`pvpgn/pvpgn-server` and the divergence is kept small and documented in
[DIVERGENCE.md](DIVERGENCE.md); parser fixes are offered back upstream. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the update workflow.

Supported clients, config, and protocol are unchanged from upstream; refer to
the [PvPGN-PRO documentation](https://github.com/pvpgn/pvpgn-server).

## License

GPL-2.0-or-later, same as upstream PvPGN and PvPGN-PRO. See [COPYING](COPYING).
Original PvPGN is the work of the PvPGN and PvPGN-PRO authors; this fork adds
build hardening, fuzzing, tests, and release tooling on top of their work.
