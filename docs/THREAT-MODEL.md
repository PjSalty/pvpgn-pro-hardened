# Threat model

## The attack surface

`bnetd` is an internet-exposed C++ daemon. A client speaks to it over two wire
protocols that carry untrusted, attacker-controlled bytes:

- **bnet** on `6112/tcp`: login, chat, channels, the game list, account
  creation. Reachable before authentication.
- **w3route** on `6200/tcp`: the Warcraft III game-session relay.

A new connection's first byte selects the protocol class (`handle_init.cpp`),
then each packet is framed by a 16-bit length field and dispatched to a handler
(`server.cpp` -> `handle_bnet.cpp`, the w3route path, etc.). Every handler pulls
variable-length fields out of the raw bytes through a handful of accessors in
`src/common/packet.cpp` and the tag decoders in `src/common/tag.cpp`.

The attack surface is therefore memory-safety bugs in those accessors and in the
per-packet field parsing: out-of-bounds reads/writes, integer overflows in length
math, and uninitialised reads, all driven by bytes an attacker fully controls.
The codebase is large and old and had never been fuzzed or audited.

## Method

Two libFuzzer harnesses (`fuzz/fuzz_packet.cc`, `fuzz/fuzz_tag.cc`) drive the
byte-level parsers under AddressSanitizer + UndefinedBehaviorSanitizer with
`-fno-sanitize-recover=all`. The packet harness is careful to reproduce the
receive-layer invariant (declared size equals bytes received, capped at
`MAX_PACKET_SIZE`), so a sanitizer finding is reachable from the wire and not a
manufactured impossible packet. Every crash was reduced to a seed
(`fuzz/seeds/`), fixed, and confirmed to pass afterwards. The seeds stay in the
tree as a regression corpus.

## Findings

All three were present in upstream and are fixed here (behaviour-preserving; see
`DIVERGENCE.md`).

### 1. `packet_get_str_const` out-of-bounds read

The NUL-scan loop dereferenced `packet->u.data[pos]` in the loop condition before
the `pos >= size` bound was tested in the body. A maximum-size packet with no
terminator walked `pos` to `MAX_PACKET_SIZE` and read one byte past the buffer.
Fix: test the bound in the loop condition, before the read.

### 2. `packet_get_data_const` integer overflow

The bounds check was `offset + len > size` with two 32-bit unsigned operands. A
large `offset` (for example `0xFFFFFFFE`) made the sum wrap to a small value that
passed the check, and the function returned an out-of-bounds pointer the caller
then read `len` bytes from. Fix: the overflow-safe form `len > size || offset >
size - len`.

### 3. `tag_str_to_uint` / `tag_case_str_to_uint`

The 4-char client/arch tag decoders read four bytes unconditionally. On a short
input `tag_str_to_uint` read past the buffer, and `tag_case_str_to_uint` fed an
uninitialised scratch buffer into the decode. Fix: stop at the NUL terminator and
zero-initialise the scratch (also removing a signed-char left-shift UB on bytes
>= 0x80).

## What is not claimed

The build hardening (`HARDENING.md`) is the primary defence for the rest of the
codebase: the hundreds of legacy `sprintf`/`strcpy`/`strcat` sites that FORTIFY
now bounds-checks, and every parser path the fuzzers have not reached yet. The
Westwood Online handlers (`handle_wol*`) carry the most unsafe string handling in
the tree but are a different protocol on different listeners, outside the WC3
6112/6200 threat model, and are contained rather than individually fixed. Fuzzing
coverage is ongoing, not complete.
