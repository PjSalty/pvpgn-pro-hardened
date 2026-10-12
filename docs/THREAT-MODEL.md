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

## Findings from review

Found by reading the handlers, which the fuzzers do not drive. Each was present
in upstream and has a regression test in `src/test/`.

### 4. `_client_anongame_infos` NULL dereference

The anongame info request carries `noitems`, a client byte, and one 8-byte entry
per item. The handler read the entries through `packet_get_data_const` without
checking the packet held them, and passed the result, NULL past the end of the
packet, to `memcpy`. Any logged-in client could crash the daemon with one short
packet. Fix: reject a packet shorter than its header plus the announced entries.

### 5. Unterminated filename in the raw file request

A file connection in raw mode has its filename read straight off the socket into
a `MAX_FILENAME_STR` stack buffer and handed to `file_send`. The read could fill
the whole buffer, leaving no terminator for the string functions behind it, and
its result was ignored, so a failed read still ran `file_send`. Reachable before
login. Fix: read one byte less than the buffer, and reject the request when the
read returns nothing or fails.

### 6. `anongame_gameresult_parse` allocation from an unchecked count

A w3route game result carries `heroes_used_count`, a 32-bit int from the client,
and that many hero records. The parser sized an `xmalloc` from the count before
checking it against the packet: a negative count asked for nearly `SIZE_MAX`
bytes and `xmalloc` aborted the daemon. The check that followed could wrap on a
32-bit `size_t`, and when it rejected the packet it returned without freeing the
result, the player table or the hero table. Fix: bound the count by the bytes
left in the packet, by division, before allocating, and free on that path.

### 7. `anongame_evaluate_results` out-of-bounds stack write

Every entry of a w3route game result names a player by number, one client byte.
The evaluation indexed two 12-entry vote tables on its stack with it, minus one,
unchecked: a player in a matched game could increment stack memory outside them,
once per entry. Fix: `gameresult_get_player_number` only hands out 1 to 12, and
the evaluation skips an entry that is not about a player of the game.

### 8. `file_send` packet leak

`file_send` creates its reply packet before it looks the file up, and returned
without releasing it when the lookup failed: about 3 KB leaked for every request
naming a file that does not exist, on a connection that needs no login and can
repeat the request. Fix: release the packet on that path.

### 9. Stale heap bytes behind a short packet

`packet_create` did not initialise the 3072-byte packet buffer, and many handlers
read a fixed field without checking the packet is long enough to hold it. For a
short packet that read returned what an earlier packet had left on the heap, and
handlers that echo the field, such as the `count` of an anongame tournament or
icon request, sent 4 of those bytes back per request. Fix: `packet_create` zeroes
the packet.

### 10. Two unbounded `sprintf` writes

`_handle_set_command` (`src/bnetd/command.cpp`) formatted its confirmation with
`sprintf` into a 255-byte buffer: the attacker-chosen key and value of a `/set`
(up to 128 each, admin command group, reachable over bnet and the longer IRC and
telnet command lines) overflowed it. The IRC emote path (`src/bnetd/irc.cpp`)
guarded its `sprintf` with a length test that omitted the leading `:`, so a
502-character emote, reachable by any user on the IRC listener, wrote one byte
past a 512-byte stack buffer. Both now use `snprintf` with the real buffer size;
anything that fit before is unchanged.

The third site the build flags, `ipban.cpp`, is left as `sprintf`: its `%.48s`
argument, `seconds_to_timestr`, is at most ~41 characters, so `"(...)"` cannot
reach the 50-byte buffer, and the duration is set by an admin, not the network.

## What is not claimed

The build hardening (`HARDENING.md`) is the primary defence for the rest of the
codebase: the hundreds of legacy `sprintf`/`strcpy`/`strcat` sites that FORTIFY
now bounds-checks, and every parser path the fuzzers have not reached yet. The
Westwood Online handlers (`handle_wol*`) carry the most unsafe string handling in
the tree but are a different protocol on different listeners, outside the WC3
6112/6200 threat model, and are contained rather than individually fixed. Fuzzing
coverage is ongoing, not complete.
