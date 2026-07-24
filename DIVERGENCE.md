# Divergence from upstream

This fork tracks [`pvpgn/pvpgn-server`](https://github.com/pvpgn/pvpgn-server).
The base is upstream `master` at commit `fcdf00f` (2021-02-26), which is 102
commits past the last tagged release (`1.99.7.2.1`, 2018). The `upstream-base`
branch pins that pristine base so the divergence is always diffable:

```sh
git diff upstream-base main -- src/
```

The divergence is meant to stay small and shrink over time: the parser fixes are
offered upstream, and once merged they drop out of this list.

## Source changes (behaviour-preserving security fixes)

| File | Change |
|---|---|
| `src/common/packet.cpp` | `packet_get_str_const`: bound the NUL scan by the declared size before dereferencing, fixing a one-byte over-read. |
| `src/common/packet.cpp` | `packet_get_data_const`: overflow-safe `offset + len` check. |
| `src/common/tag.cpp` | `tag_str_to_uint`: stop at the NUL terminator, and drop the signed-char shift UB. |
| `src/common/tag.cpp` | `tag_case_str_to_uint`: zero-initialise the scratch buffer. |
| `src/bnetd/i18n.h` | `_localize`: hold the caller's `fmt::string_view` instead of `fmt::to_string(...).c_str()`, whose temporary died at the end of the statement and left `fmt::format` parsing freed heap memory on every localized message. |
| `src/bnetd/handle_bnet.cpp` | `_client_motd_w3`: `"{}" + '\n'` was pointer arithmetic on a 3-byte literal (10 bytes past its start, 7 out of bounds), handing fmt an out-of-bounds format string. Now `"{}\n"`. |
| `CMakeLists.txt` | move `enable_testing()` before `add_subdirectory(src)` so the unit tests actually build; include the hardening module. |

Every source fix is proved to produce identical output to the pristine code for
valid input by `test/run-difftest.sh`.

## Additions (not upstream code, pure overlay)

- `cmake/Modules/Hardening.cmake`: the mitigation flag set.
- `fuzz/`: libFuzzer harnesses, seed corpus, and the regression runner.
- `test/`: checksec gate, differential oracle, build-and-verify.
- `Dockerfile`, `deploy/`: reproducible hardened image and runtime sandbox.
- `.github/`: CI, CodeQL, static analysis, Scorecard, release pipeline, Dependabot.

## Syncing new upstream

```sh
git fetch upstream
git checkout upstream-base && git merge --ff-only upstream/master   # advance the base
git checkout main && git merge upstream/master                      # bring fixes into main
```

If a merge touches `src/common/packet.cpp` or `src/common/tag.cpp`, re-run
`test/run-difftest.sh` and `fuzz/run-regression.sh` before pushing. When an
upstream release incorporates one of the fixes above, delete the now-redundant
local change during the merge and update this file.
