# Contributing

This is a hardening fork of PvPGN-PRO. Contributions that make the daemon safer
without changing the wire or config contract are very welcome: fuzz harnesses,
parser fixes, more test coverage, tighter runtime sandboxing.

## Ground rules

- **Stay a drop-in.** No new ports, no config changes, no protocol changes. A
  fix must not change behaviour for valid traffic. Prove it with
  `test/run-difftest.sh` when you touch a parser.
- **Fix the code, not the test.** If a fuzzer crashes, the parser is wrong, not
  the harness.
- **Parser bugs are usually upstream bugs.** If the fix applies to
  `pvpgn/pvpgn-server`, send it there too and note it in `DIVERGENCE.md` so it
  can be dropped once merged.

## Local workflow

```sh
# build + verify mitigations + run upstream unit tests (needs docker)
bash test/build-and-verify.sh

# behaviour-preservation oracle (fixed vs pristine upstream)
bash test/run-difftest.sh

# build the fuzzers and run the regression corpus (+ optional campaign)
FUZZ_SECONDS=60 bash fuzz/run-regression.sh
```

The fuzzers need clang with the compiler-rt fuzzer/sanitizer runtime
(`libclang-rt-*-dev` on Debian).

## Adding a fuzz target

Drop a `fuzz/fuzz_<name>.cc` with an `LLVMFuzzerTestOneInput`, link only the
translation units it needs (see `fuzz/build-fuzz.sh`). If it finds a crash, add
the reducer to `fuzz/seeds/<name>/`, fix the code, and confirm the seed passes.

## Pull requests

Keep them small and single-purpose. CI must be green: build + checksec gate +
unit tests + differential oracle + fuzz regression, plus CodeQL. New high-severity
static-analysis findings on changed code block the merge; the legacy baseline
does not.
