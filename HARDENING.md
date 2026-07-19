# Build hardening

The mitigations are wired in `cmake/Modules/Hardening.cmake`, enabled by default
(`-D PVPGN_HARDENING=ON`), and applied to every target. Each compiler flag is
probed with `check_cxx_compiler_flag`, so the build stays portable across GCC and
Clang and silently skips a flag the toolchain does not accept.

## Flag set

Compiler:

```
-fstack-protector-strong          stack canaries
-fstack-clash-protection          defeat stack-clash guard-page jumps
-fcf-protection=full              CET: IBT + SHSTK (x86_64)
-mbranch-protection=standard      PAC + BTI (aarch64, instead of the above)
-ftrivial-auto-var-init=zero      zero otherwise-uninitialised locals
-fno-strict-aliasing              safe type punning for legacy code
-fno-delete-null-pointer-checks   keep NULL checks the optimiser might drop
-fno-strict-overflow              no UB-based signed-overflow assumptions
-Wformat -Wformat=2 -Werror=format-security   format-string sinks are errors
-fPIE
-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3         (non-Debug builds)
-D_GLIBCXX_ASSERTIONS             libstdc++ bounds/precondition checks
```

Linker:

```
-pie
-Wl,-z,relro -Wl,-z,now           full RELRO
-Wl,-z,noexecstack
-Wl,-z,ibt -Wl,-z,shstk           force the x86 CET property note (see below)
```

## The CET note

`-fcf-protection=full` inserts the `endbr64` landing pads, but Debian's toolchain
does not emit the `GNU_PROPERTY` note that tells the dynamic loader to actually
enable IBT/SHSTK enforcement. `-Wl,-z,ibt -Wl,-z,shstk` forces that note at link
time, so the loader turns enforcement on. Both the pads and the note are checked.

## Verify

Never trust the flags, check the binary:

```sh
bash test/checksec.sh build/src/bnetd/bnetd
```

It fails unless full RELRO, a stack canary, PIE, a non-exec stack, FORTIFY `_chk`
symbols, and (on x86_64) the CET note are all present. Manual spot checks:

```sh
readelf -lW  build/src/bnetd/bnetd | grep GNU_RELRO           # full RELRO
readelf -dW  build/src/bnetd/bnetd | grep -E 'BIND_NOW|NOW'
readelf -sW  build/src/bnetd/bnetd | grep __stack_chk_fail    # canary
nm -D        build/src/bnetd/bnetd | grep _chk                # FORTIFY
readelf -nW  build/src/bnetd/bnetd | grep 'x86 feature'       # CET
objdump -d   build/src/bnetd/bnetd | grep -c endbr64          # IBT pads
```

## Runtime note

FORTIFY_SOURCE=3, `_GLIBCXX_ASSERTIONS`, and the stack canary turn a latent
overflow into a clean `abort()`. That is the design: fail closed. Run the daemon
under a supervisor that restarts it (the container does), so a crash is a blip,
not an outage, and never an exploit.
