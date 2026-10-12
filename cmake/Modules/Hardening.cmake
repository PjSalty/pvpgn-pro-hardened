# Hardening.cmake - security hardening flags for the pvpgn-pro-hardened build.
#
# Follows the OpenSSF Compiler Options Hardening Guide for C/C++. The intent is
# fail-closed: a memory-safety bug in the packet parsers becomes a clean crash
# (stack canary / FORTIFY / bounds assertion abort) that the container restarts,
# instead of an exploitable primitive. Every flag is probed with
# check_cxx_compiler_flag so the build stays portable across GCC and Clang.
#
# Verify the result lands in the binary with test/checksec.sh (checksec/readelf),
# never trust the flags alone.

include(CheckCXXCompilerFlag)

option(PVPGN_HARDENING "Build with security hardening flags (recommended)" ON)

if(NOT PVPGN_HARDENING)
	message(STATUS "pvpgn: security hardening DISABLED (PVPGN_HARDENING=OFF)")
	return()
endif()

if(NOT (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
	message(STATUS "pvpgn: hardening flags only wired for GCC/Clang; skipping on ${CMAKE_CXX_COMPILER_ID}")
	return()
endif()

message(STATUS "pvpgn: security hardening ENABLED")

# --- compiler flags (probed individually) -----------------------------------
set(_hardening_flags
	-fstack-protector-strong        # stack canaries on functions with buffers
	-fstack-clash-protection        # defeat stack-clash guard-page jumps
	-ftrivial-auto-var-init=zero    # zero-init otherwise-uninitialised locals
	-fno-strict-aliasing            # legacy code punning safety
	-fno-delete-null-pointer-checks # keep NULL checks the optimiser might drop
	-fno-strict-overflow            # no UB-based signed-overflow assumptions
	-fPIE
)

# control-flow integrity: CET on x86_64, PAC/BTI on aarch64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|i.86")
	list(APPEND _hardening_flags -fcf-protection=full)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
	list(APPEND _hardening_flags -mbranch-protection=standard)
endif()

foreach(_flag IN LISTS _hardening_flags)
	string(MAKE_C_IDENTIFIER "PVPGN_HAVE_${_flag}" _cachevar)
	check_cxx_compiler_flag("${_flag}" ${_cachevar})
	if(${_cachevar})
		add_compile_options("${_flag}")
	else()
		message(STATUS "pvpgn: compiler does not accept ${_flag}, skipping")
	endif()
endforeach()

# format-string sinks are build errors. probed as one group: GCC rejects
# -Werror=format-security unless -Wformat is already on, so probed alone it was
# silently skipped by every GCC that does not default to -Wformat (Debian's).
set(_format_flags -Wformat -Wformat=2 -Werror=format-security)
string(REPLACE ";" " " _format_flags_str "${_format_flags}")
check_cxx_compiler_flag("${_format_flags_str}" PVPGN_HAVE_FORMAT_SECURITY)
if(PVPGN_HAVE_FORMAT_SECURITY)
	add_compile_options(${_format_flags})
else()
	message(STATUS "pvpgn: compiler does not accept ${_format_flags_str}, skipping")
endif()

# --- preprocessor defines ----------------------------------------------------
# _FORTIFY_SOURCE needs an optimising build; skip it in Debug where it warns.
# -U first avoids a redefinition clash with a distro-injected _FORTIFY_SOURCE=2.
add_compile_options(
	"$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>"
	"$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>"
)
# libstdc++ bounds/precondition assertions (safe with both GCC and Clang+libstdc++).
add_compile_definitions(_GLIBCXX_ASSERTIONS)

# --- linker flags ------------------------------------------------------------
# full RELRO (GOT read-only after relocation), non-lazy binding, non-exec stack,
# and a position-independent executable.
set(_hardening_link_flags
	-pie
	"LINKER:-z,relro"
	"LINKER:-z,now"
	"LINKER:-z,noexecstack"
)
# force the x86 CET property note so the dynamic loader actually enables IBT+SHSTK
# enforcement. -fcf-protection emits the endbr64 landing pads, but Debian's
# toolchain does not emit the GNU_PROPERTY note on its own; -z ibt / -z shstk do.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|i.86")
	list(APPEND _hardening_link_flags "LINKER:-z,ibt" "LINKER:-z,shstk")
endif()
add_link_options(${_hardening_link_flags})
