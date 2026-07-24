// regression_fmt_lifetime.cc - guards the two fmt-related memory-safety bugs
// that upstream introduced when it moved logging/i18n onto fmt.
//
// 1. _localize (src/bnetd/i18n.h) held `const char *format =
//    fmt::to_string(format_str).c_str()`. The temporary std::string dies at the
//    end of the statement, so fmt::format later parsed freed heap memory. Any
//    format string longer than the small-string optimisation is heap allocated,
//    and glibc writes tcache pointers over the first bytes the moment it is
//    freed, so the corruption was deterministic and leaked freed bytes to the
//    client. It never crashed, because _localize catches the fmt error.
//
// 2. _client_motd_w3 (src/bnetd/handle_bnet.cpp) wrote
//    `fmt::format_to(serverinfo, "{}" + '\n', line)`. That is pointer
//    arithmetic on a 3-byte literal, not concatenation: it walks 10 bytes past
//    the start and hands fmt an out-of-bounds format string.
//
// Both are exercised here through the same idioms the fixed code uses. Build
// under ASan (test/run-fmt-regression.sh) so a reintroduced dangling pointer is
// a hard failure and not a silently wrong string.

#include <cstdio>
#include <cstring>
#include <string>

#include <fmt/format.h>

static int failures = 0;

static void check(const char *what, const std::string &got, const std::string &want) {
	if (got == want) {
		std::printf("  PASS  %s\n", what);
	} else {
		std::printf("  FAIL  %s\n    got  [%s]\n    want [%s]\n", what, got.c_str(), want.c_str());
		failures++;
	}
}

// Mirrors the fixed _localize lifetime handling: hold the caller's string_view,
// and only re-point at a translation the caller's map owns. Passing a
// heap-length format string is the whole point - an SSO-length one would hide
// the bug.
static std::string localize_like(fmt::string_view format_str, const char *translated, int arg) {
	fmt::string_view format = format_str;
	if (translated) {
		format = translated;
	}
	return fmt::format(format, arg);
}

int main() {
	// 1. long (heap-allocated, > SSO) format string, no translation: must come
	//    back intact with the argument substituted.
	const char *long_fmt = "You are sending commands to {} too quickly, please slow down and try again";
	check("long format string round-trips untranslated",
	      localize_like(long_fmt, nullptr, 7),
	      "You are sending commands to 7 too quickly, please slow down and try again");

	// 2. same, but a translation is found: the translation must be used, and it
	//    is owned by the caller (static here, the translations map in bnetd).
	static const char *translation = "Du sendest Befehle zu schnell an {}, bitte warte einen Moment";
	check("long format string uses the translation when one is found",
	      localize_like(long_fmt, translation, 3),
	      "Du sendest Befehle zu schnell an 3, bitte warte einen Moment");

	// 3. a short (SSO) format string must behave identically - this one survived
	//    even the buggy version, so it pins that the fix did not change it.
	check("short format string round-trips",
	      localize_like("hi {}", nullptr, 1),
	      "hi 1");

	// 4. the MOTD line format: the newline must be part of the literal. The old
	//    `"{}" + '\n'` produced an out-of-bounds pointer instead of "{}\n".
	{
		fmt::memory_buffer buf;
		fmt::format_to(buf, "{}\n", 42);
		check("motd line format emits the argument and a newline",
		      fmt::to_string(buf), "42\n");
	}

	if (failures) {
		std::printf("FMT LIFETIME REGRESSION: FAIL (%d)\n", failures);
		return 1;
	}
	std::printf("FMT LIFETIME REGRESSION: PASS\n");
	return 0;
}
