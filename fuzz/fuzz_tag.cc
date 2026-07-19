// fuzz_tag.cc - libFuzzer harness for the tag string<->uint primitives.
//
// tag_str_to_uint / tag_case_str_to_uint decode 4-char client/arch tags out of
// packet fields (every clienttag, archtag, gametag). They are the smallest
// isolated parsers in the tree. Passing an exact-length heap buffer (NOT
// NUL-padded) lets ASan observe any read past the supplied bytes, proving the
// primitive trusts its caller for >=4 readable bytes.

#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "common/setup_before.h"
#include "common/tag.h"
#include "common/setup_after.h"

using namespace pvpgn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1) return 0;
	uint8_t sel = data[0];
	const uint8_t *body = data + 1;
	size_t n = size - 1;

	// real callers hand these a NUL-terminated string (from packet_get_str) or a
	// fixed 4-byte field. model that: a NUL-terminated heap buffer sized exactly
	// n+1. pre-fix, tag_str_to_uint reads all 4 bytes unconditionally and walks
	// past the terminator on a <3-char input; post-fix it stops at the NUL.
	char *nt = (char *)malloc(n + 1);
	if (!nt) return 0;
	std::memcpy(nt, body, n);
	nt[n] = '\0';

	if (sel & 1) {
		(void)tag_str_to_uint(nt);
	} else {
		(void)tag_case_str_to_uint(nt);
	}

	// round-trip writers: require a >=5 byte destination.
	char out[8];
	t_tag t = tag_str_to_uint(nt);
	(void)tag_uint_to_str(out, t);
	(void)tag_uint_to_revstr(out, t);

	free(nt);
	return 0;
}
