// difftest_parsers.cc - behavior-preservation oracle for the hardened parsers.
//
// Compiled TWICE: once against the pristine (upstream) common sources, once
// against the hardened ones. For every VALID input (inputs inside each
// function's documented contract, where the pristine code is well-defined) it
// prints a stable digest. The two builds' output must be byte-identical - that
// is the proof the security fixes did not change behavior for real traffic.
//
// Inputs that are OUT of contract (the overflow / no-terminator / short-buffer
// cases the fixes exist to reject) are deliberately EXCLUDED: there the pristine
// code is undefined/over-reads and the fixed code returns NULL, so they are
// expected to differ and are covered by the fuzz seeds instead.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/tag.h"
#include "common/field_sizes.h"
#include "common/setup_after.h"

using namespace pvpgn;

// small deterministic PRNG (splitmix64) - no time/rand, fully reproducible.
static uint64_t S = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd() {
	uint64_t z = (S += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static uint32_t digest = 2166136261u; // FNV-1a accumulator over all results
static void mix(const void *p, size_t n) {
	const uint8_t *b = (const uint8_t *)p;
	for (size_t i = 0; i < n; i++) { digest ^= b[i]; digest *= 16777619u; }
}
static void mix_u32(uint32_t v) { mix(&v, sizeof v); }
static void mix_str(const char *s) { mix_u32(s ? 1u : 0u); if (s) mix(s, std::strlen(s) + 1); }

// ---- tag round-trips: 4-char ASCII tags (both builds well-defined) ---------
static void test_tags() {
	static const char *known[] = {
		"3RAW", "W3XP", "PX3W", "PX2D", "VD2D", "SEXP", "STAR", "SSHR",
		"DRTL", "DSHR", "W2BN", "IX86", "XMAC", "PMAC", "UNKN", "unkn",
	};
	for (unsigned k = 0; k < sizeof(known) / sizeof(known[0]); k++) {
		char buf[5]; std::memcpy(buf, known[k], 5);
		mix_u32((uint32_t)tag_str_to_uint(buf));
		mix_u32((uint32_t)tag_case_str_to_uint(buf));
		char out[8] = {0}; mix_str(tag_uint_to_str(out, tag_str_to_uint(buf)));
		char rev[8] = {0}; mix_str(tag_uint_to_revstr(rev, tag_str_to_uint(buf)));
	}
	// 50k random 4-char printable-ASCII tags in a zero-filled 5-byte buffer.
	for (int i = 0; i < 50000; i++) {
		char buf[5] = {0};
		for (int j = 0; j < 4; j++) buf[j] = (char)(0x21 + (rnd() % (0x7e - 0x21)));
		mix_u32((uint32_t)tag_str_to_uint(buf));
		mix_u32((uint32_t)tag_case_str_to_uint(buf));
	}
	// short (1-3 char) NUL-terminated tags in a ZERO-FILLED 5-byte buffer:
	// pristine reads the zero pad, fixed stops at the NUL - both yield the same
	// value precisely because the pad is zero. (uninit-pad is the fuzz case.)
	for (int i = 0; i < 20000; i++) {
		char buf[5] = {0};
		int len = 1 + (int)(rnd() % 3);
		for (int j = 0; j < len; j++) buf[j] = (char)(0x21 + (rnd() % (0x7e - 0x21)));
		mix_u32((uint32_t)tag_str_to_uint(buf));
	}
}

// ---- packet string/data readers: valid windows only -----------------------
static t_packet *mk_bnet(const uint8_t *body, unsigned n) {
	t_packet *p = (t_packet *)malloc(sizeof(*p));
	std::memset(p, 0, sizeof(*p));
	p->ref = 1; p->pclass = packet_class_bnet;
	if (n > MAX_PACKET_SIZE) n = MAX_PACKET_SIZE;
	std::memcpy(p->u.data, body, n);
	packet_set_size(p, n);           // declared size == bytes present (framer invariant)
	return p;
}

static void test_packets() {
	for (int i = 0; i < 40000; i++) {
		// build a valid packet: 4-byte header + payload that CONTAINS a NUL.
		unsigned payload = 1 + (unsigned)(rnd() % 200);
		unsigned n = 4 + payload;
		if (n > MAX_PACKET_SIZE) n = MAX_PACKET_SIZE;
		uint8_t body[MAX_PACKET_SIZE];
		for (unsigned j = 0; j < n; j++) body[j] = (uint8_t)(0x20 + (rnd() % 0x5e)); // printable
		// guarantee a terminator somewhere in the payload so str reads succeed.
		unsigned nul_at = 4 + (unsigned)(rnd() % payload);
		body[nul_at] = 0;
		t_packet *p = mk_bnet(body, n);
		unsigned size = packet_get_size(p);

		mix_u32(size);
		mix_u32(packet_get_type(p));
		mix_u32(packet_get_header_size(p));

		// str reader at valid offsets, generous maxlen.
		for (int t = 0; t < 6; t++) {
			unsigned off = (unsigned)(rnd() % (size + 2)); // includes a few off==size / >size (both must reject)
			unsigned maxlen = (unsigned)(rnd() % 300);
			mix_str(packet_get_str_const(p, off, maxlen));
		}
		// data reader at valid (offset+len<=size) windows plus a few rejects.
		for (int t = 0; t < 6; t++) {
			unsigned off = (unsigned)(rnd() % (size + 2));
			unsigned len = (unsigned)(rnd() % (size + 2));
			const void *d = packet_get_data_const(p, off, len);
			mix_u32(d ? 0xD00Du : 0u);
			if (d) mix(d, len); // both builds must return the same bytes
		}
		// raw reader.
		for (int t = 0; t < 4; t++) {
			unsigned off = (unsigned)(rnd() % (size + 2));
			const void *r = packet_get_raw_data_const(p, off);
			mix_u32(r ? 0x2A2Au : 0u);
		}
		free(p);
	}
}

int main() {
	test_tags();
	test_packets();
	std::printf("DIFFTEST_DIGEST=%08x\n", digest);
	return 0;
}
