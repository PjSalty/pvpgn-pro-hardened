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
#include "common/bn_type.h"
#include "common/tag.h"
#include "common/field_sizes.h"
#define ANONGAME_GAMERESULT_INTERNAL_ACCESS
#include "bnetd/anongame_gameresult.h"
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

// ---- w3route game result parser: well-formed packets only -----------------
// the hero count always matches the hero records present, or the packet is cut
// short of its fixed parts (both builds refuse that before allocating), and
// every player number is one a game can have. a hero count the packet cannot
// hold and a player number outside 1..ANONGAME_MAX_GAMECOUNT are the
// out-of-contract cases: pristine leaks, aborts or hands out a wild index
// there, and src/test/regression_gameresult.cc covers them instead.
static void test_gameresults() {
	using namespace pvpgn::bnetd;
	for (int i = 0; i < 20000; i++) {
		unsigned players = (unsigned)(rnd() % 13);
		unsigned heroes = (rnd() % 4) ? (unsigned)(rnd() % 13) : 0;
		unsigned n = sizeof(t_client_w3route_gameresult) + players * sizeof(t_client_w3route_gameresult_player)
		             + sizeof(t_client_w3route_gameresult_part2) + heroes * sizeof(t_client_w3route_gameresult_hero)
		             + sizeof(t_client_w3route_gameresult_part3);

		t_packet *p = (t_packet *)malloc(sizeof(*p));
		std::memset(p, 0, sizeof(*p));
		p->ref = 1; p->pclass = packet_class_w3route;
		for (unsigned j = 0; j < n; j++) p->u.data[j] = (char)rnd(); // every field random
		bn_byte_set(&p->u.client_w3route_gameresult.number_of_results, players);
		for (unsigned j = 0; j < players; j++)
			p->u.data[sizeof(t_client_w3route_gameresult) + j * sizeof(t_client_w3route_gameresult_player)] =
				(char)(1 + rnd() % ANONGAME_MAX_GAMECOUNT);
		t_client_w3route_gameresult_part2 *part2 = (t_client_w3route_gameresult_part2 *)
			(p->u.data + sizeof(t_client_w3route_gameresult) + players * sizeof(t_client_w3route_gameresult_player));
		bn_int_set(&part2->heroes_used_count, heroes);
		if (rnd() % 8 == 0 && heroes == 0) n -= 1 + (unsigned)(rnd() % 60); // cut short: must be refused
		packet_set_size(p, n);           // declared size == bytes present (framer invariant)

		t_anongame_gameresult *r = anongame_gameresult_parse(p);
		mix_u32(r ? 0x6A3Eu : 0u);
		if (r) {
			mix_u32((uint32_t)gameresult_get_number_of_results(r));
			for (unsigned j = 0; j < players; j++) {
				mix_u32((uint32_t)gameresult_get_player_number(r, (int)j));
				mix_u32((uint32_t)gameresult_get_player_result(r, (int)j));
				mix_u32((uint32_t)r->players[j].race);
			}
			mix_u32((uint32_t)r->unit_score); mix_u32((uint32_t)r->heroes_score);
			mix_u32((uint32_t)r->resource_score); mix_u32((uint32_t)r->units_produced);
			mix_u32((uint32_t)r->units_killed); mix_u32((uint32_t)r->buildings_produced);
			mix_u32((uint32_t)r->buildings_razed); mix_u32((uint32_t)r->largest_army);
			mix_u32((uint32_t)r->heroes_used_count);
			mix_u32(r->heroes ? 1u : 0u);
			for (unsigned j = 0; j < heroes; j++) {
				mix_u32((uint32_t)r->heroes[j].level);
				mix_u32((uint32_t)r->heroes[j].race_and_name);
				mix_u32((uint32_t)r->heroes[j].hero_xp);
			}
			mix_u32((uint32_t)r->heroes_killed); mix_u32((uint32_t)r->items_obtained);
			mix_u32((uint32_t)r->mercenaries_hired); mix_u32((uint32_t)r->total_hero_xp);
			mix_u32((uint32_t)r->gold_mined); mix_u32((uint32_t)r->lumber_harvested);
			mix_u32((uint32_t)r->resources_traded_given); mix_u32((uint32_t)r->resources_traded_taken);
			mix_u32((uint32_t)r->tech_percentage); mix_u32((uint32_t)r->gold_lost_to_upkeep);
			gameresult_destroy(r);
		}
		free(p);
	}
}

int main() {
	test_tags();
	test_packets();
	test_gameresults();
	std::printf("DIFFTEST_DIGEST=%08x\n", digest);
	return 0;
}
