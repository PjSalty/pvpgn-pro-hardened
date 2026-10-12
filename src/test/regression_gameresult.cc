// regression_gameresult.cc - guards the hero block of anongame_gameresult_parse
// (src/bnetd/anongame_gameresult.cpp).
//
// A w3route game result carries heroes_used_count, a 32-bit int the client
// picks, followed by that many hero records. The parser sized an xmalloc from
// the count before checking it against the packet, so a negative count asked
// for nearly SIZE_MAX bytes and xmalloc aborted the daemon. The check that came
// after it could wrap, and when it did reject the packet it returned NULL
// without freeing the result, the player table or the hero table.
//
// This runs the real parser on real packets. xmalloc/xfree are defined here
// instead of linking common/xalloc.cpp, so the test sees every request the
// parser makes: one no packet could justify, or one it never gives back.

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/bn_type.h"
#include "common/xalloc.h"
#define ANONGAME_GAMERESULT_INTERNAL_ACCESS
#include "bnetd/anongame_gameresult.h"
#include "common/setup_after.h"

using namespace pvpgn;
using namespace pvpgn::bnetd;

static long live = 0; // blocks handed out and not freed yet

namespace pvpgn
{
	void *xmalloc_real(std::size_t size, const char *, unsigned) {
		if (size > 64 * 1024) {
			std::printf("  FAIL  the parser asked for %zu bytes, a packet is at most %u\n", size, MAX_PACKET_SIZE);
			std::printf("GAMERESULT REGRESSION: FAIL\n");
			std::fflush(stdout);
			std::exit(1);
		}
		live++;
		return std::malloc(size ? size : 1);
	}

	void xfree_real(void *ptr, const char *, unsigned) {
		live--;
		std::free(ptr);
	}
}

static int failures = 0;

static void check(const char *what, bool ok) {
	std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
	std::fflush(stdout); // a leak report at exit must not swallow this
	if (!ok)
		failures++;
}

// A game result with `players` results and `present` hero records whose part2
// announces `announced` heroes. Every field gets a value the checks can predict.
static t_packet *gameresult_packet(unsigned int players, int announced, unsigned int present) {
	t_packet *packet = packet_create(packet_class_w3route);
	packet_set_size(packet, sizeof(t_client_w3route_gameresult));
	packet_set_type(packet, CLIENT_W3ROUTE_GAMERESULT_W3XP);
	bn_byte_set(&packet->u.client_w3route_gameresult.number_of_results, players);

	for (unsigned int i = 0; i < players; i++) {
		t_client_w3route_gameresult_player player = {};
		bn_byte_set(&player.number, i + 1);
		bn_int_set(&player.result, i % 2 ? W3_GAMERESULT_LOSS : W3_GAMERESULT_WIN);
		bn_int_set(&player.race, 1u << (i % 4));
		packet_append_data(packet, &player, sizeof(player));
	}

	t_client_w3route_gameresult_part2 part2 = {};
	bn_int_set(&part2.unit_score, 1001);
	bn_int_set(&part2.heroes_score, 1002);
	bn_int_set(&part2.resource_score, 1003);
	bn_int_set(&part2.units_produced, 1004);
	bn_int_set(&part2.units_killed, 1005);
	bn_int_set(&part2.buildings_produced, 1006);
	bn_int_set(&part2.buildings_razed, 1007);
	bn_int_set(&part2.largest_army, 1008);
	bn_int_set(&part2.heroes_used_count, announced);
	packet_append_data(packet, &part2, sizeof(part2));

	for (unsigned int i = 0; i < present; i++) {
		t_client_w3route_gameresult_hero hero = {};
		bn_short_set(&hero.level, i + 1);
		bn_int_set(&hero.race_and_name, 0x48000000u + i);
		bn_int_set(&hero.hero_xp, 100 * i);
		packet_append_data(packet, &hero, sizeof(hero));
	}

	t_client_w3route_gameresult_part3 part3 = {};
	bn_int_set(&part3.heroes_killed, 2001);
	bn_int_set(&part3.items_obtained, 2002);
	bn_int_set(&part3.mercenaries_hired, 2003);
	bn_int_set(&part3.total_hero_xp, 2004);
	bn_int_set(&part3.gold_mined, 2005);
	bn_int_set(&part3.lumber_harvested, 2006);
	bn_int_set(&part3.resources_traded_given, 2007);
	bn_int_set(&part3.resources_traded_taken, 2008);
	bn_int_set(&part3.tech_percentage, 2009);
	bn_int_set(&part3.gold_lost_to_upkeep, 2010);
	packet_append_data(packet, &part3, sizeof(part3));

	return packet;
}

// A complete packet must parse to exactly what was sent and free cleanly.
static bool parses(unsigned int players, unsigned int heroes) {
	t_packet *packet = gameresult_packet(players, heroes, heroes);
	long before = live;
	t_anongame_gameresult *r = anongame_gameresult_parse(packet);

	bool ok = r && r->number_of_results == (char)players && r->heroes_used_count == (int)heroes
	    && r->unit_score == 1001 && r->heroes_score == 1002 && r->resource_score == 1003
	    && r->units_produced == 1004 && r->units_killed == 1005 && r->buildings_produced == 1006
	    && r->buildings_razed == 1007 && r->largest_army == 1008
	    && r->heroes_killed == 2001 && r->items_obtained == 2002 && r->mercenaries_hired == 2003
	    && r->total_hero_xp == 2004 && r->gold_mined == 2005 && r->lumber_harvested == 2006
	    && r->resources_traded_given == 2007 && r->resources_traded_taken == 2008
	    && r->tech_percentage == 2009 && r->gold_lost_to_upkeep == 2010
	    && (heroes != 0) == (r->heroes != NULL);
	for (unsigned int i = 0; ok && i < players; i++)
		ok = r->players[i].number == (char)(i + 1) && r->players[i].race == (int)(1u << (i % 4))
		    && r->players[i].result == (int)(i % 2 ? W3_GAMERESULT_LOSS : W3_GAMERESULT_WIN);
	for (unsigned int i = 0; ok && i < heroes; i++)
		ok = r->heroes[i].level == (int)(i + 1) && r->heroes[i].race_and_name == (int)(0x48000000u + i)
		    && r->heroes[i].hero_xp == (int)(100 * i);

	if (r)
		gameresult_destroy(r);
	ok = ok && live == before;
	packet_del_ref(packet);
	return ok;
}

// A packet whose hero count does not match its size must be refused, and
// refusing it must not leave anything allocated.
static bool rejects(int announced, unsigned int present) {
	t_packet *packet = gameresult_packet(2, announced, present);
	long before = live;
	t_anongame_gameresult *r = anongame_gameresult_parse(packet);
	long leaked = live - before;

	if (r)
		std::printf("        hero count %d with %u records present was accepted\n", announced, present);
	else if (leaked)
		std::printf("        rejected, but %ld allocation(s) were not freed\n", leaked);
	packet_del_ref(packet);
	return !r && !leaked;
}

int main() {
	// the most heroes a 2 player result can carry in one packet
	const unsigned int room = (MAX_PACKET_SIZE - (sizeof(t_client_w3route_gameresult) + 2 * sizeof(t_client_w3route_gameresult_player)
	    + sizeof(t_client_w3route_gameresult_part2) + sizeof(t_client_w3route_gameresult_part3))) / sizeof(t_client_w3route_gameresult_hero);

	check("results without heroes parse unchanged", parses(0, 0) && parses(1, 0) && parses(2, 0) && parses(8, 0));
	check("results with heroes parse unchanged", parses(2, 1) && parses(2, 3) && parses(8, 12) && parses(1, 40));
	check("a packet filled with heroes to the last byte parses unchanged", parses(2, room));

	// these reach the old size check and are refused by it, without the frees
	check("one hero more than the packet holds is rejected and freed", rejects(3, 2));
	check("a hero count with no hero records at all is rejected and freed", rejects(1, 0));

	// these never got that far: the allocation came first
	check("a negative hero count is rejected and freed", rejects(-1, 0) && rejects(INT_MIN, 2));
	check("a huge hero count is rejected and freed", rejects(INT_MAX, 2) && rejects(100000, 0));
	// 10 * 0x1999999a is 4 mod 2^32: with a 32-bit size_t the old check let it through
	check("a hero count that wraps a 32-bit size is rejected and freed", rejects(0x1999999a, 1));

	if (failures) {
		std::printf("GAMERESULT REGRESSION: FAIL (%d)\n", failures);
		return 1;
	}
	std::printf("GAMERESULT REGRESSION: PASS\n");
	return 0;
}
