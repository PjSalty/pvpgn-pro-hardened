// regression_anongame_inforeq.cc - guards the item bound of
// _client_anongame_infos (src/bnetd/handle_anongame.cpp).
//
// A CLIENT_FINDANONGAME_INFOREQ announces noitems, a client byte, and carries
// one 8-byte <tag><unknown> pair per item after its header. The handler read
// the pairs through packet_get_data_const() without checking they were in the
// packet. That accessor returns NULL for a window past the end, and the result
// went straight into std::memcpy, so a logged-in client could crash the daemon
// with a header-only packet announcing items.
//
// The handler now rejects a packet smaller than anongame_inforeq_size(). This
// test drives that helper from the real header against the real accessor: for
// every item count, and every packet size up to past the boundary, it must
// accept exactly the packets whose pairs the accessor can all hand back.
// Accepting a shorter one is the crash, rejecting a complete one would break a
// valid client.
//
// The handler itself needs a logged-in connection and is not run here.

#include <cstdio>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/bn_type.h"
#include "bnetd/handle_anongame.h"
#include "common/setup_after.h"

using namespace pvpgn;
using namespace pvpgn::bnetd;

// the handler addresses the pairs with these literal offsets
static_assert(sizeof(t_client_findanongame_inforeq) == 10, "inforeq header is 10 bytes on the wire");

// The two reads the handler does for item i.
static bool handler_can_read(t_packet const *packet, unsigned int i) {
	return packet_get_data_const(packet, 10 + (i * 8), 4) && packet_get_data_const(packet, 14 + (i * 8), 4);
}

int main() {
	int failures = 0;
	t_packet *packet = packet_create(packet_class_bnet);

	for (unsigned int noitems = 0; noitems <= 255; noitems++) {
		for (unsigned int size = sizeof(t_bnet_header); size <= 10 + noitems * 8 + 8; size++) {
			packet_set_size(packet, size);
			bn_byte_set(&packet->u.client_findanongame_inforeq.noitems, noitems);

			bool readable = size >= sizeof(t_client_findanongame_inforeq);
			for (unsigned int i = 0; i < noitems && readable; i++)
				readable = handler_can_read(packet, i);
			bool accepted = packet_get_size(packet) >= anongame_inforeq_size(packet);

			if (accepted != readable && failures++ < 5)
				std::printf("  FAIL  noitems=%u size=%u: %s, but the handler %s read all of it\n",
				            noitems, size, accepted ? "accepted" : "rejected", readable ? "can" : "cannot");
		}
	}
	packet_del_ref(packet);

	if (failures) {
		std::printf("ANONGAME INFOREQ REGRESSION: FAIL (%d)\n", failures);
		return 1;
	}
	std::printf("  PASS  a packet is accepted exactly when it holds the header and every announced item\n");
	std::printf("ANONGAME INFOREQ REGRESSION: PASS\n");
	return 0;
}
