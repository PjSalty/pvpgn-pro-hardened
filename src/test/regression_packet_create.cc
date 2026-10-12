// regression_packet_create.cc - guards the zeroing in packet_create
// (src/common/packet.cpp).
//
// packet_create did not initialise the packet buffer, and many handlers read a
// fixed field without checking that the packet is long enough to hold it. For
// a short packet such a read returned whatever an earlier packet had left on
// the heap, and handlers that echo the field (the count of an anongame
// tournament or icon request, for one) sent those bytes back to the client.
//
// xmalloc is defined here instead of linking common/xalloc.cpp and hands out
// memory filled with a pattern, the way a heap in use holds old data. A new
// packet must read as zero all the same.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/bn_type.h"
#include "common/xalloc.h"
#include "common/setup_after.h"

using namespace pvpgn;

namespace pvpgn
{
	void *xmalloc_real(std::size_t size, const char *, unsigned) {
		return std::memset(std::malloc(size ? size : 1), 0xA5, size);
	}

	void xfree_real(void *ptr, const char *, unsigned) {
		std::free(ptr);
	}
}

static int failures = 0;

static void check(const char *what, bool ok) {
	std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		failures++;
}

int main() {
	static const t_packet_class classes[] = {
		packet_class_init, packet_class_bnet, packet_class_file, packet_class_udp,
		packet_class_raw, packet_class_d2game, packet_class_d2cs, packet_class_d2gs,
		packet_class_d2cs_bnetd, packet_class_w3route, packet_class_wolgameres,
	};

	bool zero = true;
	for (unsigned int i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
		t_packet *packet = packet_create(classes[i]);
		if (!packet) {
			std::printf("        no packet for class %d\n", (int)classes[i]);
			zero = false;
			continue;
		}
		for (unsigned int pos = 0; pos < sizeof(packet->u.data); pos++) {
			if (packet->u.data[pos] != 0) {
				if (zero)
					std::printf("        byte %u of a new packet of class %d is 0x%02x\n",
					            pos, (int)classes[i], (unsigned int)(unsigned char)packet->u.data[pos]);
				zero = false;
				break;
			}
		}
		zero = zero && packet->len == 0 && packet->flags == 0;
		packet_del_ref(packet);
	}
	check("a new packet of every class reads as zero", zero);

	// what a handler sees when it reads a field the client did not send:
	// 5 bytes on the wire are the header and the option, the count comes after
	t_packet *packet = packet_create(packet_class_bnet);
	if (!packet) {
		std::printf("PACKET CREATE REGRESSION: FAIL (no packet)\n");
		return 1;
	}
	packet_set_size(packet, sizeof(t_bnet_header) + 1);
	unsigned int count = bn_int_get(packet->u.client_anongame_tournament_request.count);
	if (count)
		std::printf("        the count behind a 5 byte request reads 0x%08x\n", count);
	check("a field past the end of a short packet reads as zero", count == 0);
	packet_del_ref(packet);

	if (failures) {
		std::printf("PACKET CREATE REGRESSION: FAIL (%d)\n", failures);
		return 1;
	}
	std::printf("PACKET CREATE REGRESSION: PASS\n");
	return 0;
}
