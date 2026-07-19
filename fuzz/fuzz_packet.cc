// fuzz_packet.cc - libFuzzer harness for the pvpgn packet byte-accessors.
//
// Targets the variable-length readers that every bnet/w3route handler calls to
// pull fields out of raw client bytes: packet_get_str_const, packet_get_data_const,
// packet_get_raw_data_const, packet_get_size, packet_get_type.
//
// Faithfulness: the socket receive layer frames a packet by reading the 16-bit
// header size field, then reading exactly that many bytes into u.data (capped at
// MAX_PACKET_SIZE). We reproduce that invariant precisely - received bytes ==
// declared size <= MAX_PACKET_SIZE - so any sanitizer finding here is reachable
// from the wire, not a manufactured impossible packet.
//
// Input layout (control fields taken from the TAIL so the head stays wire-bytes):
//   [ body .................... | off:u32le | len:u32le | ctl:u8 ]
//   body       -> copied into u.data as the on-wire packet (incl. its header)
//   off,len    -> offset / length|maxlen args handed to the accessors
//   ctl        -> low bits pick packet class; next bit picks str vs data path

#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/field_sizes.h"
#include "common/setup_after.h"

using namespace pvpgn;

static uint32_t rd_u32le(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// classes whose size comes from an attacker-controlled 16-bit header field.
static t_packet_class pick_class(uint8_t sel) {
	switch (sel % 4) {
		case 0:  return packet_class_bnet;
		case 1:  return packet_class_file;
		case 2:  return packet_class_w3route;
		default: return packet_class_d2game; // size from packet->len, set below
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 9) return 0;
	size_t body_len = size - 9;
	const uint8_t *body = data;
	uint32_t off = rd_u32le(data + body_len);
	uint32_t len = rd_u32le(data + body_len + 4);
	uint8_t  ctl = data[body_len + 8];

	// heap-allocate so ASan poisons the redzone immediately after u.data[]:
	// a 1-byte over-read past data[MAX_PACKET_SIZE] then lands in the redzone.
	t_packet *p = (t_packet *)malloc(sizeof(*p));
	if (!p) return 0;
	std::memset(p, 0, sizeof(*p));
	p->ref = 1;
	p->pclass = pick_class(ctl);

	// n = bytes actually "received" (== declared size on the wire), capped.
	size_t n = body_len < MAX_PACKET_SIZE ? body_len : (size_t)MAX_PACKET_SIZE;
	std::memcpy(p->u.data, body, n);

	if (p->pclass == packet_class_d2game) {
		// size comes from packet->len for this class; model a framed read.
		p->len = (unsigned int)n;
	} else {
		// header classes read the 16-bit size field out of the wire bytes.
		// enforce received == declared (<= n): rewrite the size field so we never
		// claim more bytes than were received (that is what the framer guarantees).
		unsigned int declared = packet_get_size(p);           // reads data[0..1], capped
		if (declared > n) declared = (unsigned int)n;
		if (declared > 0) packet_set_size(p, declared);       // writes header size field
	}

	// --- exercise the accessors -------------------------------------------
	(void)packet_get_class(p);
	(void)packet_get_class_str(p);
	(void)packet_get_header_size(p);
	unsigned int psize = packet_get_size(p);
	(void)packet_get_type(p);
	(void)packet_get_type_str(p, packet_dir_from_client);

	if (ctl & 0x40) {
		// string reader: NUL-scan bounded by declared size + maxlen.
		const char *s = packet_get_str_const(p, off, len);
		if (s) {
			// consume it the way a handler would (bounded copy), forcing any
			// over-read the reader failed to prevent to be observed.
			volatile char sink = 0;
			for (const char *q = s; *q && (size_t)(q - s) <= (size_t)len; q++)
				sink = *q;
			(void)sink;
		}
	} else {
		// data reader: offset+len window. read exactly what it says is valid,
		// so a wrapped/oversized window (the offset+len overflow) faults here.
		const void *d = packet_get_data_const(p, off, len);
		if (d && len > 0 && len <= MAX_PACKET_SIZE) {
			volatile uint8_t sink = 0;
			const uint8_t *b = (const uint8_t *)d;
			for (uint32_t i = 0; i < len; i++) sink ^= b[i];
			(void)sink;
		}
	}

	// raw readers (offset-only bounds).
	const void *r = packet_get_raw_data_const(p, off);
	if (r && off < psize) { volatile uint8_t s = *(const uint8_t *)r; (void)s; }

	free(p);
	return 0;
}
