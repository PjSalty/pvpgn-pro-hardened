// regression_handle_file.cc - guards the raw-mode filename read of
// handle_file_packet (src/bnetd/handle_file.cpp).
//
// After CLIENT_FILE_REQ2 a file connection is in raw mode: the handler reads
// the requested filename straight off the socket into a MAX_FILENAME_STR
// buffer and hands it to file_send(). The read could fill the whole buffer,
// leaving no terminating NUL, and its result was ignored, so a read that failed
// still called file_send(). All of this is reachable before login.
//
// This runs the real handler. Only the connection and file_send() are stubbed:
// the socket is one end of a socketpair the test writes to (non-blocking, like
// the server's sockets), and file_send() records what it is handed.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/field_sizes.h"
#include "bnetd/connection.h"
#include "bnetd/file.h"
#include "bnetd/handle_file.h"
#include "common/setup_after.h"

using namespace pvpgn;
using namespace pvpgn::bnetd;

static int sock = -1;
static int sends;
static bool terminated;
static std::string sent;

namespace pvpgn
{
	namespace bnetd
	{
		t_conn_state conn_get_state(t_connection const *) { return conn_state_pending_raw; }
		void conn_set_state(t_connection *, t_conn_state) {}
		int conn_get_socket(t_connection const *) { return sock; }
		int conn_push_outqueue(t_connection *, t_packet *) { return 0; }

		int file_send(t_connection *, char const * rawname, unsigned int, unsigned int, unsigned int, int)
		{
			sends++;
			// the handler's buffer is MAX_FILENAME_STR bytes, look no further
			terminated = std::memchr(rawname, '\0', MAX_FILENAME_STR) != NULL;
			sent = terminated ? rawname : "";
			return 0;
		}
	}
}

static int failures = 0;

static void check(const char *what, bool ok) {
	std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		failures++;
}

// Puts `data` on the socket, optionally closes the sending end, and runs the
// handler on a raw-mode CLIENT_FILE_REQ3. Returns what the handler returned.
static int request(const std::string &data, bool close_sender) {
	static char conn;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0 || fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0) {
		std::perror("socketpair");
		std::exit(2);
	}
	if (!data.empty() && write(sv[1], data.data(), data.size()) != (ssize_t)data.size()) {
		std::perror("write");
		std::exit(2);
	}
	if (close_sender)
		close(sv[1]);

	t_packet *packet = packet_create(packet_class_raw);
	packet_set_size(packet, sizeof(t_client_file_req3));
	sock = sv[0];
	sends = 0;
	terminated = false;
	sent.clear();
	int ret = handle_file_packet(reinterpret_cast<t_connection *>(&conn), packet);
	packet_del_ref(packet);

	close(sv[0]);
	if (!close_sender)
		close(sv[1]);
	return ret;
}

int main() {
	int ret;

	// valid requests: the name must reach file_send() unchanged.
	ret = request(std::string("tos_USA.txt\0", 12), false);
	check("a terminated filename is passed on unchanged", ret == 0 && sends == 1 && sent == "tos_USA.txt");

	ret = request("icons.bni", false);
	check("a filename sent without its NUL is terminated", ret == 0 && sends == 1 && terminated && sent == "icons.bni");

	const std::string longest(MAX_FILENAME_STR - 1, 'a');
	ret = request(longest + '\0', false);
	check("the longest filename is passed on unchanged", ret == 0 && sends == 1 && terminated && sent == longest);

	// more than the buffer holds and no NUL anywhere: the old read filled the
	// buffer and file_send() ran off its end looking for a terminator.
	ret = request(std::string(2 * MAX_FILENAME_STR, 'A'), false);
	check("an overlong filename is still a terminated string", sends == 1 && terminated && sent == std::string(MAX_FILENAME_STR - 1, 'A'));

	// nothing to read: no filename, so no file_send().
	ret = request("", true);
	check("a closed socket is rejected without calling file_send", ret == -1 && sends == 0);

	ret = request("", false);
	check("a read error is rejected without calling file_send", ret == -1 && sends == 0);

	if (failures) {
		std::printf("HANDLE FILE REGRESSION: FAIL (%d)\n", failures);
		return 1;
	}
	std::printf("HANDLE FILE REGRESSION: PASS\n");
	return 0;
}
