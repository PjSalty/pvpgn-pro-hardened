// regression_file_send.cc - guards the reject path of file_send
// (src/bnetd/file.cpp).
//
// file_send creates its reply packet first and then looks the file up. When
// the file does not exist, or the name contains a path separator, the lookup
// throws and the handler returned without releasing the packet: about 3 KB
// leaked for every such request, and a file connection needs no login.
//
// This runs the real file_send. The connection, prefs and i18n lookups are
// stubbed, and xmalloc/xfree/xstrdup are defined here instead of linking
// common/xalloc.cpp, so the test sees an allocation that is never given back.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "common/setup_before.h"
#include "common/packet.h"
#include "common/xalloc.h"
#include "bnetd/connection.h"
#include "bnetd/prefs.h"
#include "bnetd/i18n.h"
#include "bnetd/file.h"
#include "common/setup_after.h"

using namespace pvpgn;
using namespace pvpgn::bnetd;

static long live = 0; // blocks handed out and not freed yet
static int queued = 0; // packets file_send put on the connection

namespace pvpgn
{
	void *xmalloc_real(std::size_t size, const char *, unsigned) {
		live++;
		return std::malloc(size ? size : 1);
	}

	char *xstrdup_real(const char *str, const char *, unsigned) {
		live++;
		return std::strcpy((char *)std::malloc(std::strlen(str) + 1), str);
	}

	void xfree_real(void *ptr, const char *, unsigned) {
		live--;
		std::free(ptr);
	}

	namespace bnetd
	{
		// a file directory that does not exist, so no name can be found in it
		char const * prefs_get_filedir(void) { return "regression-file-send-no-such-dir"; }
		int conn_get_socket(t_connection const *) { return 1; }
		int conn_push_outqueue(t_connection *, t_packet *) { queued++; return 0; }
		t_gamelang conn_get_gamelang_localized(t_connection *) { return 0; }
		t_gamelang gamelang_get_by_country(const char *) { return 0; }
		t_language language_find_by_tag(t_gamelang, bool &found) { found = false; return t_language(); }
		std::string i18n_filename(const char *, t_tag) { return std::string(); }
	}
}

static int failures = 0;

static void check(const char *what, bool ok) {
	std::printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
	std::fflush(stdout); // a leak report at exit must not swallow this
	if (!ok)
		failures++;
}

// A request file_send has to refuse: it must return -1, queue nothing and
// leave nothing allocated.
static bool refused_cleanly(const char *rawname) {
	static char conn;
	long before = live;
	queued = 0;
	int ret = file_send(reinterpret_cast<t_connection *>(&conn), rawname, 0, 0, 0, 1);
	long left = live - before;

	if (left)
		std::printf("        %ld allocation(s) left behind for \"%s\"\n", left, rawname);
	return ret == -1 && queued == 0 && left == 0;
}

int main() {
	check("a file that does not exist is refused without a leak", refused_cleanly("no-such-file.bni"));
	check("a name with a path separator is refused without a leak", refused_cleanly("../bnetd.conf") && refused_cleanly("a\\b"));

	if (failures) {
		std::printf("FILE SEND REGRESSION: FAIL (%d)\n", failures);
		std::fflush(stdout);
		return 1;
	}
	std::printf("FILE SEND REGRESSION: PASS\n");
	return 0;
}
