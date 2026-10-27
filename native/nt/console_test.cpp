#include "console.h"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <pty.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

using raven::ConsoleKey;

static void check(bool value, const std::string &message)
{
	if (!value)
		throw std::runtime_error(message);
}

static std::vector<ConsoleKey> presses(std::string_view bytes, bool flush = true, bool virtual_terminal = false, size_t *used = nullptr)
{
	std::vector<ConsoleKey> keys;
	const size_t taken = raven::decode_terminal_keys(bytes, flush, virtual_terminal, keys);
	if (used)
		*used = taken;
	std::vector<ConsoleKey> down;
	for (size_t index = 0; index < keys.size(); ++index) {
		check(keys[index].down == !(index & 1), "a key press is not followed by its release");
		if (keys[index].down)
			down.push_back(keys[index]);
	}
	return down;
}

static void decoding()
{
	auto keys = presses("aZ1!;\r\t\x7f");
	check(keys.size() == 8, "typed characters were not one key each");
	check(keys[0].key == 'A' && keys[0].scan == 0x1e && keys[0].character == u'a' && !keys[0].controls, "a decodes wrongly");
	check(keys[1].key == 'Z' && keys[1].character == u'Z' && keys[1].controls == 0x10, "Z lacks Shift");
	check(keys[2].key == '1' && keys[2].scan == 0x02 && keys[3].key == '1' && keys[3].character == u'!' && keys[3].controls == 0x10,
		"digits and their shifted symbols decode wrongly");
	check(keys[4].key == 0xba && keys[4].scan == 0x27, "punctuation decodes wrongly");
	check(keys[5].key == 0x0d && keys[5].character == u'\r' && keys[6].key == 0x09 && keys[7].key == 0x08 && keys[7].character == 8,
		"Enter, Tab or Backspace decodes wrongly");

	keys = presses("\x03\x1a");
	check(keys[0].key == 'C' && keys[0].character == 3 && keys[0].controls == 0x8 && keys[1].key == 'Z', "Ctrl with a letter decodes wrongly");

	keys = presses("\x1b[A\x1b[1;5C\x1b[3~\x1b[15~\x1bOP\x1b[Z\x1b[1;2H");
	check(keys.size() == 7, "escape sequences were not one key each");
	check(keys[0].key == 0x26 && keys[0].scan == 0x48 && keys[0].controls == 0x100 && !keys[0].character, "Up decodes wrongly");
	check(keys[1].key == 0x27 && keys[1].controls == (0x100 | 0x8), "Ctrl+Right decodes wrongly");
	check(keys[2].key == 0x2e && keys[3].key == 0x74 && keys[3].scan == 0x3f, "Delete or F5 decodes wrongly");
	check(keys[4].key == 0x70 && keys[5].key == 0x09 && keys[5].controls == 0x10, "F1 or Shift+Tab decodes wrongly");
	check(keys[6].key == 0x24 && keys[6].controls == (0x100 | 0x10), "Shift+Home decodes wrongly");

	keys = presses("\x1b" "x");
	check(keys.size() == 1 && keys[0].key == 'X' && keys[0].controls == 0x2, "Alt+x decodes wrongly");

	size_t used = 0;
	keys = presses("a\x1b", false, false, &used);
	check(keys.size() == 1 && used == 1, "a lone ESC was taken before more could arrive");
	keys = presses("\x1b[1;", false, false, &used);
	check(keys.empty() && used == 0, "a cut-off sequence was taken");
	keys = presses("\x1b", true);
	check(keys.size() == 1 && keys[0].key == 0x1b && keys[0].character == 0x1b, "a settled ESC is not the Escape key");
	keys = presses("\xc3", false, false, &used);
	check(keys.empty() && used == 0, "a cut-off UTF-8 character was taken");

	keys = presses("\xc3\xa9\xf0\x9f\x99\x82");
	check(keys.size() == 3 && keys[0].character == 0xe9 && !keys[0].key && keys[1].character == 0xd83d && keys[2].character == 0xde42,
		"non-ASCII characters decode wrongly");

	keys = presses("\x1b[A", true, true);
	check(keys.size() == 3 && keys[0].key == 0x1b && keys[1].character == u'[' && keys[2].character == u'A',
		"virtual terminal input interpreted an escape sequence");

	keys = presses("\x1b[200~p\x1b[201~\x1b[I");
	check(keys.size() == 1 && keys[0].character == u'p', "sequences no key sends were not dropped");
}

static void tracking()
{
	raven::CursorTracker tracker;
	tracker.resize(10, 5);
	tracker.place(0, 0);
	const auto at = [&](int column, int row, const char *what) {
		check(tracker.column() == column && tracker.row() == row, std::string(what) + ": the cursor is at " + std::to_string(tracker.column()) +
			"," + std::to_string(tracker.row()) + " rather than " + std::to_string(column) + "," + std::to_string(row));
	};
	tracker.feed("abc");
	at(3, 0, "text");
	tracker.feed("\r0123456789");
	at(9, 0, "a full row holds the cursor in the last column");
	tracker.feed("X");
	at(1, 1, "the next character wraps");
	tracker.feed("\n");
	at(0, 2, "a line feed");
	tracker.feed("\x1b[2;4H");
	at(3, 1, "an absolute move");
	tracker.feed("\x1b[A\x1b[9B");
	at(3, 4, "relative moves stop at the edges");
	tracker.feed("\x1b" "7\x1b[H\x1b" "8");
	at(3, 4, "save and restore");
	tracker.feed("\n\n");
	at(0, 4, "the bottom row scrolls");
	tracker.feed("\x1b[");
	tracker.feed("3G");
	at(2, 4, "a sequence in two pieces");
	tracker.feed("\xf0\x9f");
	tracker.feed("\x99\x82");
	at(4, 4, "an emoji in two pieces takes two cells");
	tracker.feed("\xc3\xa9" "e" "\xcc\x81");
	at(6, 4, "accented and combining characters take one cell");
	tracker.feed("\x1b]0;title\a\x1b[?25l\x1b[1;31m");
	at(6, 4, "titles, modes and colours");
	tracker.feed("\t\b");
	at(7, 4, "a tab to column 8 and a backspace");
	tracker.feed("\x1b[2;3r");
	at(0, 0, "a scrolling region homes the cursor");
	tracker.feed("ab\n", false);
	at(2, 1, "a line feed without the carriage return");
	check(raven::character_cells(U'a') == 1 && raven::character_cells(0x4e2d) == 2 && raven::character_cells(0x301) == 0,
		"character widths differ");
}

static void attributes()
{
	check(raven::attribute_sequence(7) == "\x1b[0m", "the default attribute is not the terminal's own colours");
	check(raven::attribute_sequence(0x0c) == "\x1b[0;91m", "bright red differs");
	check(raven::attribute_sequence(0x1e) == "\x1b[0;93;44m", "yellow on blue differs");
	check(raven::attribute_sequence(0x70 | 0x4000 | 0x8000) == "\x1b[0;30;47;7;4m", "reverse video or underscore differs");
	check(raven::attribute_sequence(0x87) == "\x1b[0;100m", "a bright black background differs");
}

// The terminal end of a pseudo-terminal: it shows what the program writes, answers the cursor query and types when told to.
class Terminal {
public:
	explicit Terminal(int master) : master(master) {}
	// Reads until `text` has been written, answering cursor queries meanwhile.
	void expect(std::string_view text)
	{
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
		while (seen.find(text, scanned) == seen.npos) {
			const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
			pollfd entry{master, POLLIN, 0};
			check(left > 0 && ::poll(&entry, 1, int(left)) > 0, "timed out waiting for \"" + printable(text) + "\"; the program wrote \"" +
				printable(seen.substr(scanned)) + "\"");
			char chunk[4096];
			const auto count = ::read(master, chunk, sizeof chunk);
			check(count > 0, "the program closed the terminal before writing \"" + printable(text) + "\": \"" + printable(seen.substr(scanned)) +
				"\"");
			seen.append(chunk, size_t(count));
			for (size_t at; (at = seen.find("\x1b[6n", answered)) != seen.npos; answered = at + 4) {
				type("\x1b[5;10R");
				++asked;
			}
		}
		scanned = seen.find(text, scanned) + text.size();
	}
	size_t queries() const { return asked; }
	void type(std::string_view bytes) { check(::write(master, bytes.data(), bytes.size()) == ssize_t(bytes.size()), "typing failed"); }
	void drain()
	{
		char chunk[4096];
		for (pollfd entry{master, POLLIN, 0}; ::poll(&entry, 1, 200) > 0 && ::read(master, chunk, sizeof chunk) > 0;)
			;
	}

private:
	static std::string printable(std::string_view text)
	{
		std::string shown;
		for (const char character : text)
			if (uint8_t(character) < 0x20) {
				char escaped[8];
				std::snprintf(escaped, sizeof escaped, "\\x%02x", uint8_t(character));
				shown += escaped;
			} else
				shown += character;
		return shown;
	}
	int master;
	std::string seen;
	size_t scanned = 0, answered = 0, asked = 0;
};

static void terminal(const char *raven, const char *client)
{
	int master = -1;
	winsize window{};
	window.ws_col = 100;
	window.ws_row = 30;
	const pid_t child = ::forkpty(&master, nullptr, nullptr, &window);
	check(child >= 0, "no pseudo-terminal");
	if (!child) {
		::execl(raven, raven, "--run-process", "--execution=native", "--timeout-ms=60000", "--stdio=inherit", client, "--", "--exact", nullptr);
		::_exit(127);
	}
	Terminal screen(master);
	try {
		screen.expect("\x1b[0;91mcaf\xc3\xa9 \xf0\x9f\x99\x82\r\n\x1b[0m");
		screen.expect("READY-LINE: type hello and press Enter\r\n");
		screen.type("hello\r");
		// Relative moves from the followed cursor at row 7: up to row 5, a write at the top left, a scroll, and back down.
		screen.expect("\x1b[2A\x1b[5G");
		screen.expect("\x1b" "7\x1b[5A\x1b[1GXY\x1b" "8");
		screen.expect("\x1b" "7\x1b[1;30r\x1b[1S\x1b[r\x1b" "8");
		screen.expect("\x1b[2B\x1b[1G");
		screen.expect("READY-KEYS: press Up, x, Ctrl+Right, Esc\r\n");
		screen.type("\x1b[Ax\x1b[1;5C");
		::usleep(100000);
		screen.type("\x1b");
		screen.expect("READY-CHAR: type q\r\n");
		screen.type("q");
		screen.expect("via-conout\r\n");
		screen.expect("READY-SIZE: resize the window\r\n");
		winsize larger{};
		larger.ws_col = 120;
		larger.ws_row = 40;
		check(!::ioctl(master, TIOCSWINSZ, &larger), "the window could not be resized");
		screen.expect("READY-FILE: type abc and press Enter\r\n");
		screen.type("abc\r");
		screen.expect("\x1b]0;Raven test\a");
		screen.expect("READY-CTRL: press Ctrl+C\r\n");
		screen.type("\x03");
		screen.expect("HANDLED\r\n");
		screen.expect("READY-EXIT: press Ctrl+C to end the program\r\n");
		screen.type("\x03");
		screen.expect("DECLINED\r\n");
	} catch (...) {
		::kill(child, SIGKILL);
		::waitpid(child, nullptr, 0);
		throw;
	}
	screen.drain();
	int status = 0;
	check(::waitpid(child, &status, 0) == child, "the program was not reaped");
	check(WIFEXITED(status), "the program was killed by signal " + std::to_string(WIFSIGNALED(status) ? WTERMSIG(status) : 0));
	check(WEXITSTATUS(status) == 0x3a, "the unhandled Ctrl+C ended the program with " + std::to_string(WEXITSTATUS(status)) +
		" rather than STATUS_CONTROL_C_EXIT");
	check(screen.queries() == 1, "the terminal was asked for the cursor " + std::to_string(screen.queries()) +
		" times rather than once; the console did not follow it");
	termios settings{};
	check(!::tcgetattr(master, &settings) && (settings.c_lflag & ICANON) && (settings.c_lflag & ECHO) && (settings.c_iflag & ICRNL),
		"the terminal was not put back into line mode");
	::close(master);
}

int main(int argc, char **argv)
{
	try {
		decoding();
		attributes();
		tracking();
		if (argc == 3)
			terminal(argv[1], argv[2]);
		std::cout << "Console key decoding, attributes, cursor tracking" << (argc == 3 ? " and the terminal console" : "") << " passed\n";
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
