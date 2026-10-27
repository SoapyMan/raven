#include "console.h"

#include "text.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace raven {

namespace {

constexpr uint32_t shift_pressed = 0x10, left_alt_pressed = 0x2, left_ctrl_pressed = 0x8, enhanced_key = 0x100;

// Scan codes of the first IBM PC keyboard for the letters a to z.
constexpr uint8_t letter_scans[26] = {0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
	0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c};

struct Punctuation {
	char plain, shifted;
	uint16_t key, scan;
};
// The punctuation keys of the US layout: what each gives alone and with Shift, its virtual key and its scan code.
constexpr Punctuation punctuation[] = {{';', ':', 0xba, 0x27}, {'=', '+', 0xbb, 0x0d}, {',', '<', 0xbc, 0x33}, {'-', '_', 0xbd, 0x0c},
	{'.', '>', 0xbe, 0x34}, {'/', '?', 0xbf, 0x35}, {'`', '~', 0xc0, 0x29}, {'[', '{', 0xdb, 0x1a}, {'\\', '|', 0xdc, 0x2b},
	{']', '}', 0xdd, 0x1b}, {'\'', '"', 0xde, 0x28}};
constexpr char shifted_digits[] = ")!@#$%^&*(";

ConsoleKey named(uint16_t key, uint16_t scan, char16_t character = 0, uint32_t controls = 0)
{
	ConsoleKey made;
	made.key = key;
	made.scan = scan;
	made.character = character;
	made.controls = controls;
	return made;
}

uint16_t digit_scan(char digit) { return digit == '0' ? 0x0b : uint16_t(0x02 + (digit - '1')); }

// The key that types a character on a US keyboard; characters no key types arrive with no key, as pasted text does.
ConsoleKey typed(char16_t character)
{
	if (character >= u'a' && character <= u'z')
		return named(uint16_t(u'A' + (character - u'a')), letter_scans[character - u'a'], character);
	if (character >= u'A' && character <= u'Z')
		return named(character, letter_scans[character - u'A'], character, shift_pressed);
	if (character >= u'0' && character <= u'9')
		return named(character, digit_scan(char(character)), character);
	if (character == u' ')
		return named(0x20, 0x39, character);
	for (size_t digit = 0; digit < 10; ++digit)
		if (character == char16_t(shifted_digits[digit]))
			return named(uint16_t(u'0' + digit), digit_scan(char('0' + digit)), character, shift_pressed);
	for (const auto &entry : punctuation) {
		if (character == char16_t(entry.plain))
			return named(entry.key, entry.scan, character);
		if (character == char16_t(entry.shifted))
			return named(entry.key, entry.scan, character, shift_pressed);
	}
	return named(0, 0, character);
}

// A control character: Enter, Tab, Backspace, or Ctrl held with a letter or symbol.
ConsoleKey control(uint8_t byte)
{
	switch (byte) {
	case 0x0d: return named(0x0d, 0x1c, u'\r');
	case 0x0a: return named(0x0d, 0x1c, u'\n', left_ctrl_pressed);
	case 0x09: return named(0x09, 0x0f, u'\t');
	case 0x08:
	case 0x7f: return named(0x08, 0x0e, 0x08);
	case 0x1b: return named(0x1b, 0x01, 0x1b);
	case 0x00: return named(0x20, 0x39, 0, left_ctrl_pressed);
	case 0x1c: return named(0xdc, 0x2b, 0x1c, left_ctrl_pressed);
	case 0x1d: return named(0xdd, 0x1b, 0x1d, left_ctrl_pressed);
	case 0x1e: return named(u'6', 0x07, 0x1e, left_ctrl_pressed | shift_pressed);
	case 0x1f: return named(0xbd, 0x0c, 0x1f, left_ctrl_pressed | shift_pressed);
	default: return named(uint16_t(u'A' + byte - 1), letter_scans[byte - 1], byte, left_ctrl_pressed);
	}
}

// The Shift, Alt and Ctrl a terminal encodes as 1 plus a bit mask in the second parameter of a sequence.
uint32_t modifiers(const std::vector<int> &parameters)
{
	if (parameters.size() < 2 || parameters[1] < 2)
		return 0;
	const int mask = parameters[1] - 1;
	return (mask & 1 ? shift_pressed : 0) | (mask & 2 ? left_alt_pressed : 0) | (mask & 4 ? left_ctrl_pressed : 0);
}

ConsoleKey function_key(int number)
{
	const uint16_t scan = number <= 10 ? uint16_t(0x3a + number) : number == 11 ? 0x57 : 0x58;
	return named(uint16_t(0x6f + number), scan);
}

// The editing and function keys sent as ESC [ number ~.
std::optional<ConsoleKey> tilde_key(int number)
{
	switch (number) {
	case 1:
	case 7: return named(0x24, 0x47, 0, enhanced_key);
	case 2: return named(0x2d, 0x52, 0, enhanced_key);
	case 3: return named(0x2e, 0x53, 0, enhanced_key);
	case 4:
	case 8: return named(0x23, 0x4f, 0, enhanced_key);
	case 5: return named(0x21, 0x49, 0, enhanced_key);
	case 6: return named(0x22, 0x51, 0, enhanced_key);
	case 11: case 12: case 13: case 14: case 15: return function_key(number - 10);
	case 17: case 18: case 19: case 20: case 21: return function_key(number - 11);
	case 23: case 24: return function_key(number - 12);
	default: return std::nullopt;
	}
}

// The cursor keys, Home and End, and F1 to F4, by the final character both CSI and SS3 forms end in.
std::optional<ConsoleKey> final_key(char final)
{
	switch (final) {
	case 'A': return named(0x26, 0x48, 0, enhanced_key);
	case 'B': return named(0x28, 0x50, 0, enhanced_key);
	case 'C': return named(0x27, 0x4d, 0, enhanced_key);
	case 'D': return named(0x25, 0x4b, 0, enhanced_key);
	case 'H': return named(0x24, 0x47, 0, enhanced_key);
	case 'F': return named(0x23, 0x4f, 0, enhanced_key);
	case 'P': case 'Q': case 'R': case 'S': return function_key(final - 'P' + 1);
	case 'M': return named(0x0d, 0x1c, u'\r', enhanced_key);
	default: return std::nullopt;
	}
}

// Decodes one UTF-8 character; 0 when it is cut off at the end, and U+FFFD for one byte that starts no character.
size_t utf8_character(std::string_view bytes, size_t at, char32_t &character)
{
	const auto lead = uint8_t(bytes[at]);
	const size_t length = lead < 0x80 ? 1 : (lead & 0xe0) == 0xc0 ? 2 : (lead & 0xf0) == 0xe0 ? 3 : (lead & 0xf8) == 0xf0 ? 4 : 0;
	if (!length) {
		character = 0xfffd;
		return 1;
	}
	if (at + length > bytes.size())
		return 0;
	character = length == 1 ? lead : lead & (0x7f >> length);
	for (size_t index = 1; index < length; ++index) {
		const auto next = uint8_t(bytes[at + index]);
		if ((next & 0xc0) != 0x80) {
			character = 0xfffd;
			return 1;
		}
		character = (character << 6) | (next & 0x3f);
	}
	return length;
}

void press(std::vector<ConsoleKey> &keys, ConsoleKey key)
{
	keys.push_back(key);
	key.down = false;
	keys.push_back(key);
}

// One character that is not part of an escape sequence; 0 when it is cut off at the end.
size_t decode_character(std::string_view bytes, size_t at, uint32_t extra, std::vector<ConsoleKey> &keys)
{
	const auto byte = uint8_t(bytes[at]);
	if (byte < 0x20 || byte == 0x7f) {
		auto key = control(byte);
		key.controls |= extra;
		press(keys, key);
		return 1;
	}
	char32_t character;
	const size_t used = utf8_character(bytes, at, character);
	if (!used)
		return 0;
	if (character > 0xffff) {
		// A character beyond the Basic Multilingual Plane arrives as its two surrogates.
		character -= 0x10000;
		for (const char16_t half : {char16_t(0xd800 + (character >> 10)), char16_t(0xdc00 + (character & 0x3ff))}) {
			auto key = named(0, 0, half, extra);
			press(keys, key);
		}
		return used;
	}
	auto key = typed(char16_t(character));
	key.controls |= extra;
	press(keys, key);
	return used;
}

std::string utf8_of(char16_t character) { return to_utf8(std::u16string_view(&character, 1)); }

bool write_all(int descriptor, std::string_view bytes)
{
	while (!bytes.empty()) {
		const auto written = ::write(descriptor, bytes.data(), bytes.size());
		if (written < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				pollfd entry{descriptor, POLLOUT, 0};
				::poll(&entry, 1, 100);
				continue;
			}
			return false;
		}
		bytes.remove_prefix(size_t(written));
	}
	return true;
}

}

size_t decode_terminal_keys(std::string_view bytes, bool flush, bool virtual_terminal, std::vector<ConsoleKey> &keys)
{
	size_t at = 0;
	while (at < bytes.size()) {
		if (bytes[at] != '\x1b' || virtual_terminal) {
			const size_t used = decode_character(bytes, at, 0, keys);
			if (!used) {
				if (!flush)
					break;
				press(keys, named(0, 0, 0xfffd));
				at = bytes.size();
				break;
			}
			at += used;
			continue;
		}
		if (at + 1 >= bytes.size()) {
			if (!flush)
				break;
			press(keys, control(0x1b));
			++at;
			continue;
		}
		const char kind = bytes[at + 1];
		if (kind == '[') {
			size_t end = at + 2;
			while (end < bytes.size() && (uint8_t(bytes[end]) < 0x40 || uint8_t(bytes[end]) > 0x7e))
				++end;
			if (end >= bytes.size()) {
				if (!flush)
					break;
				// A sequence that never finished: the Escape key, then what followed it as typed.
				press(keys, control(0x1b));
				++at;
				continue;
			}
			std::vector<int> parameters{0};
			for (size_t index = at + 2; index < end; ++index) {
				if (bytes[index] == ';')
					parameters.push_back(0);
				else if (bytes[index] >= '0' && bytes[index] <= '9')
					parameters.back() = parameters.back() * 10 + (bytes[index] - '0');
			}
			const char final = bytes[end];
			std::optional<ConsoleKey> key;
			if (final == '~')
				key = tilde_key(parameters[0]);
			else if (final == 'Z')
				key = named(0x09, 0x0f, u'\t', shift_pressed);
			else
				key = final_key(final);
			if (key) {
				key->controls |= modifiers(parameters);
				press(keys, *key);
			}
			// Sequences no key sends (focus reports, pasted-text brackets, mouse reports) are dropped.
			at = end + 1;
			continue;
		}
		if (kind == 'O') {
			if (at + 2 >= bytes.size()) {
				if (!flush)
					break;
				press(keys, control(0x1b));
				++at;
				continue;
			}
			if (const auto key = final_key(bytes[at + 2]))
				press(keys, *key);
			at += 3;
			continue;
		}
		// ESC before a character is that character typed with Alt held.
		const size_t used = decode_character(bytes, at + 1, left_alt_pressed, keys);
		if (!used) {
			if (!flush)
				break;
			press(keys, control(0x1b));
			++at;
			continue;
		}
		at += 1 + used;
	}
	return at;
}

std::string attribute_sequence(uint16_t attribute)
{
	// Console colours are blue, green and red bits; ANSI colours number red, green and blue from the low bit.
	const auto ansi = [](uint16_t bits) { return (bits & 4 ? 1 : 0) | (bits & 2 ? 2 : 0) | (bits & 1 ? 4 : 0); };
	const uint16_t foreground = attribute & 0xf, background = (attribute >> 4) & 0xf;
	std::string sequence = "\x1b[0";
	if (foreground != 7)
		sequence += ';' + std::to_string((foreground & 8 ? 90 : 30) + ansi(foreground));
	if (background)
		sequence += ';' + std::to_string((background & 8 ? 100 : 40) + ansi(background));
	if (attribute & console_reverse_video)
		sequence += ";7";
	if (attribute & console_underscore)
		sequence += ";4";
	return sequence + 'm';
}

TerminalConsole &TerminalConsole::instance()
{
	static TerminalConsole console;
	return console;
}

TerminalConsole::~TerminalConsole()
{
	restore();
	if (original_descriptor >= 0)
		::close(original_descriptor);
}

void TerminalConsole::remember(int descriptor)
{
	if (original)
		return;
	termios settings{};
	if (::tcgetattr(descriptor, &settings))
		return;
	original = settings;
	original_descriptor = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
}

void TerminalConsole::restore()
{
	if (original && original_descriptor >= 0)
		::tcsetattr(original_descriptor, TCSADRAIN, &*original);
	if (original_descriptor >= 0) {
		if (colours != 7)
			write_all(original_descriptor, "\x1b[0m");
		if (!visible)
			write_all(original_descriptor, "\x1b[?25h");
	}
}

void TerminalConsole::restore_from_signal()
{
	if (original && original_descriptor >= 0) {
		::tcsetattr(original_descriptor, TCSANOW, &*original);
		[[maybe_unused]] const auto written = ::write(original_descriptor, "\x1b[0m\x1b[?25h", 10);
	}
}

uint32_t TerminalConsole::input_mode(int descriptor)
{
	termios settings{};
	if (::tcgetattr(descriptor, &settings))
		return extra_input | console_processed_input | console_line_input | console_echo_input;
	uint32_t mode = extra_input;
	if (settings.c_lflag & ISIG)
		mode |= console_processed_input;
	if (settings.c_lflag & ICANON) {
		mode |= console_line_input;
		if (settings.c_lflag & ECHO)
			mode |= console_echo_input;
	}
	return mode;
}

bool TerminalConsole::set_input_mode(int descriptor, uint32_t mode)
{
	if ((mode & ~console_input_modes) || ((mode & console_echo_input) && !(mode & console_line_input)))
		return false;
	termios settings{};
	if (::tcgetattr(descriptor, &settings))
		return false;
	remember(descriptor);
	const auto flag = [](tcflag_t &flags, tcflag_t bits, bool on) { flags = on ? flags | bits : flags & ~bits; };
	const bool line_input = mode & console_line_input;
	flag(settings.c_lflag, ICANON, line_input);
	flag(settings.c_lflag, ECHO | ECHOE | ECHOK, mode & console_echo_input);
	flag(settings.c_lflag, ISIG, mode & console_processed_input);
	// Enter is CR outside line mode; a line ends in the LF the terminal makes of it.
	flag(settings.c_iflag, ICRNL, line_input);
	if (!line_input) {
		settings.c_cc[VMIN] = 1;
		settings.c_cc[VTIME] = 0;
	}
	if (::tcsetattr(descriptor, TCSANOW, &settings))
		return false;
	extra_input = mode & ~(console_processed_input | console_line_input | console_echo_input);
	return true;
}

void TerminalConsole::set_output_mode(int descriptor, uint32_t mode)
{
	output = mode;
	termios settings{};
	if (::tcgetattr(descriptor, &settings))
		return;
	// A line feed returns the carriage too, unless a virtual terminal program asked that it not.
	const bool return_carriage = !((mode & console_disable_newline_auto_return) && (mode & console_virtual_terminal_processing));
	if (bool(settings.c_oflag & ONLCR) == return_carriage)
		return;
	remember(descriptor);
	settings.c_oflag = return_carriage ? settings.c_oflag | ONLCR : settings.c_oflag & ~tcflag_t(ONLCR);
	::tcsetattr(descriptor, TCSADRAIN, &settings);
}

bool TerminalConsole::write(int descriptor, std::string_view bytes) { return write_all(descriptor, bytes); }

void TerminalConsole::gather(int descriptor, bool raw)
{
	if (finished)
		return;
	termios settings{}, saved{};
	bool changed = false;
	const bool known = !::tcgetattr(descriptor, &settings);
	const bool canonical = known && (settings.c_lflag & ICANON) && !raw;
	if (raw && known && (settings.c_lflag & ICANON)) {
		// Keys are read as they are typed, not when the line is done, and are not echoed, as ReadConsoleInput sees them.
		saved = settings;
		settings.c_lflag &= ~tcflag_t(ICANON | ECHO);
		settings.c_cc[VMIN] = 0;
		settings.c_cc[VTIME] = 0;
		changed = !::tcsetattr(descriptor, TCSANOW, &settings);
	}
	for (;;) {
		pollfd entry{descriptor, POLLIN, 0};
		if (::poll(&entry, 1, 0) <= 0 || !(entry.revents & (POLLIN | POLLHUP | POLLERR)))
			break;
		char chunk[4096];
		const auto count = ::read(descriptor, chunk, sizeof chunk);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN)
				finished = true;
			break;
		}
		if (!count) {
			finished = true;
			break;
		}
		pending.append(chunk, size_t(count));
		if (canonical) {
			// The terminal hands over one line per read.
			line_complete = true;
			break;
		}
	}
	if (changed)
		::tcsetattr(descriptor, TCSANOW, &saved);
}

bool TerminalConsole::line_ready(int descriptor)
{
	if (!line.empty())
		return true;
	if (pending.find('\n') == pending.npos && !line_complete)
		gather(descriptor, false);
	const auto newline = pending.find('\n');
	if (newline == pending.npos && !line_complete && !finished)
		return false;
	const size_t length = newline == pending.npos ? pending.size() : newline + 1;
	line = from_utf8(std::string_view(pending).substr(0, length));
	pending.erase(0, length);
	line_complete = false;
	if (!line.empty() && line.back() == u'\n' && (line.size() < 2 || line[line.size() - 2] != u'\r'))
		line.insert(line.size() - 1, 1, u'\r');
	return !line.empty() || finished;
}

std::u16string TerminalConsole::take_line(size_t limit)
{
	auto taken = line.substr(0, limit);
	line.erase(0, taken.size());
	return taken;
}

bool TerminalConsole::keys_ready(int descriptor, bool settle)
{
	const size_t before = pending.size();
	gather(descriptor, true);
	// An escape sequence still cut off after a moment is not coming: its ESC was the Escape key.
	const auto now = std::chrono::steady_clock::now();
	if (pending.size() != before || pending.empty())
		partial_since = now;
	else if (now - partial_since >= std::chrono::milliseconds(30))
		settle = true;
	std::vector<ConsoleKey> decoded;
	const size_t used = decode_terminal_keys(pending, settle, extra_input & console_virtual_terminal_input, decoded);
	pending.erase(0, used);
	keys.insert(keys.end(), decoded.begin(), decoded.end());
	return !keys.empty();
}

std::vector<ConsoleKey> TerminalConsole::peek_keys(size_t limit, bool remove)
{
	const size_t count = std::min(limit, keys.size());
	std::vector<ConsoleKey> taken(keys.begin(), keys.begin() + long(count));
	if (remove)
		keys.erase(keys.begin(), keys.begin() + long(count));
	return taken;
}

std::u16string TerminalConsole::take_characters(size_t limit)
{
	std::u16string characters;
	while (!keys.empty() && characters.size() < limit) {
		const auto key = keys.front();
		keys.pop_front();
		if (key.down && key.character)
			characters += key.character;
	}
	return characters;
}

void TerminalConsole::flush_input(int descriptor)
{
	::tcflush(descriptor, TCIFLUSH);
	pending.clear();
	keys.clear();
	line.clear();
	line_complete = false;
}

TerminalConsole::Size TerminalConsole::size(int descriptor) const
{
	winsize window{};
	if (::ioctl(descriptor, TIOCGWINSZ, &window) || !window.ws_col || !window.ws_row)
		return {80, 25};
	return {int16_t(std::min<int>(window.ws_col, 0x7fff)), int16_t(std::min<int>(window.ws_row, 0x7fff))};
}

std::optional<std::pair<int16_t, int16_t>> TerminalConsole::cursor(int descriptor)
{
	if (!cursor_answers)
		return std::nullopt;
	// The answer comes back on the terminal's input: the controlling terminal, else the output descriptor when it reads as well.
	int input = ::open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	const bool opened = input >= 0;
	if (!opened)
		input = descriptor;
	termios settings{}, saved{};
	bool changed = false;
	if (!::tcgetattr(input, &settings)) {
		saved = settings;
		settings.c_lflag &= ~tcflag_t(ICANON | ECHO);
		settings.c_cc[VMIN] = 0;
		settings.c_cc[VTIME] = 0;
		changed = !::tcsetattr(input, TCSANOW, &settings);
	}
	std::optional<std::pair<int16_t, int16_t>> position;
	if (write_all(descriptor, "\x1b[6n")) {
		std::string answer;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
		while (!position) {
			const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
			pollfd entry{input, POLLIN, 0};
			if (left <= 0 || ::poll(&entry, 1, int(left)) <= 0)
				break;
			char chunk[256];
			const auto count = ::read(input, chunk, sizeof chunk);
			if (count <= 0) {
				if (count < 0 && errno == EINTR)
					continue;
				break;
			}
			answer.append(chunk, size_t(count));
			// ESC [ row ; column R, among whatever was typed ahead; the typing stays for the next read.
			for (size_t start = answer.find("\x1b["); start != answer.npos; start = answer.find("\x1b[", start + 1)) {
				int row = 0, column = 0;
				size_t at = start + 2;
				while (at < answer.size() && answer[at] >= '0' && answer[at] <= '9')
					row = row * 10 + (answer[at++] - '0');
				if (at >= answer.size() || answer[at++] != ';')
					continue;
				while (at < answer.size() && answer[at] >= '0' && answer[at] <= '9')
					column = column * 10 + (answer[at++] - '0');
				if (at >= answer.size() || answer[at] != 'R' || !row || !column)
					continue;
				position = std::pair{int16_t(column - 1), int16_t(row - 1)};
				answer.erase(start, at + 1 - start);
				break;
			}
		}
		pending += answer;
	}
	if (changed)
		::tcsetattr(input, TCSANOW, &saved);
	if (opened)
		::close(input);
	if (!position)
		cursor_answers = false;
	return position;
}

bool TerminalConsole::move_cursor(int descriptor, int16_t column, int16_t row)
{
	return write_all(descriptor, "\x1b[" + std::to_string(row + 1) + ';' + std::to_string(column + 1) + 'H');
}

bool TerminalConsole::set_attribute(int descriptor, uint16_t attribute)
{
	colours = attribute;
	return write_all(descriptor, attribute_sequence(attribute));
}

bool TerminalConsole::set_cursor_info(int descriptor, uint32_t percent, bool show)
{
	if (percent < 1 || percent > 100)
		return false;
	cursor_percent = percent;
	visible = show;
	return write_all(descriptor, show ? "\x1b[?25h" : "\x1b[?25l");
}

bool TerminalConsole::fill_characters(int descriptor, char16_t character, uint32_t count, int16_t column, int16_t row)
{
	const auto window = size(descriptor);
	// Blanking the whole screen, as programs clear it, is one erase in the current colours.
	if (character == u' ' && !column && !row && count >= uint32_t(window.columns) * uint32_t(window.rows))
		return write_all(descriptor, "\x1b" "7\x1b[H\x1b[2J\x1b" "8");
	const uint32_t cells = std::min<uint32_t>(count, uint32_t(window.columns) * uint32_t(window.rows));
	std::string sequence = "\x1b" "7\x1b[" + std::to_string(row + 1) + ';' + std::to_string(column + 1) + 'H';
	const auto glyph = utf8_of(character);
	for (uint32_t index = 0; index < cells; ++index)
		sequence += glyph;
	return write_all(descriptor, sequence + "\x1b" "8");
}

bool TerminalConsole::set_title(int descriptor, std::u16string text)
{
	caption = std::move(text);
	if (descriptor < 0)
		return true;
	return write_all(descriptor, "\x1b]0;" + to_utf8(caption) + '\a');
}

}
