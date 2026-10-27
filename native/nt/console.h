#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <termios.h>
#include <utility>
#include <vector>

namespace raven {

// Console input modes (SetConsoleMode on an input handle).
inline constexpr uint32_t console_processed_input = 0x1, console_line_input = 0x2, console_echo_input = 0x4,
	console_virtual_terminal_input = 0x200, console_input_modes = 0x3ff;
// Console output modes (SetConsoleMode on an output handle).
inline constexpr uint32_t console_processed_output = 0x1, console_wrap_at_eol = 0x2, console_virtual_terminal_processing = 0x4,
	console_disable_newline_auto_return = 0x8, console_output_modes = 0x1f;
// Character attribute bits beyond the two colour nibbles.
inline constexpr uint16_t console_reverse_video = 0x4000, console_underscore = 0x8000;

// A key press or release, as a KEY_EVENT_RECORD carries it.
struct ConsoleKey {
	bool down = true;
	uint16_t repeat = 1, key = 0, scan = 0;
	char16_t character = 0;
	uint32_t controls = 0;
	bool operator==(const ConsoleKey &) const = default;
};

// Turns what a terminal sends into key presses, each followed by its release. Returns the bytes used: an escape sequence or UTF-8
// character cut off at the end stays for the next call unless `flush` says no more is coming, and then a lone ESC is the Escape key.
// With `virtual_terminal`, escape sequences are not interpreted: every character is a key of its own, as with
// ENABLE_VIRTUAL_TERMINAL_INPUT.
size_t decode_terminal_keys(std::string_view bytes, bool flush, bool virtual_terminal, std::vector<ConsoleKey> &keys);
// The SGR sequence that draws in a console character attribute; white on black is the terminal's own default colours.
std::string attribute_sequence(uint16_t attribute);

// The console: the host terminal behind the standard handles. A process has one, so its state lives here; the input modes live in the
// terminal itself, so every process sharing the terminal sees the same ones, as processes sharing a Windows console do.
class TerminalConsole {
public:
	static TerminalConsole &instance();
	~TerminalConsole();
	TerminalConsole(const TerminalConsole &) = delete;
	TerminalConsole &operator=(const TerminalConsole &) = delete;

	// The input mode the terminal is in now; bits the terminal has no setting for are as the program last set them.
	uint32_t input_mode(int descriptor);
	// Puts the terminal into an input mode; false for a combination Windows rejects (echo without line input).
	bool set_input_mode(int descriptor, uint32_t mode);
	uint32_t output_mode() const { return output; }
	void set_output_mode(int descriptor, uint32_t mode);

	bool write(int descriptor, std::string_view bytes);

	// Line mode: whether a whole line has arrived (or the input ended), reading what the terminal has without waiting.
	bool line_ready(int descriptor);
	// The line ReadConsole returns, ending in CR LF, up to `limit` characters; the rest is kept for the next read.
	std::u16string take_line(size_t limit);
	// Key events: whether any have arrived, reading what the terminal has without waiting. An escape sequence cut off at the end is
	// taken as typed keys once nothing has followed it for 30 ms, or at once with `settle`.
	bool keys_ready(int descriptor, bool settle);
	// True while bytes at the end wait for the rest of an escape sequence.
	bool partial() const { return !pending.empty(); }
	std::vector<ConsoleKey> peek_keys(size_t limit, bool remove);
	size_t key_count() const { return keys.size(); }
	// The characters of the typed keys that have one, for ReadConsole outside line mode.
	std::u16string take_characters(size_t limit);
	// True once the terminal reported the end of its input.
	bool ended() const { return finished; }
	void flush_input(int descriptor);

	struct Size {
		int16_t columns, rows;
	};
	Size size(int descriptor) const;
	// The cursor as the terminal reports it, zero-based; nullopt when the terminal does not answer.
	std::optional<std::pair<int16_t, int16_t>> cursor(int descriptor);
	bool move_cursor(int descriptor, int16_t column, int16_t row);
	uint16_t attribute() const { return colours; }
	bool set_attribute(int descriptor, uint16_t attribute);
	bool cursor_visible() const { return visible; }
	uint32_t cursor_size() const { return cursor_percent; }
	bool set_cursor_info(int descriptor, uint32_t percent, bool show);
	// Writes `count` copies of a character from a cell on, leaving the cursor where it was.
	bool fill_characters(int descriptor, char16_t character, uint32_t count, int16_t column, int16_t row);
	const std::u16string &title() const { return caption; }
	// Keeps the title and shows it in the terminal's window title; a negative descriptor only keeps it.
	bool set_title(int descriptor, std::u16string text);
	uint32_t input_code_page = 437, output_code_page = 437;

	// Puts the terminal back as it was before this process changed it.
	void restore();
	// The same from a signal handler, with async-signal-safe calls only.
	void restore_from_signal();

private:
	TerminalConsole() = default;
	void remember(int descriptor);
	// Reads what the terminal has now, without waiting; `raw` reads keys one by one even in line mode.
	void gather(int descriptor, bool raw);
	std::optional<termios> original;
	int original_descriptor = -1;
	uint32_t extra_input = 0x1f0;
	uint32_t output = console_processed_output | console_wrap_at_eol;
	// Bytes read from the terminal and not yet handed out, and the keys and line made from them.
	std::string pending;
	std::deque<ConsoleKey> keys;
	std::u16string line;
	bool line_complete = false, finished = false;
	// When the bytes still waiting for the rest of an escape sequence last grew.
	std::chrono::steady_clock::time_point partial_since;
	uint16_t colours = 7;
	bool visible = true;
	uint32_t cursor_percent = 25;
	std::u16string caption;
	bool cursor_answers = true;
};

}
