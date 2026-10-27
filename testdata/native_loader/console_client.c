#include <windows.h>

/* The console over a terminal. Each READY- line hands the turn to whoever is typing, the person or console_test, for what the next step
   reads. With --exact, as console_test runs it through a pseudo-terminal of 100 by 30 cells that answers the cursor position query
   with row 5, column 10, the window and cursor must be exactly those. A failed step says so and returns its own number. The program
   ends in the Ctrl+C that no handler takes, with STATUS_CONTROL_C_EXIT. */

static HANDLE input, output;
static volatile LONG handled, declined;

static DWORD length(const char *text)
{
	DWORD size = 0;
	while (text[size])
		++size;
	return size;
}

static void say(const char *text)
{
	DWORD written;
	WriteFile(output, text, length(text), &written, NULL);
}

/* Reports a failed step, for a person running the program by hand, and gives the step number to return. */
static int failed(int step)
{
	char text[] = "FAILED at step 00\n";
	text[15] = (char)('0' + step / 10);
	text[16] = (char)('0' + step % 10);
	say(text);
	return step;
}

/* Whether the command line holds the argument, anywhere after the program name. */
static BOOL argument(const WCHAR *wanted)
{
	const WCHAR *line = GetCommandLineW();
	for (; *line; ++line) {
		DWORD index = 0;
		while (wanted[index] && line[index] == wanted[index])
			++index;
		if (!wanted[index])
			return TRUE;
	}
	return FALSE;
}

static BOOL same(const WCHAR *left, const WCHAR *right, DWORD count)
{
	for (DWORD index = 0; index < count; ++index)
		if (left[index] != right[index])
			return FALSE;
	return TRUE;
}

static BOOL WINAPI takes(DWORD event)
{
	if (event == CTRL_C_EVENT)
		InterlockedExchange(&handled, 1);
	return TRUE;
}

static BOOL WINAPI declines(DWORD event)
{
	(void)event;
	InterlockedExchange(&declined, 1);
	say("DECLINED\n");
	return FALSE;
}

/* The next key press, skipping releases. */
static BOOL next_press(KEY_EVENT_RECORD *key)
{
	for (;;) {
		INPUT_RECORD record;
		DWORD count = 0;
		if (!ReadConsoleInputW(input, &record, 1, &count) || count != 1 || record.EventType != KEY_EVENT)
			return FALSE;
		if (record.Event.KeyEvent.bKeyDown) {
			*key = record.Event.KeyEvent;
			return TRUE;
		}
	}
}

int raven_entry(void)
{
	DWORD mode = 0, count = 0;
	input = GetStdHandle(STD_INPUT_HANDLE);
	output = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!GetConsoleMode(input, &mode) || (mode & 7) != 7)
		return failed(1);
	if (!GetConsoleMode(output, &mode) || mode != (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT))
		return failed(2);
	if (!SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) || !GetConsoleMode(output, &mode) || !(mode & 4))
		return failed(3);
	if (SetConsoleMode(input, ENABLE_ECHO_INPUT) || GetLastError() != ERROR_INVALID_PARAMETER)
		return failed(4);

	CONSOLE_SCREEN_BUFFER_INFO info;
	if (!GetConsoleScreenBufferInfo(output, &info) || info.wAttributes != 7 || info.srWindow.Right != info.dwSize.X - 1 ||
		info.srWindow.Bottom != info.dwSize.Y - 1 || info.dwCursorPosition.X >= info.dwSize.X || info.dwCursorPosition.Y >= info.dwSize.Y)
		return failed(5);
	if (argument(L"--exact") && (info.dwSize.X != 100 || info.dwSize.Y != 30 || info.dwCursorPosition.X != 9 || info.dwCursorPosition.Y != 4))
		return failed(5);
	if (GetConsoleScreenBufferInfo(input, &info) || GetLastError() != ERROR_INVALID_HANDLE)
		return failed(6);

	if (!SetConsoleTextAttribute(output, FOREGROUND_RED | FOREGROUND_INTENSITY))
		return failed(7);
	const WCHAR text[] = L"café \xd83d\xde42\n";
	if (!WriteConsoleW(output, text, 8, &count, NULL) || count != 8)
		return failed(8);
	SetConsoleTextAttribute(output, 7);

	WCHAR line[64];
	say("READY-LINE: type hello and press Enter\n");
	if (!ReadConsoleW(input, line, 64, &count, NULL) || count != 7 || !same(line, L"hello\r\n", 7))
		return failed(9);

	if (!SetConsoleMode(input, ENABLE_PROCESSED_INPUT) || !GetConsoleMode(input, &mode) || (mode & 7) != ENABLE_PROCESSED_INPUT)
		return failed(10);
	say("READY-KEYS: press Up, x, Ctrl+Right, Esc\n");
	KEY_EVENT_RECORD key;
	if (!next_press(&key) || key.wVirtualKeyCode != VK_UP || !(key.dwControlKeyState & ENHANCED_KEY) || key.uChar.UnicodeChar)
		return failed(11);
	if (!next_press(&key) || key.wVirtualKeyCode != 'X' || key.uChar.UnicodeChar != L'x' || key.wVirtualScanCode != 0x2d)
		return failed(12);
	if (!next_press(&key) || key.wVirtualKeyCode != VK_RIGHT || !(key.dwControlKeyState & LEFT_CTRL_PRESSED))
		return failed(13);
	if (!next_press(&key) || key.wVirtualKeyCode != VK_ESCAPE)
		return failed(14);
	say("READY-CHAR: type q\n");
	if (!ReadConsoleW(input, line, 64, &count, NULL) || count != 1 || line[0] != L'q')
		return failed(15);
	if (!FlushConsoleInputBuffer(input) || !GetNumberOfConsoleInputEvents(input, &count) || count)
		return failed(16);

	HANDLE screen = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (screen == INVALID_HANDLE_VALUE || !GetConsoleMode(screen, &mode) || !WriteFile(screen, "via-conout\n", 11, &count, NULL))
		return failed(17);
	CloseHandle(screen);

	if (!SetConsoleMode(input, 0x1f7))
		return failed(18);
	char bytes[16];
	say("READY-FILE: type abc and press Enter\n");
	if (!ReadFile(input, bytes, sizeof bytes, &count, NULL) || count != 5 || bytes[0] != 'a' || bytes[3] != '\r' || bytes[4] != '\n')
		return failed(19);

	WCHAR title[32];
	if (!SetConsoleTitleW(L"Raven test") || GetConsoleTitleW(title, 32) != 10 || !same(title, L"Raven test", 11))
		return failed(20);

	if (!SetConsoleCtrlHandler(takes, TRUE))
		return failed(21);
	say("READY-CTRL: press Ctrl+C\n");
	for (int wait = 0; wait < 6000 && !handled; ++wait)
		Sleep(10);
	if (!handled)
		return failed(22);
	say("HANDLED\n");

	if (!SetConsoleCtrlHandler(takes, FALSE) || SetConsoleCtrlHandler(takes, FALSE) || !SetConsoleCtrlHandler(declines, TRUE))
		return failed(23);
	say("READY-EXIT: press Ctrl+C to end the program\n");
	for (int wait = 0; wait < 6000; ++wait)
		Sleep(10);
	return failed(24);
}
