#include <windows.h>

/* The console over a terminal, driven by console_test through a pseudo-terminal of 100 by 30 cells. Each READY- line hands the turn to
   the test, which types what the next step reads; the test also answers the cursor position query with row 5, column 10. A failed step
   returns its own number. The program ends in the Ctrl+C that no handler takes, so the test expects STATUS_CONTROL_C_EXIT. */

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
		return 1;
	if (!GetConsoleMode(output, &mode) || mode != (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT))
		return 2;
	if (!SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) || !GetConsoleMode(output, &mode) || !(mode & 4))
		return 3;
	if (SetConsoleMode(input, ENABLE_ECHO_INPUT) || GetLastError() != ERROR_INVALID_PARAMETER)
		return 4;

	CONSOLE_SCREEN_BUFFER_INFO info;
	if (!GetConsoleScreenBufferInfo(output, &info) || info.dwSize.X != 100 || info.dwSize.Y != 30 || info.dwCursorPosition.X != 9 ||
		info.dwCursorPosition.Y != 4 || info.srWindow.Right != 99 || info.srWindow.Bottom != 29 || info.wAttributes != 7)
		return 5;
	if (GetConsoleScreenBufferInfo(input, &info) || GetLastError() != ERROR_INVALID_HANDLE)
		return 6;

	if (!SetConsoleTextAttribute(output, FOREGROUND_RED | FOREGROUND_INTENSITY))
		return 7;
	const WCHAR text[] = L"café \xd83d\xde42\n";
	if (!WriteConsoleW(output, text, 8, &count, NULL) || count != 8)
		return 8;
	SetConsoleTextAttribute(output, 7);

	WCHAR line[64];
	say("READY-LINE\n");
	if (!ReadConsoleW(input, line, 64, &count, NULL) || count != 7 || !same(line, L"hello\r\n", 7))
		return 9;

	if (!SetConsoleMode(input, ENABLE_PROCESSED_INPUT) || !GetConsoleMode(input, &mode) || (mode & 7) != ENABLE_PROCESSED_INPUT)
		return 10;
	say("READY-KEYS\n");
	KEY_EVENT_RECORD key;
	if (!next_press(&key) || key.wVirtualKeyCode != VK_UP || !(key.dwControlKeyState & ENHANCED_KEY) || key.uChar.UnicodeChar)
		return 11;
	if (!next_press(&key) || key.wVirtualKeyCode != 'X' || key.uChar.UnicodeChar != L'x' || key.wVirtualScanCode != 0x2d)
		return 12;
	if (!next_press(&key) || key.wVirtualKeyCode != VK_RIGHT || !(key.dwControlKeyState & LEFT_CTRL_PRESSED))
		return 13;
	if (!next_press(&key) || key.wVirtualKeyCode != VK_ESCAPE)
		return 14;
	say("READY-CHAR\n");
	if (!ReadConsoleW(input, line, 64, &count, NULL) || count != 1 || line[0] != L'q')
		return 15;
	if (!FlushConsoleInputBuffer(input) || !GetNumberOfConsoleInputEvents(input, &count) || count)
		return 16;

	HANDLE screen = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (screen == INVALID_HANDLE_VALUE || !GetConsoleMode(screen, &mode) || !WriteFile(screen, "via-conout\n", 11, &count, NULL))
		return 17;
	CloseHandle(screen);

	if (!SetConsoleMode(input, 0x1f7))
		return 18;
	char bytes[16];
	say("READY-FILE\n");
	if (!ReadFile(input, bytes, sizeof bytes, &count, NULL) || count != 5 || bytes[0] != 'a' || bytes[3] != '\r' || bytes[4] != '\n')
		return 19;

	WCHAR title[32];
	if (!SetConsoleTitleW(L"Raven test") || GetConsoleTitleW(title, 32) != 10 || !same(title, L"Raven test", 11))
		return 20;

	if (!SetConsoleCtrlHandler(takes, TRUE))
		return 21;
	say("READY-CTRL\n");
	for (int wait = 0; wait < 500 && !handled; ++wait)
		Sleep(10);
	if (!handled)
		return 22;
	say("HANDLED\n");

	if (!SetConsoleCtrlHandler(takes, FALSE) || SetConsoleCtrlHandler(takes, FALSE) || !SetConsoleCtrlHandler(declines, TRUE))
		return 23;
	say("READY-EXIT\n");
	for (int wait = 0; wait < 500; ++wait)
		Sleep(10);
	return 24;
}
