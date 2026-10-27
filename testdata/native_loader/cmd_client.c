#include <windows.h>

/* The command processor in the prefix, through pipes: a batch file started with CreateProcess runs in cmd /c, cmd /c runs built-in
   commands and programs and ends with their ERRORLEVEL, and commands piped to its prompt run one by one. Returns the failed step. */

static WCHAR folder[MAX_PATH];

/* No C runtime: zeroing the structures below may ask for this. */
void *memset(void *target, int value, size_t size)
{
	unsigned char *bytes = target;
	while (size--)
		*bytes++ = (unsigned char)value;
	return target;
}

static DWORD length(const WCHAR *text)
{
	DWORD size = 0;
	while (text[size])
		++size;
	return size;
}

static void append(WCHAR *target, const WCHAR *text)
{
	WCHAR *end = target + length(target);
	while (*text)
		*end++ = *text++;
	*end = 0;
}

static BOOL contains(const char *text, const char *wanted)
{
	for (; *text; ++text) {
		const char *a = text, *b = wanted;
		while (*a && *b && *a == *b)
			++a, ++b;
		if (!*b)
			return TRUE;
	}
	return FALSE;
}

static BOOL same(const char *left, const char *right)
{
	while (*left && *left == *right)
		++left, ++right;
	return *left == *right;
}

/* Runs a command line with its output, and its error output, in `text`; `typed` is what it reads, if anything. */
static BOOL run(const WCHAR *application, const WCHAR *command, const char *typed, char *text, DWORD capacity, DWORD *code)
{
	SECURITY_ATTRIBUTES inherit = {sizeof inherit, NULL, TRUE};
	HANDLE read_end, write_end, feed_read = NULL, feed_write = NULL;
	if (!CreatePipe(&read_end, &write_end, &inherit, 0))
		return FALSE;
	SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
	if (typed) {
		if (!CreatePipe(&feed_read, &feed_write, &inherit, 0))
			return FALSE;
		SetHandleInformation(feed_write, HANDLE_FLAG_INHERIT, 0);
	}
	STARTUPINFOW startup = {sizeof startup};
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = feed_read;
	startup.hStdOutput = write_end;
	startup.hStdError = write_end;
	PROCESS_INFORMATION process;
	WCHAR line[1024] = {0};
	append(line, command);
	if (!CreateProcessW(application, line, NULL, NULL, TRUE, 0, NULL, folder, &startup, &process))
		return FALSE;
	CloseHandle(write_end);
	if (typed) {
		DWORD written, size = 0;
		while (typed[size])
			++size;
		CloseHandle(feed_read);
		WriteFile(feed_write, typed, size, &written, NULL);
		CloseHandle(feed_write);
	}
	DWORD total = 0, count;
	while (total < capacity - 1 && ReadFile(read_end, text + total, capacity - 1 - total, &count, NULL) && count)
		total += count;
	text[total] = 0;
	CloseHandle(read_end);
	WaitForSingleObject(process.hProcess, INFINITE);
	GetExitCodeProcess(process.hProcess, code);
	CloseHandle(process.hProcess);
	CloseHandle(process.hThread);
	return TRUE;
}

static const char script[] = "@echo off\r\n"
	"set GREETING=hello\r\n"
	"echo %GREETING% from batch\r\n"
	"goto skip\r\n"
	"echo not skipped\r\n"
	":skip\r\n"
	"echo args %1 %2\r\n"
	"exit /b 7\r\n";

int raven_entry(void)
{
	static char text[8192];
	DWORD code = 0, written;
	const WCHAR *processor = L"C:\\Windows\\System32\\cmd.exe";

	if (GetFileAttributesW(processor) == INVALID_FILE_ATTRIBUTES)
		return 1;
	GetTempPathW(MAX_PATH, folder);
	append(folder, L"raven-cmd-test");
	CreateDirectoryW(folder, NULL);
	WCHAR path[MAX_PATH] = {0};
	append(path, folder);
	append(path, L"\\script.bat");
	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (file == INVALID_HANDLE_VALUE || !WriteFile(file, script, sizeof script - 1, &written, NULL))
		return 2;
	CloseHandle(file);

	/* A batch file given to CreateProcess runs in the command processor, with its arguments. */
	WCHAR line[MAX_PATH + 32] = L"\"";
	append(line, path);
	append(line, L"\" one two");
	if (!run(NULL, line, NULL, text, sizeof text, &code) || code != 7 || !same(text, "hello from batch\r\nargs one two\r\n"))
		return 3;
	if (!run(processor, L"cmd.exe /c exit 5", NULL, text, sizeof text, &code) || code != 5)
		return 4;
	if (!run(processor, L"cmd.exe /c echo x", NULL, text, sizeof text, &code) || code || !same(text, "x\r\n"))
		return 5;
	if (!run(processor, L"cmd.exe /c no-such-program", NULL, text, sizeof text, &code) || code != 9009 ||
		!contains(text, "is not recognized as an internal or external command"))
		return 6;
	if (!run(processor, L"cmd.exe /c ver", NULL, text, sizeof text, &code) || code || !contains(text, "Raven Command Processor"))
		return 7;
	/* A program cmd finds on PATH: another command processor, whose exit code becomes ERRORLEVEL. */
	if (!run(processor, L"cmd.exe /c cmd /c exit 3", NULL, text, sizeof text, &code) || code != 3)
		return 8;
	/* Commands typed at the prompt, from a pipe: the prompt shows the folder, and EXIT ends with its code. */
	if (!run(processor, L"cmd.exe", "echo piped\r\nset RAVEN_TYPED=yes\r\necho %RAVEN_TYPED%\r\nexit 4\r\n", text, sizeof text, &code) ||
		code != 4 || !contains(text, "raven-cmd-test>") || !contains(text, "piped\r\n") || !contains(text, "yes\r\n"))
		return 9;
	DeleteFileW(path);
	RemoveDirectoryW(folder);
	return 0;
}
