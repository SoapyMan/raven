/* cmd.exe, the command processor of a Raven prefix. Raven code on the public Windows headers, written from Microsoft's public
   description of the command processor and of its commands; no Windows code is used or consulted.

   It reads commands at a prompt, or runs the one after /C or /K, or a batch file. This first part has the command line and its
   options, %variable% and batch argument expansion, batch files with labels and GOTO, a handful of built-in commands, and the search
   of PATH and PATHEXT for programs, whose exit codes become ERRORLEVEL. Operators, blocks, IF and FOR come next. */

#include <windows.h>

#define LINE_LIMIT 8192

/* No C runtime: the compiler may still ask for these. */
void *memset(void *target, int value, size_t size)
{
	unsigned char *bytes = target;
	while (size--)
		*bytes++ = (unsigned char)value;
	return target;
}

void *memcpy(void *target, const void *source, size_t size)
{
	unsigned char *to = target;
	const unsigned char *from = source;
	while (size--)
		*to++ = *from++;
	return target;
}

static HANDLE input, output, error_output;
static BOOL echo_on = TRUE, interactive_input;
static DWORD errorlevel;
/* Set by EXIT: the processor ends (or, with /B, the batch file does) with this code. */
static BOOL leaving, leaving_batch;

/* The batch file running now: its lines, where the next one starts, and its arguments %0 to %9 and the rest after them. */
struct Batch {
	WCHAR *text;
	DWORD size, next;
	WCHAR *arguments[10];
	WCHAR *rest;
};
static struct Batch *batch;

static void *allocate(SIZE_T size) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size); }
static void release(void *block) { if (block) HeapFree(GetProcessHeap(), 0, block); }

static DWORD length(const WCHAR *text)
{
	DWORD size = 0;
	while (text[size])
		++size;
	return size;
}

static WCHAR *duplicate(const WCHAR *text, DWORD size)
{
	WCHAR *copy = allocate((size + 1) * sizeof(WCHAR));
	for (DWORD index = 0; index < size; ++index)
		copy[index] = text[index];
	return copy;
}

static WCHAR folded(WCHAR character) { return character >= L'a' && character <= L'z' ? (WCHAR)(character - 32) : character; }

/* Whether `text` starts with `word`, ignoring case. */
static BOOL starts(const WCHAR *text, const WCHAR *word)
{
	for (; *word; ++text, ++word)
		if (folded(*text) != folded(*word))
			return FALSE;
	return TRUE;
}

static BOOL equal(const WCHAR *left, const WCHAR *right) { return starts(left, right) && !left[length(right)]; }
static BOOL blank(WCHAR character) { return character == L' ' || character == L'\t'; }

/* Writes text to a handle: as characters to a console, else in the console's code page as cmd writes to files and pipes. */
static void write_to(HANDLE handle, const WCHAR *text, DWORD size)
{
	DWORD done, mode;
	if (!size)
		return;
	if (GetConsoleMode(handle, &mode)) {
		WriteConsoleW(handle, text, size, &done, NULL);
		return;
	}
	const UINT page = GetConsoleOutputCP();
	const int bytes = WideCharToMultiByte(page, 0, text, (int)size, NULL, 0, NULL, NULL);
	char *encoded = allocate((SIZE_T)bytes + 1);
	WideCharToMultiByte(page, 0, text, (int)size, encoded, bytes, NULL, NULL);
	WriteFile(handle, encoded, (DWORD)bytes, &done, NULL);
	release(encoded);
}

static void say(const WCHAR *text) { write_to(output, text, length(text)); }
static void complain(const WCHAR *text) { write_to(error_output, text, length(text)); }

static void say_number(DWORD value)
{
	WCHAR digits[12];
	int at = 11;
	digits[at] = 0;
	do
		digits[--at] = (WCHAR)(L'0' + value % 10);
	while (value /= 10);
	say(digits + at);
}

static DWORD parse_number(const WCHAR *text)
{
	DWORD value = 0;
	BOOL negative = *text == L'-';
	if (negative)
		++text;
	while (*text >= L'0' && *text <= L'9')
		value = value * 10 + (DWORD)(*text++ - L'0');
	return negative ? (DWORD)-(LONG)value : value;
}

/* Reads one line of commands, without its line end; FALSE at the end of the input. */
static BOOL read_line(WCHAR *line, DWORD limit)
{
	DWORD count = 0;
	if (interactive_input) {
		if (!ReadConsoleW(input, line, limit - 1, &count, NULL) || !count)
			return FALSE;
	} else {
		/* Byte by byte, so that a program run after this line reads what follows it. */
		char bytes[LINE_LIMIT];
		DWORD size = 0, got;
		while (size < sizeof bytes - 1 && ReadFile(input, bytes + size, 1, &got, NULL) && got) {
			if (bytes[size++] == '\n')
				break;
		}
		if (!size)
			return FALSE;
		count = (DWORD)MultiByteToWideChar(GetConsoleCP(), 0, bytes, (int)size, line, (int)limit - 1);
	}
	while (count && (line[count - 1] == L'\n' || line[count - 1] == L'\r'))
		--count;
	line[count] = 0;
	return TRUE;
}

/* The prompt from PROMPT, $P$G when it is not set: $P the current folder, $G >, $L <, $N the drive, $_ a new line, $S a space,
   $$ a dollar sign. */
static void show_prompt(void)
{
	WCHAR format[256], folder[MAX_PATH];
	if (!GetEnvironmentVariableW(L"PROMPT", format, 256))
		lstrcpyW(format, L"$P$G");
	GetCurrentDirectoryW(MAX_PATH, folder);
	for (const WCHAR *at = format; *at; ++at) {
		if (*at != L'$' || !at[1]) {
			write_to(output, at, 1);
			continue;
		}
		switch (folded(*++at)) {
		case L'P': say(folder); break;
		case L'G': say(L">"); break;
		case L'L': say(L"<"); break;
		case L'N': write_to(output, folder, 1); break;
		case L'_': say(L"\r\n"); break;
		case L'S': say(L" "); break;
		case L'$': say(L"$"); break;
		default: break;
		}
	}
}

/* Expands %NAME% from the environment, %ERRORLEVEL% and %CD% when no variable of that name is set, and in a batch file %0 to %9
   and %*; %% is one percent sign. A name that is not set stays as it was typed at the prompt, and goes away in a batch file. */
static WCHAR *expand(const WCHAR *line)
{
	WCHAR *result = allocate(LINE_LIMIT * sizeof(WCHAR));
	DWORD out = 0;
	for (const WCHAR *at = line; *at && out < LINE_LIMIT - 1;) {
		if (*at != L'%') {
			result[out++] = *at++;
			continue;
		}
		if (batch && at[1] == L'%') {
			result[out++] = L'%';
			at += 2;
			continue;
		}
		if (batch && at[1] >= L'0' && at[1] <= L'9') {
			const WCHAR *value = batch->arguments[at[1] - L'0'];
			for (; value && *value && out < LINE_LIMIT - 1; ++value)
				result[out++] = *value;
			at += 2;
			continue;
		}
		if (batch && at[1] == L'*') {
			for (const WCHAR *value = batch->rest; value && *value && out < LINE_LIMIT - 1; ++value)
				result[out++] = *value;
			at += 2;
			continue;
		}
		const WCHAR *end = at + 1;
		while (*end && *end != L'%')
			++end;
		if (!*end || end == at + 1) {
			result[out++] = *at++;
			continue;
		}
		WCHAR name[256], value[LINE_LIMIT];
		DWORD size = (DWORD)(end - at - 1), found;
		if (size >= 256)
			size = 255;
		for (DWORD index = 0; index < size; ++index)
			name[index] = at[1 + index];
		name[size] = 0;
		found = GetEnvironmentVariableW(name, value, LINE_LIMIT);
		if (!found && equal(name, L"ERRORLEVEL")) {
			WCHAR digits[12];
			int place = 11;
			DWORD number = errorlevel;
			digits[place] = 0;
			do
				digits[--place] = (WCHAR)(L'0' + number % 10);
			while (number /= 10);
			lstrcpyW(value, digits + place);
			found = 1;
		} else if (!found && equal(name, L"CD"))
			found = GetCurrentDirectoryW(LINE_LIMIT, value);
		if (found && found < LINE_LIMIT) {
			for (const WCHAR *copy = value; *copy && out < LINE_LIMIT - 1; ++copy)
				result[out++] = *copy;
		} else if (!batch) {
			for (const WCHAR *copy = at; copy <= end && out < LINE_LIMIT - 1; ++copy)
				result[out++] = *copy;
		}
		at = end + 1;
	}
	result[out] = 0;
	return result;
}

/* The first word of a command: up to a blank, or quoted. `rest` is what follows it. */
static void first_word(const WCHAR *text, WCHAR *word, DWORD limit, const WCHAR **rest)
{
	DWORD out = 0;
	BOOL quoted = FALSE;
	while (blank(*text))
		++text;
	for (; *text && (quoted || !blank(*text)); ++text) {
		if (*text == L'"') {
			quoted = !quoted;
			continue;
		}
		if (out < limit - 1)
			word[out++] = *text;
	}
	word[out] = 0;
	*rest = text;
}

static BOOL is_file(const WCHAR *path)
{
	const DWORD attributes = GetFileAttributesW(path);
	return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL has_extension(const WCHAR *name)
{
	const WCHAR *dot = NULL;
	for (const WCHAR *at = name; *at; ++at)
		if (*at == L'.')
			dot = at;
		else if (*at == L'\\' || *at == L'/' || *at == L':')
			dot = NULL;
	return dot != NULL;
}

/* Tries a name as it is when it has an extension, else with each extension of PATHEXT. */
static BOOL try_extensions(WCHAR *candidate, DWORD stem)
{
	WCHAR extensions[1024];
	if (has_extension(candidate) && is_file(candidate))
		return TRUE;
	if (!GetEnvironmentVariableW(L"PATHEXT", extensions, 1024))
		lstrcpyW(extensions, L".COM;.EXE;.BAT;.CMD");
	for (WCHAR *start = extensions; *start;) {
		WCHAR *end = start;
		while (*end && *end != L';')
			++end;
		DWORD size = stem;
		for (WCHAR *copy = start; copy < end && size < MAX_PATH - 1; ++copy)
			candidate[size++] = *copy;
		candidate[size] = 0;
		if (end > start && is_file(candidate))
			return TRUE;
		candidate[stem] = 0;
		start = *end ? end + 1 : end;
	}
	return FALSE;
}

/* Finds the program a command names: by its path when it has one, else in the current folder and then the folders of PATH. */
static BOOL find_program(const WCHAR *name, WCHAR *found)
{
	BOOL has_path = FALSE;
	for (const WCHAR *at = name; *at; ++at)
		if (*at == L'\\' || *at == L'/' || *at == L':')
			has_path = TRUE;
	WCHAR *folders = allocate(32768 * sizeof(WCHAR));
	DWORD folder_size = 0;
	if (!has_path) {
		folder_size = GetCurrentDirectoryW(MAX_PATH, folders);
		folders[folder_size++] = L';';
		folder_size += GetEnvironmentVariableW(L"PATH", folders + folder_size, 32768 - folder_size);
	}
	BOOL success = FALSE;
	if (has_path) {
		lstrcpynW(found, name, MAX_PATH);
		success = try_extensions(found, length(found));
	}
	for (WCHAR *start = folders; !success && start < folders + folder_size;) {
		WCHAR *end = start;
		while (end < folders + folder_size && *end != L';')
			++end;
		DWORD size = 0;
		for (WCHAR *copy = start; copy < end && size < MAX_PATH - 2; ++copy)
			if (*copy != L'"')
				found[size++] = *copy;
		if (size) {
			if (found[size - 1] != L'\\')
				found[size++] = L'\\';
			for (const WCHAR *copy = name; *copy && size < MAX_PATH - 1; ++copy)
				found[size++] = *copy;
			found[size] = 0;
			success = try_extensions(found, size);
		}
		start = end + 1;
	}
	release(folders);
	return success;
}

static BOOL batch_file(const WCHAR *path)
{
	const DWORD size = length(path);
	return size > 4 && (equal(path + size - 4, L".BAT") || equal(path + size - 4, L".CMD"));
}

static void run_batch(const WCHAR *path, const WCHAR *arguments);
static void run_line(const WCHAR *line);

/* Runs a program and waits for it; its exit code becomes ERRORLEVEL. */
static void run_program(const WCHAR *path, const WCHAR *command)
{
	STARTUPINFOW startup;
	PROCESS_INFORMATION process;
	memset(&startup, 0, sizeof startup);
	startup.cb = sizeof startup;
	WCHAR *line = duplicate(command, length(command));
	if (!CreateProcessW(path, line, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &process)) {
		complain(L"The system cannot execute the specified program.\r\n");
		errorlevel = GetLastError();
		release(line);
		return;
	}
	release(line);
	CloseHandle(process.hThread);
	WaitForSingleObject(process.hProcess, INFINITE);
	GetExitCodeProcess(process.hProcess, &errorlevel);
	CloseHandle(process.hProcess);
}

static void command_echo(const WCHAR *rest)
{
	/* The character right after ECHO only separates: ECHO. prints an empty line. */
	const WCHAR *text = *rest ? rest + 1 : rest;
	const WCHAR *word = text;
	while (blank(*word))
		++word;
	if (!*rest || !*word) {
		if (*rest && *rest != L' ' && *rest != L'\t') {
			say(L"\r\n");
			return;
		}
		say(echo_on ? L"ECHO is on.\r\n" : L"ECHO is off.\r\n");
		return;
	}
	if (equal(word, L"ON") || equal(word, L"OFF")) {
		echo_on = equal(word, L"ON");
		return;
	}
	say(text);
	say(L"\r\n");
}

static void command_cd(const WCHAR *rest)
{
	WCHAR folder[MAX_PATH];
	while (blank(*rest))
		++rest;
	if (starts(rest, L"/D") && (blank(rest[2]) || !rest[2])) {
		rest += 2;
		while (blank(*rest))
			++rest;
	}
	if (!*rest) {
		GetCurrentDirectoryW(MAX_PATH, folder);
		say(folder);
		say(L"\r\n");
		return;
	}
	DWORD size = 0;
	for (; *rest && size < MAX_PATH - 1; ++rest)
		if (*rest != L'"')
			folder[size++] = *rest;
	while (size && blank(folder[size - 1]))
		--size;
	folder[size] = 0;
	if (!SetCurrentDirectoryW(folder)) {
		complain(L"The system cannot find the path specified.\r\n");
		errorlevel = 1;
		return;
	}
	errorlevel = 0;
}

static void command_set(const WCHAR *rest)
{
	while (blank(*rest))
		++rest;
	const WCHAR *equals = rest;
	while (*equals && *equals != L'=')
		++equals;
	if (*equals == L'=' && equals > rest) {
		WCHAR *name = duplicate(rest, (DWORD)(equals - rest));
		SetEnvironmentVariableW(name, equals[1] ? equals + 1 : NULL);
		release(name);
		errorlevel = 0;
		return;
	}
	/* SET alone lists every variable; SET name lists those whose names start with it. */
	WCHAR *block = GetEnvironmentStringsW();
	BOOL listed = FALSE;
	for (WCHAR *entry = block; *entry; entry += length(entry) + 1) {
		if (*entry == L'=' || !starts(entry, rest))
			continue;
		say(entry);
		say(L"\r\n");
		listed = TRUE;
	}
	FreeEnvironmentStringsW(block);
	if (*rest && !listed) {
		complain(L"Environment variable ");
		complain(rest);
		complain(L" not defined\r\n");
		errorlevel = 1;
	}
}

static void command_cls(void)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD origin = {0, 0};
	DWORD written;
	if (!GetConsoleScreenBufferInfo(output, &info)) {
		say(L"\f");
		return;
	}
	FillConsoleOutputCharacterW(output, L' ', (DWORD)(info.dwSize.X * info.dwSize.Y), origin, &written);
	FillConsoleOutputAttribute(output, info.wAttributes, (DWORD)(info.dwSize.X * info.dwSize.Y), origin, &written);
	SetConsoleCursorPosition(output, origin);
}

static void command_type(const WCHAR *rest)
{
	WCHAR name[MAX_PATH];
	const WCHAR *after;
	first_word(rest, name, MAX_PATH, &after);
	HANDLE file = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		complain(L"The system cannot find the file specified.\r\n");
		errorlevel = 1;
		return;
	}
	char bytes[4096];
	DWORD count;
	while (ReadFile(file, bytes, sizeof bytes, &count, NULL) && count) {
		WCHAR text[4096];
		const int characters = MultiByteToWideChar(GetConsoleOutputCP(), 0, bytes, (int)count, text, 4096);
		write_to(output, text, (DWORD)characters);
	}
	CloseHandle(file);
	errorlevel = 0;
}

static void command_pause(void)
{
	DWORD mode, count;
	WCHAR key;
	say(L"Press any key to continue . . . ");
	if (GetConsoleMode(input, &mode)) {
		SetConsoleMode(input, mode & ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
		ReadConsoleW(input, &key, 1, &count, NULL);
		SetConsoleMode(input, mode);
	} else {
		char byte;
		ReadFile(input, &byte, 1, &count, NULL);
	}
	say(L"\r\n");
}

static void command_exit(const WCHAR *rest)
{
	while (blank(*rest))
		++rest;
	if (starts(rest, L"/B") && (blank(rest[2]) || !rest[2])) {
		rest += 2;
		while (blank(*rest))
			++rest;
		if (batch)
			leaving_batch = TRUE;
		else
			leaving = TRUE;
	} else
		leaving = TRUE;
	if (*rest)
		errorlevel = parse_number(rest);
}

/* Jumps to a label of the running batch file; :EOF is its end. */
static void command_goto(const WCHAR *rest)
{
	WCHAR label[256];
	const WCHAR *after;
	while (blank(*rest) || *rest == L':')
		++rest;
	first_word(rest, label, 256, &after);
	if (!batch)
		return;
	if (equal(label, L"EOF")) {
		batch->next = batch->size;
		return;
	}
	for (DWORD at = 0; at < batch->size;) {
		DWORD end = at;
		while (end < batch->size && batch->text[end] != L'\n')
			++end;
		DWORD start = at;
		while (start < end && blank(batch->text[start]))
			++start;
		if (start < end && batch->text[start] == L':') {
			DWORD index = 0;
			++start;
			while (label[index] && start + index < end && folded(batch->text[start + index]) == folded(label[index]))
				++index;
			const DWORD stop = start + index;
			if (!label[index] && (stop == end || blank(batch->text[stop]) || batch->text[stop] == L'\r')) {
				batch->next = end < batch->size ? end + 1 : end;
				return;
			}
		}
		at = end + 1;
	}
	complain(L"The system cannot find the batch label specified - ");
	complain(label);
	complain(L"\r\n");
	batch->next = batch->size;
	errorlevel = 1;
}

/* Runs one command, expanded. */
static void run_line(const WCHAR *typed)
{
	WCHAR *line = expand(typed);
	const WCHAR *command = line;
	while (blank(*command) || *command == L'@')
		++command;
	if (!*command || *command == L':') {
		release(line);
		return;
	}
	/* A built-in's name ends at a blank or at the characters cmd lets follow it directly: ECHO. CD\ CD.. */
	const WCHAR *end = command;
	while (*end && !blank(*end) && *end != L'.' && *end != L'\\' && *end != L'/' && *end != L'(' && *end != L'=' && *end != L',' &&
		*end != L';' && *end != L'+' && *end != L'"')
		++end;
	WCHAR name[32];
	DWORD size = (DWORD)(end - command) < 31 ? (DWORD)(end - command) : 31;
	for (DWORD index = 0; index < size; ++index)
		name[index] = command[index];
	name[size] = 0;
	const WCHAR *rest = end;

	if (size == 2 && command[1] == L':' && !*rest) {
		/* X: changes to that drive. */
		WCHAR drive[3] = {command[0], L':', 0};
		if (!SetCurrentDirectoryW(drive)) {
			complain(L"The system cannot find the drive specified.\r\n");
			errorlevel = 1;
		}
	} else if (equal(name, L"ECHO"))
		command_echo(rest);
	else if (equal(name, L"REM"))
		;
	else if (equal(name, L"CD") || equal(name, L"CHDIR"))
		command_cd(rest);
	else if (equal(name, L"SET"))
		command_set(rest);
	else if (equal(name, L"CLS"))
		command_cls();
	else if (equal(name, L"VER"))
		say(L"\r\nRaven Command Processor [Version 0.1]\r\n");
	else if (equal(name, L"TITLE")) {
		while (blank(*rest))
			++rest;
		SetConsoleTitleW(rest);
	} else if (equal(name, L"TYPE"))
		command_type(rest);
	else if (equal(name, L"PAUSE"))
		command_pause();
	else if (equal(name, L"PATH")) {
		while (blank(*rest))
			++rest;
		if (*rest == L'=' || *rest == L';')
			++rest;
		if (!*rest) {
			WCHAR *path = allocate(32768 * sizeof(WCHAR));
			say(GetEnvironmentVariableW(L"PATH", path, 32768) ? L"PATH=" : L"No Path");
			say(path);
			say(L"\r\n");
			release(path);
		} else
			SetEnvironmentVariableW(L"PATH", rest);
	} else if (equal(name, L"EXIT"))
		command_exit(rest);
	else if (equal(name, L"GOTO"))
		command_goto(rest);
	else {
		WCHAR program[MAX_PATH], path[MAX_PATH];
		const WCHAR *arguments;
		first_word(command, program, MAX_PATH, &arguments);
		if (!find_program(program, path)) {
			complain(L"'");
			complain(program);
			complain(L"' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n");
			errorlevel = 9009;
		} else if (batch_file(path))
			run_batch(path, arguments);
		else
			run_program(path, command);
	}
	release(line);
}

/* Splits a batch file's arguments into %1 to %9; %* is all of them. Quotes stay part of an argument. */
static void batch_arguments(struct Batch *run, const WCHAR *path, const WCHAR *arguments)
{
	run->arguments[0] = duplicate(path, length(path));
	while (blank(*arguments))
		++arguments;
	run->rest = duplicate(arguments, length(arguments));
	for (int index = 1; index < 10 && *arguments; ++index) {
		const WCHAR *start = arguments;
		BOOL quoted = FALSE;
		while (*arguments && (quoted || !blank(*arguments))) {
			if (*arguments == L'"')
				quoted = !quoted;
			++arguments;
		}
		run->arguments[index] = duplicate(start, (DWORD)(arguments - start));
		while (blank(*arguments))
			++arguments;
	}
}

/* Runs a batch file line by line, then comes back to what called it. */
static void run_batch(const WCHAR *path, const WCHAR *arguments)
{
	HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		complain(L"The batch file cannot be found.\r\n");
		errorlevel = 1;
		return;
	}
	const DWORD bytes = GetFileSize(file, NULL);
	char *raw = allocate((SIZE_T)bytes + 1);
	DWORD count = 0;
	ReadFile(file, raw, bytes, &count, NULL);
	CloseHandle(file);
	struct Batch *run = allocate(sizeof *run);
	run->text = allocate(((SIZE_T)count + 1) * sizeof(WCHAR));
	run->size = (DWORD)MultiByteToWideChar(GetConsoleCP(), 0, raw, (int)count, run->text, (int)count);
	release(raw);
	batch_arguments(run, path, arguments);
	struct Batch *caller = batch;
	batch = run;
	while (!leaving && !leaving_batch && run->next < run->size) {
		DWORD end = run->next;
		while (end < run->size && run->text[end] != L'\n')
			++end;
		DWORD stop = end;
		if (stop > run->next && run->text[stop - 1] == L'\r')
			--stop;
		WCHAR *line = duplicate(run->text + run->next, stop - run->next);
		run->next = end < run->size ? end + 1 : end;
		const WCHAR *shown = line;
		while (blank(*shown))
			++shown;
		/* With ECHO on, each command is shown after the prompt, except one that starts with @ and labels. */
		if (echo_on && *shown && *shown != L'@' && *shown != L':') {
			say(L"\r\n");
			show_prompt();
			say(shown);
			say(L"\r\n");
		}
		run_line(line);
		release(line);
	}
	leaving_batch = FALSE;
	batch = caller;
	for (int index = 0; index < 10; ++index)
		release(run->arguments[index]);
	release(run->rest);
	release(run->text);
	release(run);
}

/* Ctrl+C belongs to the program running in the foreground: the processor itself goes on. */
static BOOL WINAPI on_control(DWORD event)
{
	(void)event;
	return TRUE;
}

/* What follows /C or /K, with quotes treated as cmd /? describes: kept when there are exactly two, with nothing special and at least
   one blank between them, around the name of a program; otherwise a leading quote and the last quote are removed. */
static WCHAR *command_text(const WCHAR *text, BOOL strip_always)
{
	while (blank(*text))
		++text;
	const DWORD size = length(text);
	WCHAR *copy = duplicate(text, size);
	if (*copy != L'"')
		return copy;
	DWORD quotes = 0, last = 0;
	BOOL special = FALSE, spaced = FALSE;
	for (DWORD index = 0; index < size; ++index) {
		if (copy[index] == L'"') {
			++quotes;
			last = index;
		} else if (quotes == 1) {
			const WCHAR character = copy[index];
			special |= character == L'&' || character == L'<' || character == L'>' || character == L'(' || character == L')' ||
				character == L'@' || character == L'^' || character == L'|';
			spaced |= blank(character);
		}
	}
	if (!strip_always && quotes == 2 && !special && spaced) {
		WCHAR name[MAX_PATH], path[MAX_PATH];
		DWORD out = 0;
		for (DWORD index = 1; index < last && out < MAX_PATH - 1; ++index)
			name[out++] = copy[index];
		name[out] = 0;
		if (find_program(name, path))
			return copy;
	}
	/* Remove the first quote and the last one. */
	DWORD out = 0;
	for (DWORD index = 1; index < size; ++index)
		if (index != last)
			copy[out++] = copy[index];
	copy[out] = 0;
	return copy;
}

int raven_cmd_entry(void)
{
	input = GetStdHandle(STD_INPUT_HANDLE);
	output = GetStdHandle(STD_OUTPUT_HANDLE);
	error_output = GetStdHandle(STD_ERROR_HANDLE);
	DWORD mode;
	interactive_input = GetConsoleMode(input, &mode);
	SetConsoleCtrlHandler(on_control, TRUE);

	/* The options before /C or /K; what follows either is the command. */
	const WCHAR *line = GetCommandLineW();
	const WCHAR *ignored;
	WCHAR program[MAX_PATH];
	first_word(line, program, MAX_PATH, &ignored);
	const WCHAR *at = ignored;
	BOOL run_once = FALSE, keep = FALSE, strip = FALSE;
	const WCHAR *command = NULL;
	for (;;) {
		while (blank(*at))
			++at;
		if (*at != L'/')
			break;
		const WCHAR option = folded(at[1]);
		if (option == L'C' || option == L'K') {
			run_once = option == L'C';
			keep = option == L'K';
			command = at + 2;
			break;
		}
		if (option == L'Q')
			echo_on = FALSE;
		else if (option == L'S')
			strip = TRUE;
		at += 2;
		while (*at && !blank(*at) && *at != L'/')
			++at;
	}

	if (command) {
		WCHAR *text = command_text(command, strip);
		run_line(text);
		release(text);
		if (run_once || leaving)
			ExitProcess(errorlevel);
	}
	if (!keep) {
		say(L"Raven Command Processor [Version 0.1]\r\n\r\n");
	}
	WCHAR *typed = allocate(LINE_LIMIT * sizeof(WCHAR));
	while (!leaving) {
		if (echo_on) {
			show_prompt();
		}
		if (!read_line(typed, LINE_LIMIT))
			break;
		run_line(typed);
		if (echo_on && interactive_input && !leaving)
			say(L"\r\n");
	}
	release(typed);
	ExitProcess(errorlevel);
	return 0;
}
