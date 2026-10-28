/* taskkill.exe: TASKKILL [/FI filter] [/PID processid | /IM imagename] [/T] [/F] — ends processes by their PID or their program's name,
   with /T the processes they started too. Raven ends a process the way /F does, whether or not /F is given. ERRORLEVEL is 0 when every
   process named was ended, 128 when one was not found, 1 on another error. */

#include "tool.h"
#include "processes.h"

static struct Processes list;
static DWORD status;

static BOOL end_process(DWORD id)
{
	HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, id);
	if (!handle)
		return FALSE;
	const BOOL ended = TerminateProcess(handle, 1);
	CloseHandle(handle);
	return ended;
}

static void report(const struct Process *process, BOOL by_name, DWORD parent)
{
	struct Text text = {0};
	if (!end_process(process->id)) {
		text_put(&text, L"ERROR: The process ");
		if (by_name) {
			text_char(&text, L'"');
			text_put(&text, process->name);
			text_put(&text, L"\" ");
		}
		text_put(&text, L"with PID ");
		put_number(&text, process->id, FALSE);
		text_put(&text, L" could not be terminated.\r\nReason: Access is denied.\r\n");
		complain(text.data);
		release(text.data);
		status = 1;
		return;
	}
	text_put(&text, L"SUCCESS: The process ");
	if (by_name) {
		text_char(&text, L'"');
		text_put(&text, process->name);
		text_put(&text, L"\" ");
	}
	text_put(&text, L"with PID ");
	put_number(&text, process->id, FALSE);
	if (parent) {
		text_put(&text, L" (child process of PID ");
		put_number(&text, parent, FALSE);
		text_char(&text, L')');
	}
	text_put(&text, L" has been terminated.\r\n");
	say_text(&text);
	release(text.data);
}

/* With /T, the processes a process started are ended first, deepest first. */
static void end_tree(const struct Process *process, BOOL by_name, DWORD parent, BOOL tree)
{
	if (tree)
		for (DWORD index = 0; index < list.count; ++index)
			if (list.items[index].parent == process->id && list.items[index].id != process->id && list.items[index].id != GetCurrentProcessId())
				end_tree(&list.items[index], by_name, process->id, tree);
	report(process, by_name, parent);
}

int raven_tool_entry(void)
{
	struct Arguments arguments;
	start_tool();
	read_arguments(&arguments);
	struct Filter filters[16];
	DWORD filter_count = 0, targets = 0;
	BOOL tree = FALSE;
	for (DWORD index = 0; index < arguments.count; ++index) {
		const WCHAR *argument = arguments.items[index];
		const BOOL value = index + 1 < arguments.count;
		if ((switch_is(argument, L"/PID") || switch_is(argument, L"/IM")) && value) {
			++targets;
			++index;
		} else if (switch_is(argument, L"/FI") && value) {
			if (filter_count == 16 || !read_filter(arguments.items[++index], &filters[filter_count])) {
				complain(L"ERROR: The search filter cannot be recognized.\r\n");
				ExitProcess(1);
			}
			++filter_count;
		} else if (switch_is(argument, L"/T"))
			tree = TRUE;
		else if (switch_is(argument, L"/F"))
			;
		else if ((switch_is(argument, L"/S") || switch_is(argument, L"/U") || switch_is(argument, L"/P")) && value)
			++index;
		else if (switch_is(argument, L"/?")) {
			say(L"TASKKILL [/S system [/U username [/P [password]]]]\r\n"
				L"         { [/FI filter] [/PID processid | /IM imagename] } [/T] [/F]\r\n\r\n"
				L"Description:\r\n    This tool is used to terminate tasks by process id (PID) or image name.\r\n");
			ExitProcess(0);
		} else {
			complain(L"ERROR: Invalid argument/option - '");
			complain(argument);
			complain(L"'.\r\nType \"TASKKILL /?\" for usage.\r\n");
			ExitProcess(1);
		}
	}
	if (!targets && !filter_count) {
		complain(L"ERROR: Invalid syntax. Neither /FI nor /PID nor /IM were specified.\r\nType \"TASKKILL /?\" for usage.\r\n");
		ExitProcess(1);
	}
	if (!list_processes(&list)) {
		complain(L"ERROR: The process list cannot be read.\r\n");
		ExitProcess(1);
	}
	const DWORD self = GetCurrentProcessId();
	for (DWORD index = 0; index < arguments.count; ++index) {
		const WCHAR *argument = arguments.items[index];
		const BOOL by_id = switch_is(argument, L"/PID"), by_name = switch_is(argument, L"/IM");
		if ((!by_id && !by_name) || index + 1 >= arguments.count)
			continue;
		const WCHAR *target = arguments.items[++index];
		ULONGLONG id = 0;
		if (by_id && !read_number(target, &id)) {
			complain(L"ERROR: Invalid syntax. Value expected for '/pid'.\r\n");
			status = 1;
			continue;
		}
		BOOL found = FALSE;
		for (DWORD item = 0; item < list.count; ++item) {
			const struct Process *process = &list.items[item];
			if (process->id == self || (by_id ? process->id != id : !matches(target, process->name)))
				continue;
			BOOL wanted = TRUE;
			for (DWORD filter = 0; filter < filter_count && wanted; ++filter)
				wanted = passes(&filters[filter], process);
			if (!wanted)
				continue;
			found = TRUE;
			end_tree(process, by_name, 0, tree);
		}
		if (!found) {
			complain(L"ERROR: The process \"");
			complain(target);
			complain(L"\" not found.\r\n");
			status = 128;
		}
	}
	/* Filters alone end every process they let through. */
	if (!targets) {
		BOOL found = FALSE;
		for (DWORD item = 0; item < list.count; ++item) {
			BOOL wanted = list.items[item].id != self;
			for (DWORD filter = 0; filter < filter_count && wanted; ++filter)
				wanted = passes(&filters[filter], &list.items[item]);
			if (wanted) {
				found = TRUE;
				end_tree(&list.items[item], TRUE, 0, tree);
			}
		}
		if (!found)
			say(L"INFO: No tasks running with the specified criteria.\r\n");
	}
	ExitProcess(status);
	return 0;
}
