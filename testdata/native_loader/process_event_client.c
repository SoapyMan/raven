#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>

typedef LONG (WINAPI *query_process)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef LONG (WINAPI *query_event)(HANDLE, ULONG, void *, ULONG, ULONG *);

struct basic_information {
	LONG exit_status;
	void *peb;
	ULONG_PTR affinity;
	LONG priority;
	ULONG_PTR pid, parent;
};

static HANDLE transferred[8];
static HANDLE sibling_handle;

static int extended_events(void)
{
	query_event query = (query_event)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryEvent");
	ULONG state[2], length;
	HANDLE modify = CreateEventExW(NULL, NULL, 0, EVENT_MODIFY_STATE);
	HANDLE query_only = CreateEventExA(NULL, NULL, 3, 1);
	HANDLE empty = CreateEventExW(NULL, NULL, 2, 0);
	if (!query || !modify || !query_only || !empty || !SetEvent(modify) ||
		WaitForSingleObject(modify, 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED ||
		query(query_only, 0, state, sizeof(state), &length) || state[0] || state[1] != 1)
		return 100;
	if (SetEvent(query_only) || GetLastError() != ERROR_ACCESS_DENIED ||
		WaitForSingleObject(query_only, 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED ||
		(ULONG)query(empty, 0, state, sizeof(state), &length) != 0xc0000022)
		return 101;
	if (!CloseHandle(modify) || !CloseHandle(query_only) || !CloseHandle(empty))
		return 102;
	if (CreateEventExW(NULL, NULL, 4, EVENT_ALL_ACCESS) || GetLastError() != ERROR_INVALID_PARAMETER ||
		CreateEventExA(NULL, NULL, 0, 4) || GetLastError() != ERROR_INVALID_PARAMETER)
		return 103;
	char name[] = "Local\\RavenEventEx-00000000";
	DWORD pid = GetCurrentProcessId();
	for (unsigned index = 0; index < 8; ++index) {
		name[sizeof(name) - 2 - index] = "0123456789abcdef"[pid & 15];
		pid >>= 4;
	}
	WCHAR wide[sizeof(name)];
	for (unsigned index = 0; index < sizeof(name); ++index) wide[index] = (BYTE)name[index];
	SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
	HANDLE first = CreateEventExW(&attributes, wide, 3, EVENT_ALL_ACCESS);
	DWORD flags;
	if (!first || GetLastError() == ERROR_ALREADY_EXISTS || !GetHandleInformation(first, &flags) || !(flags & HANDLE_FLAG_INHERIT))
		return 104;
	HANDLE second = CreateEventExA(NULL, name, 0, SYNCHRONIZE);
	if (!second || GetLastError() != ERROR_ALREADY_EXISTS || !GetHandleInformation(second, &flags) || (flags & HANDLE_FLAG_INHERIT) ||
		WaitForSingleObject(second, 0) != WAIT_OBJECT_0 || WaitForSingleObject(second, 0) != WAIT_OBJECT_0 ||
		SetEvent(second) || GetLastError() != ERROR_ACCESS_DENIED)
		return 105;
	if (!ResetEvent(first) || WaitForSingleObject(second, 0) != WAIT_TIMEOUT || !SetEvent(first))
		return 106;
	HANDLE legacy = CreateEventW(NULL, FALSE, FALSE, wide);
	if (!legacy || GetLastError() != ERROR_ALREADY_EXISTS || WaitForSingleObject(legacy, 0) != WAIT_OBJECT_0 ||
		WaitForSingleObject(legacy, 0) != WAIT_OBJECT_0 || !CloseHandle(first) ||
		WaitForSingleObject(second, 0) != WAIT_OBJECT_0 || !CloseHandle(legacy) || !CloseHandle(second))
		return 107;
	/* A descriptor of its own, as services give the events they share with other sessions, is accepted with the event. */
	SECURITY_DESCRIPTOR descriptor;
	if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) || !SetSecurityDescriptorDacl(&descriptor, TRUE, NULL, FALSE))
		return 108;
	attributes.lpSecurityDescriptor = &descriptor;
	WCHAR global[sizeof(name) + 1] = L"Global";
	for (unsigned index = 5; index < sizeof(name); ++index) global[index + 1] = wide[index];
	HANDLE shared = CreateEventExW(&attributes, global, 0, EVENT_ALL_ACCESS);
	if (!shared || GetLastError() == ERROR_ALREADY_EXISTS || !SetEvent(shared) || !CloseHandle(shared))
		return 109;
	return 0;
}

static int child_entry(void)
{
	query_event query = (query_event)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryEvent");
	ULONG state[2], length;
	HANDLE copy;
	if (!query || query(transferred[2], 0, state, sizeof(state), &length) || state[0] || state[1] != 1)
		return 20;
	if (SetEvent(transferred[2]) || GetLastError() != ERROR_ACCESS_DENIED ||
		SetEvent(transferred[3]) || GetLastError() != ERROR_ACCESS_DENIED ||
		WaitForSingleObject(transferred[3], 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED ||
		WaitForSingleObject(transferred[4], 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED ||
		(ULONG)query(transferred[3], 0, state, sizeof(state), &length) != 0xc0000022)
		return 21;
	if (WaitForSingleObject(transferred[5], 0) != WAIT_OBJECT_0 || WaitForSingleObject(transferred[5], 0) != WAIT_TIMEOUT)
		return 22;
	if (!DuplicateHandle(GetCurrentProcess(), transferred[2], GetCurrentProcess(), &copy, GENERIC_READ, FALSE, 0) ||
		query(copy, 0, state, sizeof(state), &length) || !state[1] ||
		SetEvent(copy) || GetLastError() != ERROR_ACCESS_DENIED)
		return 23;
	CloseHandle(copy);
	if (WaitForSingleObject(transferred[6], 0) != WAIT_TIMEOUT || ReleaseMutex(transferred[6]) ||
		GetLastError() != ERROR_NOT_OWNER || WaitForSingleObject(transferred[7], 0) != WAIT_FAILED ||
		GetLastError() != ERROR_ACCESS_DENIED)
		return 26;
	if (!SetEvent(transferred[1]) || WaitForSingleObject(transferred[0], 10000) != WAIT_OBJECT_0 ||
		WaitForSingleObject(transferred[0], 0) != WAIT_TIMEOUT || WaitForSingleObject(transferred[2], 0) != WAIT_TIMEOUT ||
		WaitForSingleObject(transferred[6], 0) != WAIT_TIMEOUT || !SetEvent(transferred[4]) || !SetEvent(transferred[1]))
		return 24;
	if (WaitForSingleObject(transferred[0], 10000) != WAIT_OBJECT_0 ||
		WaitForSingleObject(transferred[2], 0) != WAIT_TIMEOUT ||
		WaitForSingleObject(transferred[6], 10000) != WAIT_OBJECT_0 || WaitForSingleObject(transferred[6], 0) != WAIT_OBJECT_0 ||
		!ReleaseMutex(transferred[6]) || !SetEvent(transferred[1]) || WaitForSingleObject(transferred[0], 10000) != WAIT_OBJECT_0 ||
		!ReleaseMutex(transferred[6]) || !SetEvent(transferred[1]))
		return 25;
	for (unsigned index = 0; index < 8; ++index) CloseHandle(transferred[index]);
	return 0;
}

static int detached_child(void)
{
	if (WaitForSingleObject(transferred[1], 10000) != WAIT_OBJECT_0) return 130;
	HANDLE parent = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)(ULONG_PTR)transferred[0]);
	HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL), remote = NULL, copy = NULL;
	if (!parent || !event || !DuplicateHandle(GetCurrentProcess(), event, parent, &remote, EVENT_ALL_ACCESS, FALSE, 0)) return 131;
	if (!CloseHandle(event) || !DuplicateHandle(parent, remote, GetCurrentProcess(), &copy, SYNCHRONIZE, FALSE, DUPLICATE_CLOSE_SOURCE) ||
		WaitForSingleObject(copy, 0) != WAIT_OBJECT_0 || WaitForSingleObject(copy, 0) != WAIT_OBJECT_0 ||
		SetEvent(copy) || GetLastError() != ERROR_ACCESS_DENIED || !CloseHandle(copy) || !CloseHandle(parent)) return 132;
	if (!SetEvent(transferred[2]) || WaitForSingleObject(transferred[1], 10000) != WAIT_OBJECT_0) return 133;
	CloseHandle(transferred[1]);
	CloseHandle(transferred[2]);
	return 0;
}

static int sibling_child(void)
{
	if (WaitForSingleObject(transferred[1], 10000) != WAIT_OBJECT_0) return 160;
	HANDLE parent = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)(ULONG_PTR)transferred[0]);
	HANDLE event = CreateEventW(NULL, TRUE, (BOOL)(ULONG_PTR)transferred[3], NULL);
	HANDLE denied = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)(ULONG_PTR)transferred[0]);
	HANDLE unchanged = (HANDLE)(ULONG_PTR)0x1234;
	if (!denied || DuplicateHandle(GetCurrentProcess(), event, denied, &unchanged, EVENT_ALL_ACCESS, FALSE, 0) ||
		GetLastError() != ERROR_ACCESS_DENIED || unchanged != (HANDLE)(ULONG_PTR)0x1234 || !CloseHandle(denied)) return 163;
	DWORD access = transferred[3] ? EVENT_ALL_ACCESS : SYNCHRONIZE;
	if (!parent || !event || !DuplicateHandle(GetCurrentProcess(), event, parent, &sibling_handle,
		access, (BOOL)(ULONG_PTR)transferred[3], 0) || !CloseHandle(parent) || !CloseHandle(event)) return 161;
	if (!SetEvent(transferred[2]) || WaitForSingleObject(transferred[1], 10000) != WAIT_OBJECT_0) return 162;
	CloseHandle(transferred[1]);
	CloseHandle(transferred[2]);
	return 0;
}

static int sibling_transfers(void)
{
	query_process query = (query_process)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	STARTUPINFOW startup = {sizeof(startup)};
	PROCESS_INFORMATION child[2];
	WCHAR command[512];
	HANDLE gate[2], done[2], remote[2];
	ULONG_PTR image[2];
	SIZE_T copied;
	for (unsigned index = 0; index < 2; ++index) {
		command[0] = '"';
		DWORD used = GetModuleFileNameW(NULL, command + 1, 480);
		if (!query || !used || used >= 480) return 140;
		command[++used] = '"'; command[++used] = ' '; command[++used] = '-'; command[++used] = '-'; command[++used] = 's'; command[++used] = 0;
		gate[index] = CreateEventW(NULL, FALSE, FALSE, NULL);
		done[index] = CreateEventW(NULL, FALSE, FALSE, NULL);
		if (!gate[index] || !done[index] || !CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child[index])) return 141;
		HANDLE payload[4] = {(HANDLE)(ULONG_PTR)GetCurrentProcessId(), NULL, NULL, (HANDLE)(ULONG_PTR)(index == 0)};
		struct basic_information information;
		ULONG length;
		if (!DuplicateHandle(GetCurrentProcess(), gate[index], child[index].hProcess, &payload[1], SYNCHRONIZE, FALSE, 0) ||
			!DuplicateHandle(GetCurrentProcess(), done[index], child[index].hProcess, &payload[2], EVENT_MODIFY_STATE, FALSE, 0) ||
			query(child[index].hProcess, 0, &information, sizeof(information), &length) ||
			!ReadProcessMemory(child[index].hProcess, (BYTE *)information.peb + 2 * sizeof(void *), &image[index], sizeof(image[index]), &copied) ||
			!WriteProcessMemory(child[index].hProcess, (void *)(image[index] + (ULONG_PTR)&transferred - (ULONG_PTR)GetModuleHandleW(NULL)), payload, sizeof(payload), &copied) ||
			copied != sizeof(payload) || ResumeThread(child[index].hThread) != 1) return 142;
	}
	for (unsigned index = 0; index < 2; ++index) {
		if (!SetEvent(gate[index]) || WaitForSingleObject(done[index], 10000) != WAIT_OBJECT_0 ||
			!ReadProcessMemory(child[index].hProcess, (void *)(image[index] + (ULONG_PTR)&sibling_handle - (ULONG_PTR)GetModuleHandleW(NULL)),
				&remote[index], sizeof(remote[index]), &copied) || copied != sizeof(remote[index])) return 143;
	}
	if (!remote[0] || !remote[1] || remote[0] == remote[1]) return 144;
	DWORD first_flags, second_flags;
	if (!GetHandleInformation(remote[0], &first_flags) || !(first_flags & HANDLE_FLAG_INHERIT) ||
		!GetHandleInformation(remote[1], &second_flags) || (second_flags & HANDLE_FLAG_INHERIT)) return 145;
	if (WaitForSingleObject(remote[0], 0) != WAIT_OBJECT_0 || WaitForSingleObject(remote[0], 0) != WAIT_OBJECT_0 ||
		WaitForSingleObject(remote[1], 0) != WAIT_TIMEOUT || SetEvent(remote[1]) || GetLastError() != ERROR_ACCESS_DENIED ||
		!ResetEvent(remote[0]) || WaitForSingleObject(remote[0], 0) != WAIT_TIMEOUT || WaitForSingleObject(remote[1], 0) != WAIT_TIMEOUT) return 146;
	for (unsigned index = 0; index < 2; ++index) {
		DWORD code = STILL_ACTIVE;
		if (!CloseHandle(remote[index]) || !SetEvent(gate[index]) || WaitForSingleObject(child[index].hProcess, 10000) != WAIT_OBJECT_0 ||
			!GetExitCodeProcess(child[index].hProcess, &code) || code) return 147;
		CloseHandle(child[index].hThread);
		CloseHandle(child[index].hProcess);
		CloseHandle(gate[index]);
		CloseHandle(done[index]);
	}
	return 0;
}

static int closed_process_handles(void)
{
	query_process query = (query_process)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	STARTUPINFOW startup = {sizeof(startup)};
	PROCESS_INFORMATION child;
	struct basic_information information;
	WCHAR command[512];
	command[0] = '"';
	DWORD used = GetModuleFileNameW(NULL, command + 1, 480);
	if (!query || !used || used >= 480) return 120;
	command[++used] = '"'; command[++used] = ' '; command[++used] = '-'; command[++used] = '-'; command[++used] = 'd'; command[++used] = 0;
	HANDLE gate = CreateEventW(NULL, FALSE, FALSE, NULL), done = CreateEventW(NULL, FALSE, FALSE, NULL);
	DWORD baseline, held;
	if (!gate || !done || !GetProcessHandleCount(GetCurrentProcess(), &baseline) ||
		!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child)) return 121;
	HANDLE payload[3] = {(HANDLE)(ULONG_PTR)GetCurrentProcessId(), NULL, NULL};
	ULONG length;
	ULONG_PTR image;
	SIZE_T copied;
	if (!DuplicateHandle(GetCurrentProcess(), gate, child.hProcess, &payload[1], SYNCHRONIZE, FALSE, 0) ||
		!DuplicateHandle(GetCurrentProcess(), done, child.hProcess, &payload[2], EVENT_MODIFY_STATE, FALSE, 0) ||
		query(child.hProcess, 0, &information, sizeof(information), &length) ||
		!ReadProcessMemory(child.hProcess, (BYTE *)information.peb + 2 * sizeof(void *), &image, sizeof(image), &copied) ||
		!WriteProcessMemory(child.hProcess, (void *)(image + (ULONG_PTR)&transferred - (ULONG_PTR)GetModuleHandleW(NULL)), payload, sizeof(payload), &copied) ||
		copied != sizeof(payload) || ResumeThread(child.hThread) != 1) return 122;
	DWORD pid = child.dwProcessId;
	if (!CloseHandle(child.hThread) || !CloseHandle(child.hProcess) ||
		!GetProcessHandleCount(GetCurrentProcess(), &held) || held != baseline || !SetEvent(gate)) return 123;
	if (WaitForSingleObject(done, 10000) != WAIT_OBJECT_0) return 124;
	HANDLE reopened = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	DWORD code = STILL_ACTIVE;
	if (!reopened || !SetEvent(gate) || WaitForSingleObject(reopened, 10000) != WAIT_OBJECT_0 || !GetExitCodeProcess(reopened, &code) || code) return 125;
	if (!CloseHandle(reopened) || !CloseHandle(gate) || !CloseHandle(done)) return 126;
	return 0;
}

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	for (unsigned index = 0; line[index]; ++index)
		if (line[index] == '-' && line[index + 1] == '-' && line[index + 2] == 's')
			return sibling_child();
	for (unsigned index = 0; line[index]; ++index)
		if (line[index] == '-' && line[index + 1] == '-' && line[index + 2] == 'd')
			return detached_child();
	for (unsigned index = 0; line[index]; ++index)
		if (line[index] == '-' && line[index + 1] == '-' && line[index + 2] == 'c')
			return child_entry();
	const int extended = extended_events();
	if (extended) return extended;
	query_process query = (query_process)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	STARTUPINFOW startup = {0};
	PROCESS_INFORMATION child;
	struct basic_information information;
	WCHAR command[512];
	HANDLE ping = CreateEventExW(NULL, NULL, 0, SYNCHRONIZE | EVENT_MODIFY_STATE);
	HANDLE pong = CreateEventExA(NULL, NULL, 0, SYNCHRONIZE | EVENT_MODIFY_STATE);
	HANDLE manual = CreateEventExW(NULL, NULL, 3, EVENT_ALL_ACCESS), orphan = CreateEventExA(NULL, NULL, 2, EVENT_ALL_ACCESS);
	HANDLE mutex = CreateMutexW(NULL, TRUE, NULL);
	HANDLE sent[8], fetched = NULL, empty = NULL;
	HANDLE sources[8] = {ping, pong, manual, manual, manual, orphan, mutex, mutex};
	DWORD rights[8] = {SYNCHRONIZE | EVENT_MODIFY_STATE, SYNCHRONIZE | EVENT_MODIFY_STATE,
		SYNCHRONIZE | 1, 0, EVENT_MODIFY_STATE, SYNCHRONIZE, SYNCHRONIZE | 2, 0};
	DWORD used, code = 0;
	ULONG length;
	ULONG_PTR image;
	SIZE_T copied;
	int result = 0;
	startup.cb = sizeof(startup);
	command[0] = '"';
	used = GetModuleFileNameW(NULL, command + 1, 480);
	if (!query || !used || used >= 480 || !ping || !pong || !manual || !orphan || !mutex || WaitForSingleObject(mutex, 0) != WAIT_OBJECT_0)
		return 1;
	command[++used] = '"'; command[++used] = ' '; command[++used] = '-'; command[++used] = '-'; command[++used] = 'c'; command[++used] = 0;
	if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child))
		return 2;
	for (unsigned index = 0; index < 8; ++index)
		if (!DuplicateHandle(GetCurrentProcess(), sources[index], child.hProcess, &sent[index], rights[index], FALSE, 0)) {
			result = 3;
			goto done;
		}
	if (!DuplicateHandle(child.hProcess, sent[0], GetCurrentProcess(), &fetched, SYNCHRONIZE, FALSE, 0) ||
		SetEvent(fetched) || GetLastError() != ERROR_ACCESS_DENIED ||
		!DuplicateHandle(child.hProcess, sent[0], GetCurrentProcess(), &empty, 0, FALSE, 0) ||
		WaitForSingleObject(empty, 0) != WAIT_FAILED || GetLastError() != ERROR_ACCESS_DENIED) {
		result = 4;
		goto done;
	}
	if (query(child.hProcess, 0, &information, sizeof(information), &length) ||
		!ReadProcessMemory(child.hProcess, (BYTE *)information.peb + 2 * sizeof(void *), &image, sizeof(image), &copied) ||
		!WriteProcessMemory(child.hProcess, (void *)(image + (ULONG_PTR)&transferred - (ULONG_PTR)GetModuleHandleW(NULL)),
			sent, sizeof(sent), &copied) || copied != sizeof(sent)) {
		result = 5;
		goto done;
	}
	CloseHandle(orphan);
	orphan = NULL;
	if (ResumeThread(child.hThread) != 1 || WaitForSingleObject(pong, 10000) != WAIT_OBJECT_0 ||
		WaitForSingleObject(pong, 0) != WAIT_TIMEOUT || !ResetEvent(manual) || !ReleaseMutex(mutex) || !SetEvent(ping) ||
		WaitForSingleObject(pong, 10000) != WAIT_OBJECT_0 || WaitForSingleObject(manual, 0) != WAIT_OBJECT_0 ||
		WaitForSingleObject(manual, 0) != WAIT_OBJECT_0 || !ResetEvent(manual) || !ReleaseMutex(mutex) || !SetEvent(ping) ||
		WaitForSingleObject(pong, 10000) != WAIT_OBJECT_0 || WaitForSingleObject(mutex, 0) != WAIT_TIMEOUT || !SetEvent(ping) ||
		WaitForSingleObject(pong, 10000) != WAIT_OBJECT_0 || WaitForSingleObject(mutex, 10000) != WAIT_OBJECT_0 || !ReleaseMutex(mutex) ||
		WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0 || !GetExitCodeProcess(child.hProcess, &code) || code)
		result = code ? (int)code : 6;
done:
	if (result) {
		GetExitCodeProcess(child.hProcess, &code);
		if (code && code != STILL_ACTIVE) result = (int)code;
		TerminateProcess(child.hProcess, 99);
		WaitForSingleObject(child.hProcess, 5000);
	}
	if (fetched) CloseHandle(fetched);
	if (empty) CloseHandle(empty);
	if (orphan) CloseHandle(orphan);
	CloseHandle(ping);
	CloseHandle(pong);
	CloseHandle(manual);
	CloseHandle(mutex);
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	if (result) return result;
	const int closed = closed_process_handles();
	return closed ? closed : sibling_transfers();
}
