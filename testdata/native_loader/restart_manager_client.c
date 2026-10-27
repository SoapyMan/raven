#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <restartmanager.h>

/* The Restart Manager as an installer uses it before replacing files: a session with its key, files registered, nobody holding them,
 * nothing to shut down, and a session that ends once. */
int raven_entry(void)
{
	DWORD session = 0xdead, joined = 0xdead;
	WCHAR key[CCH_RM_SESSION_KEY + 1] = {0};
	if (RmStartSession(&session, 0, key) != ERROR_SUCCESS || session == 0xdead || lstrlenW(key) != CCH_RM_SESSION_KEY) return 1;
	if (RmJoinSession(&joined, key) != ERROR_SUCCESS || joined == session) return 2;
	LPCWSTR files[] = {L"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe"};
	if (RmRegisterResources(session, 1, files, 0, NULL, 0, NULL) != ERROR_SUCCESS) return 3;
	UINT needed = 7, count = 0;
	DWORD reasons = 7;
	if (RmGetList(session, &needed, &count, NULL, &reasons) != ERROR_SUCCESS || needed || count || reasons != RmRebootReasonNone) return 4;
	if (RmShutdown(session, RmForceShutdown, NULL) != ERROR_SUCCESS || RmRestart(session, 0, NULL) != ERROR_SUCCESS) return 5;
	if (RmEndSession(joined) != ERROR_SUCCESS || RmEndSession(session) != ERROR_SUCCESS) return 6;
	if (RmEndSession(session) != ERROR_INVALID_HANDLE || RmGetList(session, &needed, &count, NULL, &reasons) != ERROR_INVALID_HANDLE) return 7;
	return 0;
}
