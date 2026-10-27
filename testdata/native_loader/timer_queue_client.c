#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG once_count, periodic_count, changed_count, fired_value = -1;
static HANDLE once_done, periodic_done, changed_done;

static void CALLBACK once(void *parameter, BOOLEAN fired)
{
	fired_value = fired;
	InterlockedIncrement(&once_count);
	SetEvent(once_done);
}

static void CALLBACK periodic(void *parameter, BOOLEAN fired)
{
	if (InterlockedIncrement(&periodic_count) == 3)
		SetEvent(periodic_done);
}

static void CALLBACK changed(void *parameter, BOOLEAN fired)
{
	InterlockedIncrement(&changed_count);
	SetEvent(changed_done);
}

/* Timer queues as services schedule their work with them: a timer of its own queue runs once, a periodic timer of the default queue
 * keeps running until it is deleted and not after, a far timer brought forward runs, a timer runs for a thread that only polls, and
 * deleting a queue sets the event it names. */
static volatile LONG pool_runs;

static void CALLBACK pool_work(PTP_CALLBACK_INSTANCE instance, void *parameter, PTP_WORK work)
{
	Sleep(20);
	InterlockedIncrement(&pool_runs);
}

/* A private pool with a cleanup group: closing the group's members lets their submitted callbacks finish and frees the work items. */
static int private_pool(void)
{
	PTP_POOL pool = CreateThreadpool(NULL);
	if (!pool) return 20;
	SetThreadpoolThreadMaximum(pool, 2);
	if (!SetThreadpoolThreadMinimum(pool, 1)) return 21;
	PTP_CLEANUP_GROUP group = CreateThreadpoolCleanupGroup();
	if (!group) return 22;
	TP_CALLBACK_ENVIRON environment;
	InitializeThreadpoolEnvironment(&environment);
	SetThreadpoolCallbackPool(&environment, pool);
	SetThreadpoolCallbackCleanupGroup(&environment, group, NULL);
	PTP_WORK first = CreateThreadpoolWork(pool_work, NULL, &environment), second = CreateThreadpoolWork(pool_work, NULL, &environment);
	if (!first || !second) return 23;
	SubmitThreadpoolWork(first);
	SubmitThreadpoolWork(second);
	SubmitThreadpoolWork(first);
	CloseThreadpoolCleanupGroupMembers(group, FALSE, NULL);
	if (pool_runs != 3) return 24;
	CloseThreadpoolCleanupGroup(group);
	CloseThreadpool(pool);
	return 0;
}

int raven_entry(void)
{
	HANDLE queue = CreateTimerQueue(), first = NULL, repeating = NULL, distant = NULL;
	once_done = CreateEventW(NULL, TRUE, FALSE, NULL);
	periodic_done = CreateEventW(NULL, TRUE, FALSE, NULL);
	changed_done = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!queue || !once_done || !periodic_done || !changed_done) return 1;
	if (CreateTimerQueueTimer(&first, queue, NULL, NULL, 10, 0, 0) || GetLastError() != ERROR_INVALID_PARAMETER) return 2;
	if (!CreateTimerQueueTimer(&first, queue, once, NULL, 20, 0, WT_EXECUTEDEFAULT) || !first) return 3;
	if (WaitForSingleObject(once_done, 5000) != WAIT_OBJECT_0 || fired_value != TRUE) return 4;
	if (!CreateTimerQueueTimer(&repeating, NULL, periodic, NULL, 10, 10, 0)) return 5;
	if (WaitForSingleObject(periodic_done, 5000) != WAIT_OBJECT_0) return 6;
	if (!DeleteTimerQueueTimer(NULL, repeating, INVALID_HANDLE_VALUE)) return 7;
	const LONG stopped = periodic_count;
	Sleep(80);
	if (periodic_count != stopped) return 8;
	if (!CreateTimerQueueTimer(&distant, queue, changed, NULL, 600000, 0, 0) || !ChangeTimerQueueTimer(queue, distant, 10, 0)) return 9;
	if (WaitForSingleObject(changed_done, 5000) != WAIT_OBJECT_0 || changed_count != 1) return 10;
	Sleep(40);
	if (once_count != 1 || changed_count != 1) return 11;
	/* A thread that only polls with a zero timeout still sees a due timer start its callback. */
	HANDLE polled = NULL;
	ResetEvent(changed_done);
	if (!CreateTimerQueueTimer(&polled, queue, changed, NULL, 10, 0, 0)) return 13;
	const ULONGLONG until = GetTickCount64() + 5000;
	while (WaitForSingleObject(changed_done, 0) == WAIT_TIMEOUT)
		if (GetTickCount64() > until) return 14;
	if (changed_count != 2) return 15;
	HANDLE deleted = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!DeleteTimerQueueEx(queue, deleted) || WaitForSingleObject(deleted, 5000) != WAIT_OBJECT_0) return 12;
	return private_pool();
}
