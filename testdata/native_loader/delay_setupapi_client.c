#include <windows.h>
#include <setupapi.h>
#include <delayimp.h>

PfnDliHook __pfnDliNotifyHook2 = NULL;
PfnDliHook __pfnDliFailureHook2 = NULL;

static UINT CALLBACK visit(PVOID context, UINT notification, UINT_PTR first, UINT_PTR second)
{
	++*(int *)context;
	return NO_ERROR;
}

/* A program that loads the setup API only lazily, as large installers delay-load it, still extracts cabinets through it: a cabinet that
 * does not exist is refused without visiting any file. */
int raven_entry(void)
{
	int visited = 0;
	if (SetupIterateCabinetW(L"C:\\raven-missing.cab", 0, visit, &visited)) return 1;
	if (visited) return 2;
	return 0;
}
