#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <oleacc.h>

typedef HRESULT (WINAPI *initialize_function)(void *, DWORD);
typedef HRESULT (WINAPI *create_function)(REFCLSID, IUnknown *, DWORD, REFIID, void **);
typedef void (WINAPI *free_function)(void *);
typedef void (WINAPI *uninitialize_function)(void);

/* The annotation services through COM, with ole32 loaded only at run time as a console program that imports just automation does:
 * identity strings round-trip, properties are set, replaced and cleared, and a string of one kind does not decompose as the other. */
int raven_entry(void)
{
	HMODULE ole = LoadLibraryW(L"ole32.dll");
	if (!ole) return 20;
	initialize_function CoInitializeEx = (initialize_function)GetProcAddress(ole, "CoInitializeEx");
	create_function CoCreateInstance = (create_function)GetProcAddress(ole, "CoCreateInstance");
	free_function CoTaskMemFree = (free_function)GetProcAddress(ole, "CoTaskMemFree");
	uninitialize_function CoUninitialize = (uninitialize_function)GetProcAddress(ole, "CoUninitialize");
	if (!CoInitializeEx || !CoCreateInstance || !CoTaskMemFree || !CoUninitialize) return 21;
	IAccPropServices *services = NULL;
	BYTE *identity = NULL;
	DWORD length = 0, object = 0, child = 0;
	HWND window = NULL;
	HMENU menu = NULL;
	VARIANT value;
	if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
	if (CoCreateInstance(&CLSID_AccPropServices, NULL, CLSCTX_INPROC_SERVER, &IID_IAccPropServices, (void **)&services) != S_OK || !services)
		return 2;
	if (IAccPropServices_ComposeHwndIdentityString(services, (HWND)0x1234, OBJID_CLIENT, 7, &identity, &length) != S_OK || !identity || !length)
		return 3;
	if (IAccPropServices_DecomposeHwndIdentityString(services, identity, length, &window, &object, &child) != S_OK || window != (HWND)0x1234 ||
		object != (DWORD)OBJID_CLIENT || child != 7) return 4;
	if (IAccPropServices_DecomposeHmenuIdentityString(services, identity, length, &menu, &child) != E_INVALIDARG) return 5;
	VariantInit(&value);
	value.vt = VT_I4;
	value.lVal = ROLE_SYSTEM_PUSHBUTTON;
	if (IAccPropServices_SetPropValue(services, identity, length, PROPID_ACC_ROLE, value) != S_OK) return 6;
	if (IAccPropServices_SetHwndPropStr(services, (HWND)0x1234, OBJID_CLIENT, 7, PROPID_ACC_NAME, L"Install") != S_OK) return 7;
	if (IAccPropServices_SetHwndPropStr(services, (HWND)0x1234, OBJID_CLIENT, 7, PROPID_ACC_NAME, L"Close") != S_OK) return 8;
	MSAAPROPID cleared[] = {PROPID_ACC_NAME, PROPID_ACC_ROLE};
	if (IAccPropServices_ClearHwndProps(services, (HWND)0x1234, OBJID_CLIENT, 7, cleared, 2) != S_OK) return 9;
	if (IAccPropServices_SetHwndPropStr(services, NULL, OBJID_CLIENT, 7, PROPID_ACC_NAME, L"x") != E_INVALIDARG) return 10;
	CoTaskMemFree(identity);
	if (IAccPropServices_ComposeHmenuIdentityString(services, (HMENU)0x88, 3, &identity, &length) != S_OK ||
		IAccPropServices_DecomposeHmenuIdentityString(services, identity, length, &menu, &child) != S_OK || menu != (HMENU)0x88 || child != 3)
		return 11;
	CoTaskMemFree(identity);
	if (IAccPropServices_Release(services)) return 12;
	CoUninitialize();
	return 0;
}
