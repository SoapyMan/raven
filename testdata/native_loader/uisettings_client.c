#define WIN32_LEAN_AND_MEAN
#define INITGUID
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <winstring.h>
#include <activation.h>
#include <windows.ui.viewmanagement.h>

typedef HRESULT (WINAPI *initialize_function)(int);
typedef HRESULT (WINAPI *activate_function)(HSTRING, IInspectable **);

/* The string header programs built with C++/WinRT write themselves for a reference: flags, length, two unused words, the characters. */
struct reference {
	UINT32 flags, length, unused[2];
	const WCHAR *text;
};

/* The UI settings class through the Windows Runtime, as Office asks it while it starts: activated by name, it answers the light
 * theme's colours and the default accent, a text scale of one, the system's double-click time and the window colour, and takes a
 * handler for a change it never raises. */
int raven_entry(void)
{
	static const WCHAR name[] = L"Windows.UI.ViewManagement.UISettings";
	HMODULE runtime = LoadLibraryW(L"combase.dll");
	initialize_function RoInitialize = runtime ? (initialize_function)GetProcAddress(runtime, "RoInitialize") : NULL;
	activate_function RoActivateInstance = runtime ? (activate_function)GetProcAddress(runtime, "RoActivateInstance") : NULL;
	if (!RoInitialize || !RoActivateInstance) return 20;
	if (FAILED(RoInitialize(1))) return 1;
	struct reference class_name = {1, ARRAYSIZE(name) - 1, {0, 0}, name};
	IInspectable *object = NULL;
	if (RoActivateInstance((HSTRING)&class_name, &object) != S_OK || !object) return 2;
	__x_ABI_CWindows_CUI_CViewManagement_CIUISettings *one = NULL;
	__x_ABI_CWindows_CUI_CViewManagement_CIUISettings2 *two = NULL;
	__x_ABI_CWindows_CUI_CViewManagement_CIUISettings3 *three = NULL;
	if (FAILED(IInspectable_QueryInterface(object, &IID___x_ABI_CWindows_CUI_CViewManagement_CIUISettings, (void **)&one))) return 3;
	if (FAILED(IInspectable_QueryInterface(object, &IID___x_ABI_CWindows_CUI_CViewManagement_CIUISettings2, (void **)&two))) return 4;
	if (FAILED(IInspectable_QueryInterface(object, &IID___x_ABI_CWindows_CUI_CViewManagement_CIUISettings3, (void **)&three))) return 5;
	__x_ABI_CWindows_CUI_CColor color;
	if (FAILED(three->lpVtbl->GetColorValue(three, UIColorType_Background, &color)) || color.A != 255 || color.R != 255 || color.B != 255)
		return 6;
	if (FAILED(three->lpVtbl->GetColorValue(three, UIColorType_Accent, &color)) || color.R != 0 || color.G != 0x78 || color.B != 0xd7)
		return 7;
	DOUBLE scale = 0;
	if (FAILED(two->lpVtbl->get_TextScaleFactor(two, &scale)) || scale != 1.0) return 8;
	UINT32 time = 0;
	if (FAILED(one->lpVtbl->get_DoubleClickTime(one, &time)) || time != GetDoubleClickTime()) return 9;
	const COLORREF window = GetSysColor(COLOR_WINDOW);
	if (FAILED(one->lpVtbl->UIElementColor(one, UIElementType_Window, &color)) || color.R != GetRValue(window) || color.B != GetBValue(window))
		return 10;
	EventRegistrationToken token = {0};
	if (FAILED(three->lpVtbl->add_ColorValuesChanged(three, (void *)object, &token)) || !token.value) return 11;
	if (FAILED(three->lpVtbl->remove_ColorValuesChanged(three, token))) return 12;
	three->lpVtbl->Release(three);
	two->lpVtbl->Release(two);
	one->lpVtbl->Release(one);
	IInspectable_Release(object);
	return 0;
}
