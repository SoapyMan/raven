#include <windows.h>
#include <uxtheme.h>

/* Dark variants of visual styles as programs ask for them: a window given a "DarkMode_" application name hears that its theme changed,
   and the theme data its controls open then gives light text on dark parts, as a class list with that prefix does; taking the name
   away gives the light palette back. */

#define TMT_TEXTCOLOR 3803
#define BP_PUSHBUTTON 1
#define PBS_NORMAL 1

static int theme_changes;

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_THEMECHANGED)
		++theme_changes;
	return DefWindowProcW(window, message, wparam, lparam);
}

static COLORREF text_of(HWND window, const WCHAR *classes)
{
	HTHEME theme = OpenThemeData(window, classes);
	COLORREF color = CLR_INVALID;

	if (theme && GetThemeColor(theme, BP_PUSHBUTTON, PBS_NORMAL, TMT_TEXTCOLOR, &color) != S_OK)
		color = CLR_INVALID;
	if (theme)
		CloseThemeData(theme);
	return color;
}

int raven_entry(void)
{
	WNDCLASSW definition = {0};
	HWND window;
	COLORREF light;

	definition.lpfnWndProc = procedure;
	definition.lpszClassName = L"ThemeProbe";
	if (!RegisterClassW(&definition))
		return 1;
	window = CreateWindowExW(0, L"ThemeProbe", L"theme", WS_POPUP, 0, 0, 40, 20, NULL, NULL, NULL, NULL);
	if (!window)
		return 2;
	light = text_of(window, L"Button");
	if (light == CLR_INVALID || light == RGB(255, 255, 255))
		return 3;
	if (SetWindowTheme(window, L"DarkMode_Explorer", NULL) != S_OK || theme_changes != 1)
		return 4;
	if (text_of(window, L"Button") != RGB(255, 255, 255))
		return 5;
	if (text_of(NULL, L"DarkMode_Explorer::Button") != RGB(255, 255, 255) || text_of(NULL, L"Explorer::Button") != light)
		return 6;
	if (SetWindowTheme(window, NULL, NULL) != S_OK || theme_changes != 2 || text_of(window, L"Button") != light)
		return 7;
	DestroyWindow(window);
	return 0;
}
