#include <windows.h>
#include <richedit.h>

/* Rich edit controls used as labels: one made with WS_EX_TRANSPARENT paints only its text over what lies behind it, while an ordinary
   one fills its background with the window colour. Each prints its client area into a bitmap filled green first. */

#define BACKGROUND RGB(0, 128, 0)

static COLORREF painted(HWND edit, HDC memory)
{
	RECT all = {0, 0, 200, 40};
	HBRUSH green = CreateSolidBrush(BACKGROUND);
	COLORREF pixel;

	FillRect(memory, &all, green);
	DeleteObject(green);
	SendMessageW(edit, WM_PRINTCLIENT, (WPARAM)memory, PRF_CLIENT);
	/* Past the end of the short text, and below it. */
	pixel = GetPixel(memory, 150, 10);
	if (GetPixel(memory, 150, 30) != pixel)
		return CLR_INVALID;
	return pixel;
}

int raven_entry(void)
{
	HDC screen, memory;
	HBITMAP bitmap;
	HWND parent, transparent, opaque;

	if (!LoadLibraryW(L"riched20.dll"))
		return 1;
	parent = CreateWindowExW(0, L"STATIC", L"panel", WS_POPUP, 0, 0, 200, 80, NULL, NULL, NULL, NULL);
	transparent = CreateWindowExW(WS_EX_TRANSPARENT, L"RichEdit20W", L"label", WS_CHILD | ES_READONLY, 0, 0, 200, 40, parent, NULL, NULL, NULL);
	opaque = CreateWindowExW(0, L"RichEdit20W", L"label", WS_CHILD | ES_READONLY, 0, 40, 200, 40, parent, NULL, NULL, NULL);
	if (!parent || !transparent || !opaque)
		return 2;
	screen = GetDC(NULL);
	memory = CreateCompatibleDC(screen);
	bitmap = CreateCompatibleBitmap(screen, 200, 40);
	ReleaseDC(NULL, screen);
	if (!memory || !bitmap)
		return 3;
	SelectObject(memory, bitmap);
	if (painted(transparent, memory) != BACKGROUND)
		return 4;
	if (painted(opaque, memory) != GetSysColor(COLOR_WINDOW))
		return 5;
	DestroyWindow(parent);
	DeleteDC(memory);
	DeleteObject(bitmap);
	return 0;
}
