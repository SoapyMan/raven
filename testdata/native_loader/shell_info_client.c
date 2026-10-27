#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>

#define CHECK(code, condition) do { if (!(condition)) return code; } while (0)

static int same(const WCHAR *left, const WCHAR *right)
{
	unsigned i = 0;
	for (; left[i] || right[i]; ++i) if (left[i] != right[i]) return 0;
	return 1;
}

static void join(WCHAR *out, const WCHAR *left, const WCHAR *right)
{
	unsigned i = 0, j = 0;
	while (left[i]) { out[i] = left[i]; ++i; }
	while (right[j]) out[i++] = right[j++];
	out[i] = 0;
}

int raven_entry(void)
{
	WCHAR text[64];
	CHECK(1, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"1234567.891",0,text,64) == 13 && same(text,L"1,234,567.89"));
	CHECK(2, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"-0.005",0,text,64) && same(text,L"-0.01"));
	CHECK(3, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"999.999",0,0,0) == 9);
	NUMBERFMTW plain = {0,1,3,L".",L",",1};
	CHECK(4, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"300000",&plain,text,64) && same(text,L"300,000"));
	NUMBERFMTW indian = {1,0,32,L",",L".",0};
	CHECK(5, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"-12345678.25",&indian,text,64) && same(text,L"(1.23.45.678,3)"));
	CHECK(6, GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"0.5",&indian,text,64) && same(text,L",5"));
	SetLastError(0);
	CHECK(7, !GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"12a",0,text,64) && GetLastError() == ERROR_INVALID_PARAMETER);
	CHECK(8, !GetNumberFormatW(LOCALE_USER_DEFAULT,LOCALE_NOUSEROVERRIDE,L"1",&plain,text,64) && GetLastError() == ERROR_INVALID_FLAGS);
	CHECK(9, !GetNumberFormatW(LOCALE_USER_DEFAULT,0,L"123456",0,text,4) && GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	SHFILEINFOW info;
	CHECK(10, SHGetFileInfoW(L"C:\\nowhere\\notes.txt",FILE_ATTRIBUTE_NORMAL,&info,sizeof info,SHGFI_USEFILEATTRIBUTES | SHGFI_TYPENAME | SHGFI_DISPLAYNAME));
	CHECK(11, same(info.szTypeName,L"TXT File") && same(info.szDisplayName,L"notes.txt"));
	CHECK(12, SHGetFileInfoW(L"C:\\nowhere\\stuff",FILE_ATTRIBUTE_DIRECTORY,&info,sizeof info,SHGFI_USEFILEATTRIBUTES | SHGFI_TYPENAME | SHGFI_ATTRIBUTES));
	CHECK(13, same(info.szTypeName,L"File folder") && (info.dwAttributes & 0x20000000));
	CHECK(14, SHGetFileInfoW(L"README",FILE_ATTRIBUTE_NORMAL,&info,sizeof info,SHGFI_USEFILEATTRIBUTES | SHGFI_TYPENAME) && same(info.szTypeName,L"File"));
	CHECK(15, !SHGetFileInfoW(L"C:\\nowhere\\missing.txt",0,&info,sizeof info,SHGFI_TYPENAME));
	CHECK(16, SHGetFileInfoW(L"x.bin",FILE_ATTRIBUTE_NORMAL,&info,sizeof info,SHGFI_USEFILEATTRIBUTES | SHGFI_ICON | SHGFI_SMALLICON));
	if (info.hIcon) {
		ICONINFO icon;
		BITMAP bitmap;
		CHECK(17, GetIconInfo(info.hIcon,&icon) && GetObjectW(icon.hbmColor,sizeof bitmap,&bitmap) && bitmap.bmWidth == 16);
		DeleteObject(icon.hbmColor);
		DeleteObject(icon.hbmMask);
		CHECK(18, DestroyIcon(info.hIcon));
	}

	WCHAR temporary[260], root[260], path[260];
	CHECK(19, GetTempPathW(260,temporary));
	// A program that is not SYSTEM gets the same folder from GetTempPath2, which newer programs look up at run time.
	typedef DWORD (WINAPI *TempPath2W)(DWORD,LPWSTR);
	typedef DWORD (WINAPI *TempPath2A)(DWORD,LPSTR);
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	TempPath2W temp_path2w = (TempPath2W)GetProcAddress(kernel,"GetTempPath2W");
	TempPath2A temp_path2a = (TempPath2A)GetProcAddress(kernel,"GetTempPath2A");
	char narrow[260];
	CHECK(31, temp_path2w && temp_path2a && temp_path2w(260,path) == GetTempPathW(0,0) - 1 && same(path,temporary));
	CHECK(32, temp_path2a(260,narrow) == GetTempPathA(0,0) - 1 && narrow[0] == (char)temporary[0]);
	join(root,temporary,L"raven-change-notification");
	CreateDirectoryW(root,0);
	SetLastError(0);
	CHECK(20, FindFirstChangeNotificationW(root,FALSE,0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER);
	join(path,root,L"\\missing");
	CHECK(21, FindFirstChangeNotificationW(path,FALSE,FILE_NOTIFY_CHANGE_FILE_NAME) == INVALID_HANDLE_VALUE);
	HANDLE change = FindFirstChangeNotificationW(root,FALSE,FILE_NOTIFY_CHANGE_FILE_NAME);
	CHECK(22, change != INVALID_HANDLE_VALUE && WaitForSingleObject(change,0) == WAIT_TIMEOUT);
	join(path,root,L"\\created.txt");
	HANDLE file = CreateFileW(path,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	CHECK(23, file != INVALID_HANDLE_VALUE && CloseHandle(file));
	CHECK(24, WaitForSingleObject(change,5000) == WAIT_OBJECT_0);
	CHECK(25, FindNextChangeNotification(change) && WaitForSingleObject(change,0) == WAIT_TIMEOUT);
	CHECK(26, DeleteFileW(path) && WaitForMultipleObjects(1,&change,FALSE,5000) == WAIT_OBJECT_0);
	CHECK(27, FindCloseChangeNotification(change) && !FindCloseChangeNotification(change));
	CHECK(28, RemoveDirectoryW(root));

	CHECK(29, CoLockObjectExternal(0,TRUE,FALSE) == E_INVALIDARG);
	CHECK(30, CoLockObjectExternal((IUnknown *)&info,TRUE,FALSE) == S_OK && CoLockObjectExternal((IUnknown *)&info,FALSE,TRUE) == S_OK);
	return 0;
}
