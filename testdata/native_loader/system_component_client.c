#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <mscat.h>

// A library the runtime ships is a file in the system directory, as installers that check their dependencies expect: it is found by
// SearchPathW, readable through CreateFileW, and hashed by the catalog administrator, which finds no catalog that lists it.

static int same(const BYTE *left, const BYTE *right, unsigned size)
{
	for (unsigned index = 0; index < size; ++index)
		if (left[index] != right[index]) return 0;
	return 1;
}

int raven_entry(void)
{
	WCHAR path[MAX_PATH];
	WCHAR *file_part = NULL;
	const DWORD length = SearchPathW(NULL, L"gdiplus.dll", NULL, MAX_PATH, path, &file_part);
	if (!length || length >= MAX_PATH || !file_part) return 1;
	if (GetFileAttributesW(L"C:\\Windows\\System32\\gdiplus.dll") == INVALID_FILE_ATTRIBUTES) return 2;
	HANDLE library = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (library == INVALID_HANDLE_VALUE) return 3;
	char header[2];
	DWORD read = 0;
	if (!ReadFile(library, header, sizeof(header), &read, NULL) || read != 2 || header[0] != 'M' || header[1] != 'Z') return 4;

	HCATADMIN admin = NULL;
	if (!CryptCATAdminAcquireContext(&admin, NULL, 0) || !admin) return 5;
	BYTE hash[32];
	DWORD size = 0;
	if (CryptCATAdminCalcHashFromFileHandle(library, &size, NULL, 0) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || size != 20) return 6;
	if (!CryptCATAdminCalcHashFromFileHandle(library, &size, hash, 0) || size != 20) return 7;
	// The hash reads the file from its start and leaves the handle where it was.
	if (SetFilePointer(library, 0, NULL, FILE_CURRENT) != 2) return 8;
	SetLastError(0);
	if (CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, NULL) || GetLastError() != ERROR_NOT_FOUND) return 9;
	CloseHandle(library);

	// A file that is not a program is hashed whole: SHA-1 of "abc".
	static const BYTE abc_sha1[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
	HANDLE text = CreateFileW(L"C:\\catalog-probe.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;
	if (text == INVALID_HANDLE_VALUE || !WriteFile(text, "abc", 3, &written, NULL) || written != 3) return 10;
	size = sizeof(hash);
	if (!CryptCATAdminCalcHashFromFileHandle(text, &size, hash, 0) || size != 20 || !same(hash, abc_sha1, 20)) return 11;
	CloseHandle(text);
	DeleteFileW(L"C:\\catalog-probe.txt");
	if (!CryptCATAdminReleaseContext(admin, 0)) return 12;
	return 0;
}
