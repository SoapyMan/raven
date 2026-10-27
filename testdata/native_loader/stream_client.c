#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <objidl.h>
#include <oleauto.h>

typedef HRESULT (WINAPI *create_function)(HGLOBAL, BOOL, IStream **);
typedef HRESULT (WINAPI *memory_function)(IStream *, HGLOBAL *);

/* Streams over global memory, with ole32 loaded only at run time as a console program that imports just automation does: a stream made
 * without memory grows as it is written, a clone shares the bytes with its own position, a stream over given memory starts as long as that
 * memory, and only these streams hand back their memory. */
int raven_entry(void)
{
	if (SysStringLen(NULL)) return 20;
	HMODULE ole = LoadLibraryW(L"ole32.dll");
	create_function CreateStreamOnHGlobal = ole ? (create_function)GetProcAddress(ole, "CreateStreamOnHGlobal") : NULL;
	memory_function GetHGlobalFromStream = ole ? (memory_function)GetProcAddress(ole, "GetHGlobalFromStream") : NULL;
	if (!CreateStreamOnHGlobal || !GetHGlobalFromStream) return 21;
	IStream *stream = NULL, *clone = NULL;
	HGLOBAL memory = NULL;
	LARGE_INTEGER start = {{0, 0}};
	ULARGE_INTEGER at;
	STATSTG stat;
	char text[16];
	ULONG done = 0;
	if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK || !stream) return 1;
	if (IStream_Write(stream, "Hello, world", 12, &done) != S_OK || done != 12) return 2;
	if (IStream_Stat(stream, &stat, STATFLAG_NONAME) != S_OK || stat.cbSize.QuadPart != 12) return 3;
	if (IStream_Clone(stream, &clone) != S_OK || IStream_Seek(clone, start, STREAM_SEEK_SET, &at) != S_OK || at.QuadPart) return 4;
	if (IStream_Read(clone, text, sizeof text, &done) != S_OK || done != 12 || text[7] != 'w') return 5;
	if (IStream_Write(stream, "!", 1, NULL) != S_OK || IStream_Read(clone, text, 4, &done) != S_OK || done != 1 || text[0] != '!') return 6;
	if (GetHGlobalFromStream(clone, &memory) != S_OK || !memory || GlobalSize(memory) < 13) return 7;
	char *bytes = GlobalLock(memory);
	if (!bytes || bytes[0] != 'H' || bytes[12] != '!') return 8;
	GlobalUnlock(memory);
	IStream_Release(clone);
	IStream_Release(stream);
	memory = GlobalAlloc(GMEM_MOVEABLE, 5);
	bytes = GlobalLock(memory);
	for (int index = 0; index < 5; ++index) bytes[index] = "abcde"[index];
	GlobalUnlock(memory);
	if (CreateStreamOnHGlobal(memory, FALSE, &stream) != S_OK || IStream_Stat(stream, &stat, STATFLAG_NONAME) != S_OK || stat.cbSize.QuadPart < 5) return 9;
	if (IStream_Read(stream, text, 5, &done) != S_OK || done != 5 || text[4] != 'e') return 10;
	IStream_Release(stream);
	if (GlobalFree(memory)) return 11;
	if (GetHGlobalFromStream(NULL, &memory) != E_INVALIDARG || CreateStreamOnHGlobal(NULL, TRUE, NULL) != E_INVALIDARG) return 12;
	return 0;
}
