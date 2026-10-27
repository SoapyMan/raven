#include <windows.h>

// The Universal CRT entry points a larger program needs: file streams, descriptors, sorting, time formatting, math and jumps.
typedef struct { int sec, min, hour, mday, mon, year, wday, yday, isdst; } Tm;
extern void *fopen(const char *, const char *);
extern int fclose(void *);
extern size_t fread(void *, size_t, size_t, void *);
extern size_t fwrite(const void *, size_t, size_t, void *);
extern char *fgets(char *, int, void *);
extern int fseek(void *, long, int);
extern long ftell(void *);
extern int ungetc(int, void *);
extern int getc(void *);
extern int remove(const char *);
extern void qsort(void *, size_t, size_t, int (__cdecl *)(const void *, const void *));
extern size_t strftime(char *, size_t, const char *, const Tm *);
extern float powf(float, float);
extern float cosf(float);
extern float fmaxf(float, float);
extern float fminf(float, float);
extern long lroundf(float);
extern char *getenv(const char *);
extern int _open(const char *, int, ...);
extern int _read(int, void *, unsigned);
extern int _write(int, const void *, unsigned);
extern int _close(int);
extern long long _lseeki64(int, long long, int);
extern int __intrinsic_setjmp(void *, void *);
extern void longjmp(void *, int);
extern long long strtoll(const char *, char **, int);
extern int __stdio_common_vsnwprintf_s(unsigned long long, wchar_t *, size_t, size_t, const wchar_t *, void *, __builtin_va_list);
extern void *_aligned_malloc(size_t, size_t);
extern void _aligned_free(void *);
extern void free(void *);
struct time_of_day { long long seconds; long nanoseconds; };
extern int strcmp(const char *, const char *);
extern char *_mktemp(char *);
extern int *_errno(void);

static int temp_names(void)
{
	char names[26][32], exhausted[] = "crt-mktemp-XXXXXX", invalid[] = "crt-mktemp-XXXXX";
	for (int index = 0; index < 26; ++index) {
		lstrcpyA(names[index], "crt-mktemp-XXXXXX");
		if (_mktemp(names[index]) != names[index] || names[index][11] != 'a' + index ||
			GetFileAttributesA(names[index]) != INVALID_FILE_ATTRIBUTES) return 18;
		HANDLE file = CreateFileA(names[index], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) return 19;
		CloseHandle(file);
	}
	if (_mktemp(exhausted) || exhausted[0] || *_errno() != 17) return 20;
	for (int index = 0; index < 26; ++index)
		if (!DeleteFileA(names[index])) return 21;
	lstrcpyA(exhausted, "crt-mktemp-XXXXXX");
	if (_mktemp(exhausted) != exhausted || strcmp(exhausted, names[0])) return 22;
	if (_mktemp(invalid) || *_errno() != 22 || strcmp(invalid, "crt-mktemp-XXXXX")) return 23;
	if (_mktemp(NULL) || *_errno() != 22) return 24;
	return 0;
}

static int compare(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
static int __cdecl compare_context(void *context, const void *a, const void *b) { return compare(a, b); }
static int close_to(float value, float expected) { float d = value - expected; return d < 0.001f && d > -0.001f; }

int raven_entry(void)
{
	char line[64], big[64];
	void *file;
	int numbers[7] = {5, 3, 9, 1, 7, 2, 8}, fd;
	Tm when = {9, 7, 14, 5, 2, 124, 2, 64, 0};
	__attribute__((aligned(16))) char jump[256];
	volatile int reached = 0;
	void *block;
	size_t count;
	file = fopen("crt-io.txt", "w");
	if (!file || fwrite("alpha\nbeta\n", 1, 11, file) != 11 || fclose(file)) return 1;
	file = fopen("crt-io.txt", "rb");
	if (!file || (count = fread(big, 1, sizeof big, file)) != 13 || big[5] != '\r') return 2;
	fclose(file);
	file = fopen("crt-io.txt", "r");
	if (!file || !fgets(line, sizeof line, file) || strcmp(line, "alpha\n") || ftell(file) != 7) return 3;
	if (!fgets(line, sizeof line, file) || strcmp(line, "beta\n") || fgets(line, sizeof line, file)) return 4;
	if (fseek(file, 2, 0) || getc(file) != 'p' || ungetc('Q', file) != 'Q' || getc(file) != 'Q' || getc(file) != 'h') return 5;
	fclose(file);
	fd = _open("crt-io.txt", 0x8000);
	if (fd < 3 || _lseeki64(fd, 6, 0) != 6 || _read(fd, line, 5) != 5 || line[0] != '\n' || line[1] != 'b') return 6;
	_close(fd);
	if (remove("crt-io.txt") || fopen("crt-io.txt", "r")) return 7;
	qsort(numbers, 7, sizeof numbers[0], compare);
	for (int index = 1; index < 7; ++index)
		if (numbers[index - 1] > numbers[index]) return 8;
	if (!strftime(big, sizeof big, "%Y-%m-%d %H:%M:%S %a %b %j", &when) || strcmp(big, "2024-03-05 14:07:09 Tue Mar 065") != 0) return 9;
	if (powf(2.0f, 10.0f) < 1023.9f || powf(2.0f, 10.0f) > 1024.1f || powf(-2.0f, 3.0f) > -7.99f) return 10;
	if (!close_to(cosf(0.0f), 1.0f) || !close_to(cosf(3.14159265f), -1.0f) || !close_to(cosf(1.0f), 0.5403023f)) return 11;
	if (fmaxf(1.0f, 2.0f) != 2.0f || fminf(1.0f, 2.0f) != 1.0f || lroundf(2.5f) != 3 || lroundf(-2.5f) != -3) return 12;
	SetEnvironmentVariableA("RAVEN_CRT_PROBE", "value");
	if (!getenv("RAVEN_CRT_PROBE") || strcmp(getenv("RAVEN_CRT_PROBE"), "value") || getenv("RAVEN_CRT_ABSENT")) return 13;
	/* Older MinGW import libraries omit this UCRT export. */
	size_t (__cdecl *limited_length)(const char *, size_t) = (void *)GetProcAddress(GetModuleHandleA("ucrtbase.dll"), "strnlen");
	if (!limited_length || strtoll("-9223372036854775808", 0, 10) != (long long)0x8000000000000000ULL || limited_length("abcdef", 3) != 3) return 14;
	block = _aligned_malloc(100, 64);
	if (!block || ((unsigned long long)block & 63)) return 15;
	_aligned_free(block);
	if (!__intrinsic_setjmp(jump, 0)) {
		reached = 1;
		longjmp(jump, 7);
		return 16;
	}
	if (reached != 1) return 17;
	return temp_names();
}
