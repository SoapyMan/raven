#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The integrity level of the process token agrees with its elevation: high for the full token of an elevated process, medium for the
 * limited one. */
int raven_entry(void)
{
	HANDLE token = NULL;
	BYTE buffer[64];
	DWORD size = 0;
	TOKEN_ELEVATION elevation = {0};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 1;
	if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) return 2;
	if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, sizeof(buffer), &size)) return 3;
	PSID label = ((TOKEN_MANDATORY_LABEL *)buffer)->Label.Sid;
	const DWORD level = *GetSidSubAuthority(label, *GetSidSubAuthorityCount(label) - 1);
	CloseHandle(token);
	if (level != (elevation.TokenIsElevated ? SECURITY_MANDATORY_HIGH_RID : SECURITY_MANDATORY_MEDIUM_RID)) return 4;
	return elevation.TokenIsElevated ? 0 : 10;
}
