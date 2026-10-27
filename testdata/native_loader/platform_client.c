/* Host services: known folders, the computer name, network adapters, data protection, security checks and job objects. */
#define INITGUID
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define PSAPI_VERSION 2
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <sddl.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <psapi.h>

static void clear(void *memory, int length)
{
	unsigned char *bytes = memory;
	int index;
	for (index = 0; index < length; ++index)
		bytes[index] = 0;
}

static int same(const void *left, const void *right, int length)
{
	const unsigned char *a = left, *b = right;
	int index;
	for (index = 0; index < length; ++index)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static int contains_narrow(const char *text, char part)
{
	for (; *text; ++text)
		if (*text == part)
			return 1;
	return 0;
}

static int contains(const WCHAR *text, const WCHAR *part)
{
	int at, index;
	for (at = 0; text[at]; ++at) {
		for (index = 0; part[index] && text[at + index] == part[index]; ++index)
			;
		if (!part[index])
			return 1;
	}
	return 0;
}

int raven_entry(void)
{
	{
		const UINT requested[] = {CP_ACP, CP_OEMCP, CP_THREAD_ACP, 1252, 437, 850, 28591, 20127, CP_UTF8};
		for (UINT index = 0; index < sizeof(requested) / sizeof(requested[0]); ++index) {
			CPINFO plain;
			CPINFOEXA ansi;
			CPINFOEXW wide;
			UINT page = requested[index] == CP_OEMCP ? GetOEMCP() :
				requested[index] == CP_ACP || requested[index] == CP_THREAD_ACP ? GetACP() : requested[index];
			if (!GetCPInfo(requested[index], &plain) || !GetCPInfoExA(requested[index], 0, &ansi) ||
				!GetCPInfoExW(requested[index], 0, &wide) || ansi.CodePage != page || wide.CodePage != page ||
				wide.MaxCharSize != plain.MaxCharSize || ansi.MaxCharSize != plain.MaxCharSize ||
				wide.MaxCharSize != (page == CP_UTF8 ? 4 : 1) || wide.DefaultChar[0] != plain.DefaultChar[0] ||
				wide.UnicodeDefaultChar != L'?' || !wide.CodePageName[0]) return 160;
			for (UINT character = 0; character < MAX_PATH; ++character) {
				if ((BYTE)ansi.CodePageName[character] != wide.CodePageName[character]) return 161;
				if (!ansi.CodePageName[character]) break;
				if (character == MAX_PATH - 1) return 162;
			}
		}
		CPINFOEXW sentinel;
		BYTE *bytes = (BYTE *)&sentinel;
		for (UINT index = 0; index < sizeof(sentinel); ++index) bytes[index] = 0x5a;
		if (GetCPInfoExW(0x7fffffff, 0, &sentinel) || GetLastError() != ERROR_INVALID_PARAMETER ||
			GetCPInfoExW(CP_UTF8, 1, &sentinel) || GetLastError() != ERROR_INVALID_PARAMETER ||
			GetCPInfoExW(CP_UTF8, 0, NULL) || GetLastError() != ERROR_INVALID_PARAMETER) return 163;
		for (UINT index = 0; index < sizeof(sentinel); ++index) if (bytes[index] != 0x5a) return 164;
	}
	{
		DWORD needed = 0, repeated = 0, found = 0;
		if (!K32EnumProcessModules(GetCurrentProcess(), NULL, 0, &needed) || needed < 3 * sizeof(HMODULE)) return 150;
		HMODULE *modules = HeapAlloc(GetProcessHeap(), 0, needed);
		if (!modules || !K32EnumProcessModulesEx(GetCurrentProcess(), modules, needed, &repeated, LIST_MODULES_ALL) ||
			repeated != needed || modules[0] != GetModuleHandleW(NULL)) return 151;
		for (DWORD index = 0; index < needed / sizeof(HMODULE); ++index) {
			if (modules[index] == GetModuleHandleW(L"ntdll.dll")) found |= 1;
			if (modules[index] == GetModuleHandleW(L"kernel32.dll")) {
				MODULEINFO info;
				WCHAR name[64];
				if (!K32GetModuleBaseNameW(GetCurrentProcess(), modules[index], name, 64) ||
					!K32GetModuleInformation(GetCurrentProcess(), modules[index], &info, sizeof(info)) ||
					info.lpBaseOfDll != modules[index] || !info.SizeOfImage ||
					!GetProcAddress(modules[index], "SetThreadErrorMode")) return 152;
				found |= 2;
			}
		}
		if (found != 3 || !HeapFree(GetProcessHeap(), 0, modules)) return 153;
	}
	{
		char ansi[128];
		WCHAR wide[128];
		DWORD mask = GetLogicalDrives(), seen = 0, expected = 0, index, letter;
		for (letter = 0; letter < 26; ++letter) if (mask & (1u << letter)) expected += 4;
		if (!(mask & (1u << 2)) || !(mask & (1u << 25)) || GetLogicalDriveStringsA(0, NULL) != expected + 1 ||
			GetLogicalDriveStringsW(0, NULL) != expected + 1 || expected + 1 > sizeof(ansi)) return 50;
		for (index = 0; index < sizeof(ansi); ++index) ansi[index] = 0x5a;
		if (GetLogicalDriveStringsA(expected, ansi) != expected + 1) return 51;
		for (index = 0; index < sizeof(ansi); ++index) if (ansi[index] != 0x5a) return 52;
		if (GetLogicalDriveStringsA(expected + 1, ansi) != expected || GetLogicalDriveStringsW(128, wide) != expected ||
			ansi[expected] || wide[expected] || ansi[expected + 1] != 0x5a) return 53;
		for (index = 0; index < expected; ++index) if ((BYTE)ansi[index] != wide[index]) return 54;
		for (index = 0; index < expected; index += 4) {
			if (ansi[index] < 'A' || ansi[index] > 'Z' || ansi[index + 1] != ':' || ansi[index + 2] != '\\' || ansi[index + 3]) return 55;
			seen |= 1u << (ansi[index] - 'A');
		}
		if (seen != mask) return 56;
	}
	WCHAR *folder = NULL, name[64];
	DWORD size, error;
	IP_ADAPTER_ADDRESSES *adapters, *adapter;
	ULONG needed = 0;
	DATA_BLOB plain = {5, (BYTE *)"token"}, sealed, opened, entropy = {3, (BYTE *)"abc"}, wrong = {3, (BYTE *)"xyz"};
	LPWSTR description = NULL;
	HANDLE job, token = NULL, copy = NULL;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits, queried;
	BOOL inside = TRUE;
	DWORD mask;
	GENERIC_MAPPING mapping = {1, 2, 4, 7};
	int loopback = 0;
	PSID everyone = NULL;

	if (SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, &folder) != S_OK || !folder || !contains(folder, L"AppData\\Roaming"))
		return 1;
	CoTaskMemFree(folder);
	if (SHGetKnownFolderPath(&FOLDERID_ProgramFilesX86, 0, NULL, &folder) != S_OK || !contains(folder, L"Program Files (x86)"))
		return 2;
	CoTaskMemFree(folder);

	size = 64;
	if (!GetComputerNameExW(ComputerNameDnsHostname, name, &size) || size == 0 || name[0] == 0)
		return 3;
	size = 1;
	if (GetComputerNameExW(ComputerNameDnsHostname, name, &size) || GetLastError() != ERROR_MORE_DATA || size < 2)
		return 4;

	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &needed) != ERROR_BUFFER_OVERFLOW || needed < sizeof(IP_ADAPTER_ADDRESSES))
		return 5;
	adapters = HeapAlloc(GetProcessHeap(), 0, needed);
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &needed) != NO_ERROR)
		return 6;
	for (adapter = adapters; adapter; adapter = adapter->Next)
		if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK && adapter->FirstUnicastAddress && adapter->FirstUnicastAddress->Address.lpSockaddr &&
			adapter->FirstUnicastAddress->Address.iSockaddrLength >= 16)
			loopback = 1;
	if (!loopback)
		return 7;
	HeapFree(GetProcessHeap(), 0, adapters);
	/* The IPv4 list leaves loopback out: a host with only loopback has no data, any other adapter has a dotted address and mask. */
	needed = 0;
	error = GetAdaptersInfo(NULL, &needed);
	if (error == ERROR_BUFFER_OVERFLOW) {
		IP_ADAPTER_INFO *infos = HeapAlloc(GetProcessHeap(), 0, needed), *info;
		if (!infos || GetAdaptersInfo(infos, &needed) != NO_ERROR)
			return 60;
		for (info = infos; info; info = info->Next)
			if (info->Type == MIB_IF_TYPE_LOOPBACK || info->AdapterName[0] != '{' || !info->IpAddressList.IpAddress.String[0] ||
				!contains_narrow(info->IpAddressList.IpMask.String, '.') || !contains_narrow(info->GatewayList.IpAddress.String, '.'))
				return 61;
		HeapFree(GetProcessHeap(), 0, infos);
	} else if (error != ERROR_NO_DATA)
		return 62;
	if (GetAdaptersInfo(NULL, NULL) != ERROR_INVALID_PARAMETER)
		return 63;

	if (!CryptProtectData(&plain, L"note", &entropy, NULL, NULL, 0, &sealed) || sealed.cbData <= plain.cbData)
		return 8;
	if (!CryptUnprotectData(&sealed, &description, &entropy, NULL, NULL, 0, &opened) || opened.cbData != 5 || !same(opened.pbData, "token", 5) ||
		!description || description[0] != 'n' || description[3] != 'e')
		return 9;
	LocalFree(description);
	LocalFree(opened.pbData);
	if (CryptUnprotectData(&sealed, NULL, &wrong, NULL, NULL, 0, &opened))
		return 10;
	LocalFree(sealed.pbData);

	/* Account checks: the generic rights of a mask become specific ones, and the descriptor decides the rest. */
	mask = GENERIC_READ | GENERIC_WRITE;
	MapGenericMask(&mask, &mapping);
	if (mask != 3)
		return 11;
	if (!ConvertStringSidToSidW(L"WD", &everyone))
		return 12;
	{
		SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
		PSID expected = NULL;
		if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &expected) || !EqualSid(everyone, expected))
			return 13;
		FreeSid(expected);
	}
	LocalFree(everyone);

	/* Jobs keep the limits the program sets. */
	job = CreateJobObjectW(NULL, NULL);
	if (!job)
		return 14;
	clear(&limits, sizeof(limits));
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	limits.BasicLimitInformation.ActiveProcessLimit = 5;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
		return 15;
	clear(&queried, sizeof(queried));
	if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &queried, sizeof(queried), NULL) ||
		queried.BasicLimitInformation.ActiveProcessLimit != 5 || !(queried.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE))
		return 16;
	if (!IsProcessInJob(GetCurrentProcess(), job, &inside) || inside)
		return 17;
	CloseHandle(job);

	/* Tokens copy. */
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
		return 18;
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &copy) || !copy)
		return 19;
	{
		DWORD privileges[5] = {0xffffffff, 0, 0, 0, 0x12345678};
		size = 0;
		if (GetTokenInformation(token, TokenPrivileges, NULL, 0, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || size != sizeof(TOKEN_PRIVILEGES))
			return 20;
		if (GetTokenInformation(token, TokenPrivileges, privileges, size - 1, &size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
			privileges[0] != 0xffffffff)
			return 21;
		if (!GetTokenInformation(token, TokenPrivileges, privileges, sizeof(privileges), &size) || size != sizeof(TOKEN_PRIVILEGES) ||
			privileges[0] != 1 || privileges[1] != 23 || privileges[2] || privileges[3] != (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT) ||
			privileges[4] != 0x12345678)
			return 22;
		if (GetTokenInformation((HANDLE)(UINT_PTR)0x12345678, TokenPrivileges, privileges, sizeof(privileges), &size) ||
			GetLastError() != ERROR_INVALID_HANDLE)
			return 23;
	}
	{
		TOKEN_GROUPS *groups, *logon;
		DWORD group_size = 0, logon_size = 0, index;
		int found = 0;
		if (GetTokenInformation(token, TokenLogonSid, NULL, 0, &logon_size) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
			logon_size < sizeof(TOKEN_GROUPS))
			return 24;
		GetTokenInformation(token, TokenGroups, NULL, 0, &group_size);
		groups = HeapAlloc(GetProcessHeap(), 0, group_size);
		logon = HeapAlloc(GetProcessHeap(), 0, logon_size);
		if (!groups || !logon || !GetTokenInformation(token, TokenGroups, groups, group_size, &group_size) ||
			!GetTokenInformation(token, TokenLogonSid, logon, logon_size, &logon_size) || logon->GroupCount != 1 ||
			(logon->Groups[0].Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID || !IsValidSid(logon->Groups[0].Sid))
			return 25;
		for (index = 0; index < groups->GroupCount; ++index)
			if ((groups->Groups[index].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID &&
				EqualSid(groups->Groups[index].Sid, logon->Groups[0].Sid))
				++found;
		if (found != 1)
			return 26;
		HeapFree(GetProcessHeap(), 0, groups);
		HeapFree(GetProcessHeap(), 0, logon);
	}
	{
		ACL acl;
		TOKEN_DEFAULT_DACL dacl = {&acl};
		union { ULONGLONG align; BYTE bytes[128]; } buffer;
		TOKEN_DEFAULT_DACL *queried_dacl = (TOKEN_DEFAULT_DACL *)buffer.bytes;
		HANDLE changed = NULL;
		clear(&acl, sizeof(acl));
		acl.AclRevision = ACL_REVISION;
		acl.AclSize = sizeof(acl);
		if (!SetTokenInformation(token, TokenDefaultDacl, &dacl, sizeof(dacl)) ||
			!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &changed))
			return 27;
		acl.AceCount = 1;
		if (SetTokenInformation(token, TokenDefaultDacl, &dacl, sizeof(dacl)) || GetLastError() != ERROR_INVALID_ACL)
			return 28;
		if (!GetTokenInformation(token, TokenDefaultDacl, &buffer, sizeof(buffer), &size) || size != sizeof(dacl) + sizeof(acl) ||
			queried_dacl->DefaultDacl != (PACL)(buffer.bytes + sizeof(dacl)) || queried_dacl->DefaultDacl->AceCount != 0)
			return 29;
		dacl.DefaultDacl = NULL;
		if (!SetTokenInformation(token, TokenDefaultDacl, &dacl, sizeof(dacl)) ||
			!GetTokenInformation(token, TokenDefaultDacl, &buffer, sizeof(buffer), &size) || size != sizeof(dacl) || queried_dacl->DefaultDacl)
			return 30;
		if (!GetTokenInformation(changed, TokenDefaultDacl, &buffer, sizeof(buffer), &size) || size != sizeof(dacl) + sizeof(acl) ||
			!queried_dacl->DefaultDacl || queried_dacl->DefaultDacl->AceCount != 0)
			return 31;
		CloseHandle(changed);
	}
	{
		TOKEN_MANDATORY_LABEL label;
		union { ULONGLONG align; BYTE bytes[64]; } buffer;
		TOKEN_MANDATORY_LABEL *queried_label = (TOKEN_MANDATORY_LABEL *)buffer.bytes;
		if (!ConvertStringSidToSidW(L"LW", &label.Label.Sid))
			return 32;
		label.Label.Attributes = SE_GROUP_INTEGRITY;
		if (!SetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label)) ||
			!GetTokenInformation(token, TokenIntegrityLevel, &buffer, sizeof(buffer), &size) ||
			!EqualSid(label.Label.Sid, queried_label->Label.Sid))
			return 33;
		if (!GetTokenInformation(copy, TokenIntegrityLevel, &buffer, sizeof(buffer), &size) ||
			*GetSidSubAuthority(queried_label->Label.Sid, 0) != SECURITY_MANDATORY_MEDIUM_RID)
			return 34;
		LocalFree(label.Label.Sid);
		if (!ConvertStringSidToSidW(L"WD", &label.Label.Sid) ||
			SetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label)) || GetLastError() != ERROR_INVALID_SID)
			return 39;
		if (!GetTokenInformation(token, TokenIntegrityLevel, &buffer, sizeof(buffer), &size) ||
			*GetSidSubAuthority(queried_label->Label.Sid, 0) != SECURITY_MANDATORY_LOW_RID)
			return 40;
		LocalFree(label.Label.Sid);
	}
	{
		EXPLICIT_ACCESSW entries[3], revoke;
		PACL original = NULL, reduced = NULL, empty = NULL;
		PSID world = NULL, users = NULL;
		ACL_SIZE_INFORMATION acl_size;
		ACCESS_ALLOWED_ACE *ace = NULL;
		DWORD index;
		if (!ConvertStringSidToSidW(L"WD", &world) || !ConvertStringSidToSidW(L"S-1-5-32-545", &users))
			return 35;
		clear(entries, sizeof(entries));
		for (index = 0; index < 3; ++index) {
			entries[index].grfAccessPermissions = GENERIC_READ;
			entries[index].grfAccessMode = index == 2 ? DENY_ACCESS : GRANT_ACCESS;
			BuildTrusteeWithSidW(&entries[index].Trustee, index == 0 ? users : world);
		}
		if (SetEntriesInAclW(3, entries, NULL, &original) != ERROR_SUCCESS)
			return 36;
		clear(&revoke, sizeof(revoke));
		revoke.grfAccessMode = REVOKE_ACCESS;
		BuildTrusteeWithSidW(&revoke.Trustee, world);
		if (SetEntriesInAclW(1, &revoke, original, &reduced) != ERROR_SUCCESS ||
			!GetAclInformation(reduced, &acl_size, sizeof(acl_size), AclSizeInformation) || acl_size.AceCount != 1 ||
			!GetAce(reduced, 0, (void **)&ace) || !EqualSid(&ace->SidStart, users) || original->AceCount != 3)
			return 37;
		if (SetEntriesInAclW(1, &revoke, NULL, &empty) != ERROR_SUCCESS || empty->AceCount != 0 || empty->AclSize != sizeof(ACL))
			return 38;
		{
			ACL malformed;
			PACL result = NULL;
			clear(&malformed, sizeof(malformed));
			malformed.AclRevision = ACL_REVISION;
			malformed.AclSize = sizeof(malformed);
			malformed.AceCount = 1;
			if (SetEntriesInAclW(1, &revoke, &malformed, &result) != ERROR_INVALID_ACL || result)
				return 41;
		}
		LocalFree(original);
		LocalFree(reduced);
		LocalFree(empty);
		LocalFree(world);
		LocalFree(users);
	}
	CloseHandle(copy);
	CloseHandle(token);
	(void)error;
	/* The address waits through the synchronization API set, as programs built against it import them: a value already changed returns at
	 * once, an unchanged one times out. */
	HMODULE synch = LoadLibraryA("api-ms-win-core-synch-l1-2-0.dll");
	BOOL (WINAPI *wait_on)(volatile void *, void *, SIZE_T, DWORD) = synch ? (void *)GetProcAddress(synch, "WaitOnAddress") : NULL;
	void (WINAPI *wake_all)(void *) = synch ? (void *)GetProcAddress(synch, "WakeByAddressAll") : NULL;
	if (!wait_on || !wake_all || !GetProcAddress(synch, "WakeByAddressSingle")) return 165;
	LONG watched = 1, compare = 0;
	if (!wait_on(&watched, &compare, sizeof watched, 1000)) return 166;
	compare = 1;
	if (wait_on(&watched, &compare, sizeof watched, 10) || GetLastError() != ERROR_TIMEOUT) return 167;
	wake_all(&watched);
	/* A descriptor naming the local administrator account and a raw access mask, as installers write for their shared folders. */
	PSECURITY_DESCRIPTOR shared_folder = NULL;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OI;GA;;;LS)(A;OI;GA;;;BA)(A;OI;GA;;;LA)(A;OI;GR;;;AU)(A;OI;0x00100000;;;BG)",
		SDDL_REVISION_1, &shared_folder, NULL)) return 168;
	LPWSTR round_trip = NULL;
	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(shared_folder, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &round_trip, NULL) ||
		!contains(round_trip, L";;;LA)") || !contains(round_trip, L"0x100000;;;BG)")) return 169;
	LocalFree(round_trip);
	LocalFree(shared_folder);
	return 0;
}
