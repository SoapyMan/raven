#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <rpc.h>
#include <sspi.h>

/* Local remote procedure calls with authentication, as services and their clients set it up: the logon packages are listed with their
 * RPC identifiers, a server registers NTLM and Negotiate, and a client binds over ncalrpc with NTLM at packet privacy. */
int raven_entry(void)
{
	ULONG count = 0;
	SecPkgInfoW *packages = NULL;
	if (EnumerateSecurityPackagesW(&count, &packages) != SEC_E_OK || !count) return 1;
	int ntlm = 0, negotiate = 0;
	for (ULONG index = 0; index < count; ++index) {
		if (packages[index].wRPCID == RPC_C_AUTHN_WINNT && packages[index].cbMaxToken) ntlm = 1;
		if (packages[index].wRPCID == RPC_C_AUTHN_GSS_NEGOTIATE) negotiate = 1;
	}
	FreeContextBuffer(packages);
	if (!ntlm || !negotiate) return 2;
	if (RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_WINNT, NULL, NULL) != RPC_S_OK) return 3;
	if (RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_GSS_NEGOTIATE, NULL, NULL) != RPC_S_OK) return 4;
	if (RpcServerRegisterAuthInfoW(NULL, 0x7777, NULL, NULL) != RPC_S_UNKNOWN_AUTHN_SERVICE) return 5;
	RPC_WSTR text = NULL;
	RPC_BINDING_HANDLE binding = NULL;
	if (RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"raven-auth", NULL, &text) != RPC_S_OK) return 6;
	if (RpcBindingFromStringBindingW(text, &binding) != RPC_S_OK) return 7;
	RpcStringFreeW(&text);
	if (RpcBindingSetAuthInfoW(binding, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, NULL, 0) != RPC_S_OK) return 8;
	RpcBindingFree(&binding);
	return 0;
}
