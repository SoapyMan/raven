#define WIN32_LEAN_AND_MEAN
#define INITGUID
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <oleauto.h>
#include <ocidl.h>
#include <netlistmgr.h>

typedef HRESULT (WINAPI *initialize_function)(void *, DWORD);
typedef HRESULT (WINAPI *create_function)(REFCLSID, IUnknown *, DWORD, REFIID, void **);

/* An event sink that accepts the network list events and is never called. */
static HRESULT WINAPI sink_query(INetworkListManagerEvents *self, REFIID iid, void **out)
{
	if (iid->Data1 == IID_INetworkListManagerEvents.Data1 || iid->Data1 == 0) {
		*out = self;
		return S_OK;
	}
	*out = NULL;
	return E_NOINTERFACE;
}

static ULONG WINAPI sink_reference(INetworkListManagerEvents *self) { return 2; }
static HRESULT WINAPI sink_changed(INetworkListManagerEvents *self, NLM_CONNECTIVITY connectivity) { return S_OK; }
static INetworkListManagerEventsVtbl sink_table = {sink_query, sink_reference, sink_reference, sink_changed};

/* The network list through COM, with ole32 loaded only at run time as a program that imports just automation does: connectivity agrees
 * across the manager, its networks and their connections, the cost is unrestricted, and an event registration is accepted and ended. */
int raven_entry(void)
{
	if (SysStringLen(NULL)) return 20;
	HMODULE ole = LoadLibraryW(L"ole32.dll");
	initialize_function CoInitializeEx = ole ? (initialize_function)GetProcAddress(ole, "CoInitializeEx") : NULL;
	create_function CoCreateInstance = ole ? (create_function)GetProcAddress(ole, "CoCreateInstance") : NULL;
	if (!CoInitializeEx || !CoCreateInstance) return 21;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) return 1;
	INetworkListManager *manager = NULL;
	if (CoCreateInstance(&CLSID_NetworkListManager, NULL, CLSCTX_ALL, &IID_INetworkListManager, (void **)&manager) != S_OK || !manager) return 2;
	NLM_CONNECTIVITY connectivity = 0xdead;
	VARIANT_BOOL internet = 7, connected = 7;
	if (INetworkListManager_GetConnectivity(manager, &connectivity) != S_OK || connectivity == 0xdead) return 3;
	if (INetworkListManager_IsConnectedToInternet(manager, &internet) != S_OK || internet != (connectivity & NLM_CONNECTIVITY_IPV4_INTERNET ? VARIANT_TRUE : VARIANT_FALSE)) return 4;
	if (INetworkListManager_IsConnected(manager, &connected) != S_OK || connected != (connectivity ? VARIANT_TRUE : VARIANT_FALSE)) return 5;
	IEnumNetworks *networks = NULL;
	INetwork *network = NULL;
	ULONG fetched = 9;
	if (INetworkListManager_GetNetworks(manager, NLM_ENUM_NETWORK_CONNECTED, &networks) != S_OK) return 6;
	const HRESULT next = IEnumNetworks_Next(networks, 1, &network, &fetched);
	if (connectivity ? next != S_OK || fetched != 1 || !network : next != S_FALSE || fetched) return 7;
	if (network) {
		VARIANT_BOOL network_connected = 7;
		IEnumNetworkConnections *connections = NULL;
		INetworkConnection *connection = NULL;
		GUID id;
		if (INetwork_get_IsConnected(network, &network_connected) != S_OK || network_connected != VARIANT_TRUE) return 8;
		if (INetwork_GetNetworkConnections(network, &connections) != S_OK || IEnumNetworkConnections_Next(connections, 1, &connection, NULL) != S_OK)
			return 9;
		if (INetworkConnection_GetConnectionId(connection, &id) != S_OK) return 10;
		INetworkConnection *found = NULL;
		if (INetworkListManager_GetNetworkConnection(manager, id, &found) != S_OK || found != connection) return 11;
		IEnumNetworkConnections_Release(connections);
	}
	IEnumNetworks_Release(networks);
	INetworkCostManager *cost = NULL;
	DWORD value = 0;
	if (INetworkListManager_QueryInterface(manager, &IID_INetworkCostManager, (void **)&cost) != S_OK) return 12;
	if (INetworkCostManager_GetCost(cost, &value, NULL) != S_OK || value != NLM_CONNECTION_COST_UNRESTRICTED) return 13;
	INetworkCostManager_Release(cost);
	IConnectionPointContainer *container = NULL;
	IConnectionPoint *point = NULL;
	INetworkListManagerEvents sink = {&sink_table};
	DWORD cookie = 0;
	if (INetworkListManager_QueryInterface(manager, &IID_IConnectionPointContainer, (void **)&container) != S_OK) return 14;
	if (IConnectionPointContainer_FindConnectionPoint(container, &IID_INetworkListManagerEvents, &point) != S_OK) return 15;
	if (IConnectionPoint_Advise(point, (IUnknown *)&sink, &cookie) != S_OK || !cookie || IConnectionPoint_Unadvise(point, cookie) != S_OK) return 16;
	IConnectionPoint_Release(point);
	IConnectionPointContainer_Release(container);
	if (INetworkListManager_Release(manager)) return 17;
	return connectivity ? 0 : 30;
}
