#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <d3d10_1.h>
#include <d3d10effect.h>

typedef HRESULT (WINAPI *create_device)(IDXGIAdapter *, D3D10_DRIVER_TYPE, HMODULE, UINT, D3D10_FEATURE_LEVEL1, UINT, ID3D10Device1 **);
typedef HRESULT (WINAPI *create_block)(ID3D10Device *, D3D10_STATE_BLOCK_MASK *, ID3D10StateBlock **);

/* Direct3D 10.1 loaded by name, as programs that delay-load it do: the library resolves, only hardware devices are offered, a hardware
 * device without a d3d10core.dll beside the runtime is unsupported rather than a fault, and state blocks are not implemented. */
int raven_entry(void)
{
	ID3D10Device1 *device = (ID3D10Device1 *)(UINT_PTR)1;
	ID3D10StateBlock *block = (ID3D10StateBlock *)(UINT_PTR)1;
	D3D10_STATE_BLOCK_MASK mask;
	HMODULE library = LoadLibraryW(L"d3d10_1.dll");
	if (!library)
		return 1;
	create_device D3D10CreateDevice1 = (create_device)(void *)GetProcAddress(library, "D3D10CreateDevice1");
	create_block D3D10CreateStateBlock = (create_block)(void *)GetProcAddress(library, "D3D10CreateStateBlock");
	if (!D3D10CreateDevice1 || !D3D10CreateStateBlock)
		return 5;
	if (D3D10CreateDevice1(NULL, D3D10_DRIVER_TYPE_REFERENCE, NULL, 0, D3D10_FEATURE_LEVEL_10_1, D3D10_1_SDK_VERSION, &device) !=
		DXGI_ERROR_UNSUPPORTED || device)
		return 2;
	device = (ID3D10Device1 *)(UINT_PTR)1;
	if (D3D10CreateDevice1(NULL, D3D10_DRIVER_TYPE_HARDWARE, NULL, 0, D3D10_FEATURE_LEVEL_10_1, D3D10_1_SDK_VERSION, &device) !=
		DXGI_ERROR_UNSUPPORTED || device)
		return 3;
	if (D3D10CreateStateBlock(NULL, &mask, &block) != E_NOTIMPL || block)
		return 4;
	return 0;
}
