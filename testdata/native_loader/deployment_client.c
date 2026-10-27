#define WIN32_LEAN_AND_MEAN
#define INITGUID
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <oleauto.h>
#include <winstring.h>
#include <activation.h>
#include <windows.management.deployment.h>

typedef HRESULT (WINAPI *initialize_function)(int);
typedef HRESULT (WINAPI *factory_function)(HSTRING, REFIID, void **);
typedef HRESULT (WINAPI *activate_function)(HSTRING, IInspectable **);
typedef const WCHAR *(WINAPI *buffer_function)(HSTRING, UINT32 *);
typedef HRESULT (WINAPI *delete_function)(HSTRING);

/* The string header programs built with C++/WinRT write themselves for a reference: flags, length, two unused words, the characters. */
struct reference {
	UINT32 flags, length, unused[2];
	const WCHAR *text;
};

/* The package manager through the Windows Runtime, with the runtime loaded only at run time as a program that imports just automation
 * does: the class is activated by name and by factory, finds no packages, users or package by full name, names its class, and a class
 * nobody registered is not activated. */
int raven_entry(void)
{
	static const WCHAR name[] = L"Windows.Management.Deployment.PackageManager";
	if (SysStringLen(NULL)) return 20;
	HMODULE runtime = LoadLibraryW(L"combase.dll");
	initialize_function RoInitialize = runtime ? (initialize_function)GetProcAddress(runtime, "RoInitialize") : NULL;
	factory_function RoGetActivationFactory = runtime ? (factory_function)GetProcAddress(runtime, "RoGetActivationFactory") : NULL;
	activate_function RoActivateInstance = runtime ? (activate_function)GetProcAddress(runtime, "RoActivateInstance") : NULL;
	buffer_function WindowsGetStringRawBuffer = runtime ? (buffer_function)GetProcAddress(runtime, "WindowsGetStringRawBuffer") : NULL;
	delete_function WindowsDeleteString = runtime ? (delete_function)GetProcAddress(runtime, "WindowsDeleteString") : NULL;
	if (!RoInitialize || !RoGetActivationFactory || !RoActivateInstance || !WindowsGetStringRawBuffer || !WindowsDeleteString) return 21;
	if (FAILED(RoInitialize(1))) return 1;
	struct reference class_name = {1, ARRAYSIZE(name) - 1, {0, 0}, name};
	IInspectable *object = NULL;
	if (RoActivateInstance((HSTRING)&class_name, &object) != S_OK || !object) return 2;
	__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager *manager = NULL;
	if (IInspectable_QueryInterface(object, &IID___x_ABI_CWindows_CManagement_CDeployment_CIPackageManager, (void **)&manager) != S_OK) return 3;
	IInspectable_Release(object);
	HSTRING runtime_name = NULL;
	UINT32 length = 0;
	if (__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager_GetRuntimeClassName(manager, &runtime_name) != S_OK) return 4;
	const WCHAR *text = WindowsGetStringRawBuffer(runtime_name, &length);
	if (length != ARRAYSIZE(name) - 1 || text[30] != 'P' || text[length]) return 5;
	WindowsDeleteString(runtime_name);
	static const WCHAR family[] = L"Microsoft.Office.Desktop_8wekyb3d8bbwe";
	struct reference family_name = {1, ARRAYSIZE(family) - 1, {0, 0}, family};
	__FIIterable_1_Windows__CApplicationModel__CPackage *packages = NULL;
	if (__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager_FindPackagesByUserSecurityIdPackageFamilyName(manager, NULL,
		(HSTRING)&family_name, &packages) != S_OK || !packages) return 6;
	__FIIterator_1_Windows__CApplicationModel__CPackage *iterator = NULL;
	boolean present = TRUE;
	UINT32 count = 7;
	if (__FIIterable_1_Windows__CApplicationModel__CPackage_First(packages, &iterator) != S_OK || !iterator) return 7;
	if (__FIIterator_1_Windows__CApplicationModel__CPackage_get_HasCurrent(iterator, &present) != S_OK || present) return 8;
	if (__FIIterator_1_Windows__CApplicationModel__CPackage_GetMany(iterator, 0, NULL, &count) != S_OK || count) return 9;
	__FIIterator_1_Windows__CApplicationModel__CPackage_Release(iterator);
	__FIIterable_1_Windows__CApplicationModel__CPackage_Release(packages);
	__FIIterable_1_Windows__CManagement__CDeployment__CPackageUserInformation *users = NULL;
	__FIIterator_1_Windows__CManagement__CDeployment__CPackageUserInformation *user = NULL;
	if (__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager_FindUsers(manager, (HSTRING)&family_name, &users) != S_OK) return 10;
	present = TRUE;
	if (__FIIterable_1_Windows__CManagement__CDeployment__CPackageUserInformation_First(users, &user) != S_OK ||
		__FIIterator_1_Windows__CManagement__CDeployment__CPackageUserInformation_get_HasCurrent(user, &present) != S_OK || present) return 11;
	__FIIterator_1_Windows__CManagement__CDeployment__CPackageUserInformation_Release(user);
	__FIIterable_1_Windows__CManagement__CDeployment__CPackageUserInformation_Release(users);
	__x_ABI_CWindows_CApplicationModel_CIPackage *package = (void *)1;
	if (__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager_FindPackageByPackageFullName(manager, (HSTRING)&family_name, &package) != S_OK ||
		package) return 12;
	__x_ABI_CWindows_CManagement_CDeployment_CIPackageManager_Release(manager);
	IActivationFactory *factory = NULL;
	if (RoGetActivationFactory((HSTRING)&class_name, &IID_IActivationFactory, (void **)&factory) != S_OK || !factory) return 13;
	if (IActivationFactory_ActivateInstance(factory, &object) != S_OK || !object) return 14;
	IInspectable_Release(object);
	IActivationFactory_Release(factory);
	static const WCHAR missing[] = L"Windows.Raven.Missing";
	struct reference missing_name = {1, ARRAYSIZE(missing) - 1, {0, 0}, missing};
	object = (void *)1;
	if (RoActivateInstance((HSTRING)&missing_name, &object) != REGDB_E_CLASSNOTREG || object) return 15;
	return 0;
}
