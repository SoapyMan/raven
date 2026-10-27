#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <msxml6.h>

/* The MSXML 6.0 document class, found by its name as programs find it: it parses a document and answers for its elements. */
int raven_entry(void)
{
	CLSID clsid;
	IXMLDOMDocument *document = NULL;
	IXMLDOMElement *root = NULL;
	IXMLDOMNode *node = NULL;
	VARIANT_BOOL loaded = VARIANT_FALSE;
	BSTR text = NULL, name = NULL;
	if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
	if (CLSIDFromProgID(L"Msxml2.DOMDocument.6.0", &clsid) != S_OK || clsid.Data1 != CLSID_DOMDocument60.Data1 || clsid.Data2 != CLSID_DOMDocument60.Data2) return 2;
	if (CoCreateInstance(&CLSID_DOMDocument60, NULL, CLSCTX_INPROC_SERVER, &IID_IXMLDOMDocument, (void **)&document) != S_OK || !document) return 3;
	text = SysAllocString(L"<Configuration><Add Channel=\"Current\"><Product ID=\"O365ProPlusRetail\"/></Add></Configuration>");
	if (IXMLDOMDocument_loadXML(document, text, &loaded) != S_OK || loaded != VARIANT_TRUE) return 4;
	if (IXMLDOMDocument_get_documentElement(document, &root) != S_OK || !root || IXMLDOMElement_get_nodeName(root, &name) != S_OK ||
		lstrcmpW(name, L"Configuration")) return 5;
	SysFreeString(name);
	SysFreeString(text);
	text = SysAllocString(L"//Product/@ID");
	if (IXMLDOMDocument_selectSingleNode(document, text, &node) != S_OK || !node || IXMLDOMNode_get_text(node, &name) != S_OK ||
		lstrcmpW(name, L"O365ProPlusRetail")) return 6;
	SysFreeString(name);
	SysFreeString(text);
	IXMLDOMNode_Release(node);
	IXMLDOMElement_Release(root);
	IXMLDOMDocument_Release(document);
	CoUninitialize();
	return 0;
}
