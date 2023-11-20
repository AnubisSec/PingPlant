package main

/*
#cgo CFLAGS: -I. -D_CRT_SECURE_NO_WARNINGS
#cgo LDFLAGS: -lole32 -loleaut32 -luuid

#include <windows.h>
#include <ole2.h>
#include <netfw.h>

// Declare CLSID and IID
EXTERN_C const GUID CLSID_NetFwPolicy2 = {0x4C96BE40, 0x915C, 0x11CF, {0x99, 0x3B, 0x00, 0xAA, 0x00, 0x41, 0xF7, 0x37}};
EXTERN_C const GUID IID_INetFwPolicy2 = {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0x87, 0x2E, 0x24, 0xF5, 0x79, 0x70}};

HRESULT enableFirewallRule(const wchar_t *ruleName) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        return hr;
    }

    INetFwPolicy2 *fwPolicy2 = NULL;
    INetFwRules *fwRules = NULL;
    INetFwRule *fwRule = NULL;

    hr = CoCreateInstance(
        &CLSID_NetFwPolicy2,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_INetFwPolicy2,
        (void **)&fwPolicy2
    );

    if (FAILED(hr)) {
        CoUninitialize();
        return hr;
    }

    hr = fwPolicy2->lpVtbl->get_Rules(fwPolicy2, &fwRules);
    if (FAILED(hr)) {
        fwPolicy2->lpVtbl->Release(fwPolicy2);
        CoUninitialize();
        return hr;
    }

    BSTR ruleNameBstr = SysAllocString(ruleName);
    if (ruleNameBstr == NULL) {
        fwRules->lpVtbl->Release(fwRules);
        fwPolicy2->lpVtbl->Release(fwPolicy2);
        CoUninitialize();
        return E_OUTOFMEMORY;
    }

    hr = fwRules->lpVtbl->Item(fwRules, ruleNameBstr, &fwRule);
    SysFreeString(ruleNameBstr);

    if (FAILED(hr)) {
        fwRules->lpVtbl->Release(fwRules);
        fwPolicy2->lpVtbl->Release(fwPolicy2);
        CoUninitialize();
        return hr;
    }

    hr = fwRule->lpVtbl->put_Enabled(fwRule, VARIANT_TRUE);

    fwRule->lpVtbl->Release(fwRule);
    fwRules->lpVtbl->Release(fwRules);
    fwPolicy2->lpVtbl->Release(fwPolicy2);
    CoUninitialize();

    return hr;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func enableFirewallRule(ruleName string) error {
	cRuleName := C.CString(ruleName)
	defer C.free(unsafe.Pointer(cRuleName))

	hr := C.enableFirewallRule((*C.wchar_t)(unsafe.Pointer(cRuleName)))
	if hr != 0 {
		return fmt.Errorf("Failed to enable firewall rule. COM error: 0x%X", uint32(hr))
	}

	return nil
}

func main() {
	ruleName := "File and Printer Sharing (Echo Request - ICMPv4-In)" // Replace with the actual name of your firewall rule
	if err := enableFirewallRule(ruleName); err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Firewall rule '%s' has been enabled.\n", ruleName)
	}
}

