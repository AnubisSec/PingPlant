package main

import (
	"fmt"
	//"syscall"
	//"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

func enableExistingFirewallRule(ruleName string) error {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		return fmt.Errorf("Failed to create COM object: %v", err)
	}
	defer unknown.Release()

	firewallPolicy, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("Failed to query interface: %v", err)
	}
	defer firewallPolicy.Release()

	rules, err := oleutil.GetProperty(firewallPolicy, "Rules")
	if err != nil {
		return fmt.Errorf("Failed to get Rules property: %v", err)
	}
	defer rules.Clear()

	rulesDispatch := rules.ToIDispatch()

	// Get the existing rule by name
	existingRule, err := oleutil.CallMethod(rulesDispatch, "Item", ruleName)
	if err != nil {
		return fmt.Errorf("Failed to get existing rule: %v", err)
	}
	defer existingRule.Clear()

	existingRuleDispatch := existingRule.ToIDispatch()

	// Enable the existing rule
	enabled, err := oleutil.PutProperty(existingRuleDispatch, "Enabled", true)
	if err != nil {
		return fmt.Errorf("Failed to set Enabled property: %v", err)
	}
	defer enabled.Clear()

	return nil
}

func main() {
	ruleName := "File and Printer Sharing (Echo Request - ICMPv4-In)"

	if err := enableExistingFirewallRule(ruleName); err != nil {
		fmt.Println("Error:", err)
	} //else {
		//fmt.Printf("Firewall rule '%s' has been enabled.\n", ruleName)
	//}
}

