package main

import (
	"log"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const targetIP = "127.0.0.1"

func main() {
	conn, err := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	

	wm := icmp.Message{
        Type: ipv4.ICMPTypeEcho, Code: 0,
        Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			// b64 encoded secret string, below is "Activate"
            Data: []byte("QWN0aXZhdGUV"),
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