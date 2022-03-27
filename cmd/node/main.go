package main

import (
	"flag"
	"log"
	"net"

	"github.com/intrntsrfr/gonion/node"
)

func main() {

	var addr, port string

	flag.StringVar(&addr, "ip", "", "ip address of the computer, will use localhost if none is provided")
	flag.StringVar(&port, "port", "", "port to run the node on")
	flag.Parse()

	if addr == "" {
		addr, _, _ = net.SplitHostPort(getLocalIP())
	}

	if port == "" {
		log.Fatal("you need to specify a port")
	}

	// create new node and generate keypair
	h := node.NewNode()
	//h := &node.Node{}
	err := h.Run(addr, port)
	if err != nil {
		log.Fatal(err)
	}
}

// getLocalIP gets the local IP
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	return conn.LocalAddr().String()
}
