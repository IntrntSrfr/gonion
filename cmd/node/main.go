package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/node"
)

func main() {

	var p string
	fmt.Print("what port u wanna use:")
	fmt.Scan(&p)
	fmt.Println()

	// get the outbound IP for the node, can probably be changed to an environment variable
	localIP := GetOutIP()
	host, _, _ := net.SplitHostPort(localIP)
	fmt.Println("local ip:", host)

	// create new node and generate keypairs
	h := new(node.Node)
	h.GenerateKeypair()

	n := &gonion.NodeInfo{
		IP:        host,
		Port:      p,
		PublicKey: h.PubKeyBytes(),
	}
	d, _ := json.MarshalIndent(n, "", "\t")

	// the node can then add itself to the node directory
	res, err := http.Post("http://localhost:9051/api/nodes", "application/json", bytes.NewBuffer(d))
	if err != nil {
		log.Fatal(err)
	}

	// if OK is not returned, something went wrong and the program will exit
	if res.StatusCode != http.StatusOK {
		log.Fatal("unable to join the node network")
	}

	log.Println("joined node network")

	// start listening for connections
	h.StartListenAtPort(p)
	h.Listen()
}

// GetOutIP gets the outbound local IP
func GetOutIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	return conn.LocalAddr().String()
}
