package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/node"
	"log"
	"net"
	"net/http"
)

func main() {

	var p string
	fmt.Print("what port u wanna use:")
	fmt.Scan(&p)
	fmt.Println()

	localIP := GetOutIP()
	host, _, _ := net.SplitHostPort(localIP)
	fmt.Println("local ip:", host)

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

	if res.StatusCode != http.StatusOK {
		log.Fatal("unable to join the node network")
	}

	log.Println("joined node network")

	// start listening for connections
	h.StartListenAtPort(p)
	h.Listen()
}

func GetOutIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	return conn.LocalAddr().String()
}
