package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/intrntsrfr/gonion/client"
	"github.com/intrntsrfr/gonion/packet"
	"io"
	"log"
	"net"
	"net/netip"
)

func closeConn(c net.Conn) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println("closed connection")

}

const MaxContent = 64

func main() {

	a := "http://localhost:9051/api/nodes?weed=fart"
	req := client.ParseRequest(a)

	d, _ := json.Marshal(req)
	innerMsgBuffer := bytes.NewBuffer(d)
	log.Println("msg buffer length:", len(d))

	// first we must get the nodes and their public keys
	nodes := client.GetNodes()

	if len(nodes) < 3 {
		log.Fatal("too few nodes")
	}

	node1 := nodes[0]
	// dont need a layer for node 1 as its directly connected
	c, err := net.Dial("tcp", fmt.Sprintf("%v:%v", node1.IP, node1.Port))
	if err != nil {
		log.Fatal(err)
	}
	defer closeConn(c)

	// partition the body into sizes we want to manage
	// send each packet separately to the next node
	for {
		partialMsg := make([]byte, MaxContent)
		n, err := innerMsgBuffer.Read(partialMsg)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		p := packet.NewPacket()
		p.AddDataFrame(partialMsg[:n], n != MaxContent)

		// packet should be encrypted here with node 3 key

		// here we add the layers for the 2 other nodes

		// the loop body can probably be turned into a function call instead, making it much easier to deal with
		// when it comes to encryption

		// add 2x relay header
		for i := 2; i > 0; i-- {
			node := nodes[i]
			ap, err := netip.ParseAddrPort(fmt.Sprintf("%v:%v", node.IP, node.Port))
			if err != nil {
				log.Fatal(err)
			}
			nodeIP := ap.Addr().As4()
			nodePort := ap.Port()
			p.AddRelayFrame(nodeIP, [2]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, n != MaxContent)

			// it should be a layer of encryption here
		}

		p.PrintInfo()

		_, err = c.Write(partialMsg)
		if err != nil {
			log.Fatal(err)
		}
		if n != MaxContent {
			break
		}
	}

	// read the response
	resp := new(bytes.Buffer)
	for {
		tmp := make([]byte, 1024)
		_, err := c.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		resp.Write(tmp)
	}

	fmt.Println(resp.String())

}
