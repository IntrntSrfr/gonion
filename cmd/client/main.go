package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/intrntsrfr/gonion/client"
	"github.com/intrntsrfr/gonion/packet"
)

func closeConn(c net.Conn) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println("closed connection")

}

//const MaxContent = packet.MaxPacketSize - (NodeCount-1)*8 - 4
const MaxContent = 256
const NodeCount = 3

func main() {

	flag.Parse()
	file := flag.Arg(0)
	if file == "" {
		fmt.Println("please specify an output file")
		return
	}

	a := "https://www.vg.no/"
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
		//p.AESEncrypt([]byte("siggarett"))

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
			//p.AESEncrypt([]byte("siggarett"))
		}

		p.Pad()
		//p.PrintInfo()
		_, err = c.Write(p.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		if n != MaxContent {
			break
		}
	}

	fmt.Println("i will now try to read a response")

	// read the response
	resp := new(bytes.Buffer)
	for {
		fmt.Println("receiving packet...")
		tmp := make([]byte, packet.MaxPacketSize)
		_, err := c.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		p := packet.NewPacketFromBytes(tmp)
		//p.PrintInfo()
		header := p.PopBytes(2)
		length := int(binary.BigEndian.Uint16(p.PopBytes(2)))
		resp.Write(p.Bytes()[:length])
		if header[0]&1 == 1 {
			break
		}
	}

	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(f, resp)
}
