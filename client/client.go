package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/packet"
)

// NodeCount will be 3 for this client.
const NodeCount = 3
const MaxContent = 256
const DirURL = "http://localhost:9051/api/nodes"

type Client struct {
	directoryURL string
	nodes        []*gonion.NodeInfo
	secrets      []string
}

func marshalRequest(req *gonion.HTTPRequest) []byte {
	d, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	return d
}

func (cli *Client) getNodes() []*gonion.NodeInfo {
	res, err := http.DefaultClient.Get(cli.directoryURL)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err = res.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	var nodes []*gonion.NodeInfo
	err = json.NewDecoder(res.Body).Decode(&nodes)
	if err != nil {
		log.Fatal(err)
	}
	cli.nodes = nodes
	return nodes
}
func Do(req *gonion.HTTPRequest) *bytes.Buffer {
	c := &Client{directoryURL: DirURL}
	return c.do(req)
}

func (cli *Client) do(req *gonion.HTTPRequest) *bytes.Buffer {

	inner := bytes.NewBuffer(marshalRequest(req))

	// first we must get the nodes and their public keys
	nodes := cli.getNodes()

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

	// before sending request, we need to get secrets from each node

	// partition the body into sizes we want to manage
	// send each packet separately to the next node
	for {
		partialMsg := make([]byte, MaxContent)
		n, err := inner.Read(partialMsg)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		p := packet.NewPacket()
		p.AddDataFrame(partialMsg[:n], n != MaxContent)
		//fmt.Println("before encrypt")
		//p.PrintInfo()

		// packet should be encrypted here with node 3 key
		p.AESEncrypt([]byte("siggarett"))

		// here we add the layers for the 2 other nodes

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
			p.AESEncrypt([]byte("siggarett"))
		}

		p.Pad()
		_, err = c.Write(p.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		if n != MaxContent {
			break
		}
	}

	fmt.Println("i will now try to read a response")

	resp := new(bytes.Buffer)

	for {
		fmt.Println("receiving packet...")
		tmp := make([]byte, packet.MaxPacketSize)
		fmt.Println("read 1")
		_, err := c.Read(tmp)
		fmt.Println("read 2")
		if err != nil {
			fmt.Println(err)
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		p := packet.NewPacketFromBytes(tmp)
		p.Trim()

		// we need to 3x decrypt here

		header := p.PopBytes(2)
		length := int(binary.BigEndian.Uint16(p.PopBytes(2)))
		resp.Write(p.Bytes()[:length])
		//io.Copy(f, bytes.NewBuffer(p.Bytes()[:length]))
		if header[0]&1 == 1 {
			break
		}
	}

	return resp
}

func closeConn(c net.Conn) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println("closed connection")

}

func (c *Client) GetSecret() {

}

func ParseURL(inp string) *gonion.HTTPRequest {
	u, err := url.Parse(inp)
	if err != nil {
		log.Fatal(err)
	}
	return &gonion.HTTPRequest{
		Method:  "GET",
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		Queries: u.Query(),
	}
}

/*
func main() {

	// first we must get the nodes and their public keys

	res, err := http.DefaultClient.Get("http://localhost:9051/api/nodes")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	var nodes []*Node
	err = json.NewDecoder(res.Body).Decode(&nodes)
	if err != nil {
		log.Fatal(err)
	}

	node := nodes[0]

	pubKey := BytesToPublicKey(node.PublicKey)

	key := make([]byte, 8)
	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("client key:", key)
	encrypted, err := Encrypt(key, pubKey)
	if err != nil {
		log.Fatal(err)
	}

}
*/

func Encrypt(data []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, []byte(""))
}

func Decrypt(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, []byte(""))
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode public key PEM block")
	}
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		log.Fatal("not ok")
	}
	return key
}
