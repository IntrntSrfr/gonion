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
	secrets      [][]byte
	conn         net.Conn
}

func marshalRequest(req *gonion.HTTPRequest) []byte {
	d, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	return d
}

// connect takes in a node and attempts to connect the Client to it.
func (cli *Client) connect(node *gonion.NodeInfo) {
	c, err := net.Dial("tcp", fmt.Sprintf("%v:%v", node.IP, node.Port))
	if err != nil {
		log.Fatal(err)
	}
	cli.conn = c
}

func (cli *Client) closeConnection() {
	cli.conn.Close()
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

func (cli *Client) exchangeSecrets() {
	fmt.Println("attempting node handshakes...")

	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[0]))
	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[1], cli.nodes[1]))
	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[2], cli.nodes[2], cli.nodes[1]))

	fmt.Println("completed all handshakes")

}

func (cli *Client) exchangeSecret(node *gonion.NodeInfo, relays ...*gonion.NodeInfo) []byte {
	fmt.Println(fmt.Sprintf("starting handshake with %v relay(s)", len(relays)))

	pub := BytesToPublicKey(node.PublicKey)
	askP := packet.NewPacket()

	// make first half of key
	ck := make([]byte, 16)
	rand.Read(ck)

	fmt.Println(ck)

	askP.AddAskFrame(ck, true)
	askP.PrintInfo()

	err := askP.RSAEncrypt(pub)
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println("this is the input")
	//askP.PrintInfo()
	//askP.Pad()

	for i := range relays {
		fmt.Println("adding AES encryption layer...")

		node := relays[i]
		ap, err := netip.ParseAddrPort(fmt.Sprintf("%v:%v", node.IP, node.Port))
		if err != nil {
			log.Fatal(err)
		}
		nodeIP := ap.Addr().As4()
		nodePort := ap.Port()
		askP.AddRelayFrame(nodeIP, [2]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, true)

		askP.AESEncrypt(cli.secrets[i])
	}
	askP.Pad()

	askP.PrintInfo()

	// send ask packet
	fmt.Println("sending secret to node...")
	cli.conn.Write(askP.Bytes())

	fmt.Println("trying to read secret from node...")
	res := make([]byte, 512)
	_, err = io.ReadFull(cli.conn, res)
	if err != nil {
		log.Fatal(err)
	}

	skP := packet.NewPacketFromBytes(res)
	skP.Trim()

	for i := range relays {
		skP.AESDecrypt(cli.secrets[i])
	}

	skP.PrintInfo()

	skP.PopBytes(4)

	sk := skP.Bytes()

	sharedKey := append(ck, sk...)
	fmt.Println("SHARED KEY:", sharedKey)
	hashed := sha256.New()
	hashed.Write(sharedKey)
	secret := hashed.Sum(nil)
	fmt.Println("HASHED SHARED KEY:", secret)

	fmt.Println("completed handshake")
	return secret
}

func (cli *Client) do(req *gonion.HTTPRequest) *bytes.Buffer {

	inner := bytes.NewBuffer(marshalRequest(req))

	// first we must get the nodes and their public keys
	nodes := cli.getNodes()

	if len(nodes) < 3 {
		log.Fatal("too few nodes")
	}

	cli.connect(nodes[0])
	defer cli.closeConnection()

	// before sending request, we need to get secrets from each node

	cli.exchangeSecrets()

	return nil

	// partition the body into sizes we want to manage
	// send each packet separately to the next node
	for {
		partialMsg := make([]byte, MaxContent)
		n, err := io.ReadFull(inner, partialMsg)
		//n, err := inner.Read(partialMsg)
		if err != nil && err != io.ErrUnexpectedEOF {
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
		_, err = cli.conn.Write(p.Bytes())
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
		_, err := io.ReadFull(cli.conn, tmp)
		//_, err := c.Read(tmp)
		fmt.Println("read 2")
		if err != nil {
			log.Fatal(err)
		}
		p := packet.NewPacketFromBytes(tmp)
		p.Trim()

		//p.PrintInfo()
		// we need to 3x decrypt here
		for i := 0; i < 3; i++ {
			p.AESDecrypt([]byte("siggarett"))
		}

		//p.PrintInfo()

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
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		panic("failed lol")
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
