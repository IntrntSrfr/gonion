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

// MaxContent is the max amount of bytes a data frame can hold as a maximum
const MaxContent = 256

// DirURL is the directory node URL
const DirURL = "http://localhost:9051/api/nodes"

// Client represents a Gonion client that sends a request through the node network
type Client struct {
	directoryURL string
	nodes        []*gonion.NodeInfo
	secrets      [][]byte
	conn         net.Conn
}

// marshalRequest turns an HTTPRequest struct into a byte array
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

// closeConnection closes a tcp connection
func (cli *Client) closeConnection() {
	cli.conn.Close()
}

// getNodes fetches node info from the directory node, tracks and returns it
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

// Do uses the client to send an HTTPRequest through the node network and get a response back
func Do(req *gonion.HTTPRequest) *bytes.Buffer {
	c := &Client{directoryURL: DirURL}
	return c.do(req)
}

// exchangeSecrets exchanges secrets with 3 nodes and tracks them for later use
func (cli *Client) exchangeSecrets() {
	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[0]))
	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[1], cli.nodes[1]))
	cli.secrets = append(cli.secrets, cli.exchangeSecret(cli.nodes[2], cli.nodes[2], cli.nodes[1]))
}

// exchangeSecret connects to a node through an amount of relays and exchanges a secret with it
func (cli *Client) exchangeSecret(node *gonion.NodeInfo, relays ...*gonion.NodeInfo) []byte {
	pub := BytesToPublicKey(node.PublicKey)
	askP := packet.NewPacket()

	// make the client secret
	ck := make([]byte, 16)
	rand.Read(ck)

	// add an ask frame containing the client secret
	askP.AddAskFrame(ck, true)

	// RSA encrypt the client secret with the public key from the input node
	err := askP.RSAEncrypt(pub)
	if err != nil {
		log.Fatal(err)
	}

	for i := range relays {
		node := relays[i]
		ap, err := netip.ParseAddrPort(fmt.Sprintf("%v:%v", node.IP, node.Port))
		if err != nil {
			log.Fatal(err)
		}
		nodeIP := ap.Addr().As4()
		nodePort := ap.Port()

		// add relay frame with next node info
		askP.AddRelayFrame(nodeIP, [2]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, true)
		askP.AESEncrypt(cli.secrets[len(cli.secrets)-i-1])
	}
	askP.Pad() // pad packet before sending

	// send ask packet
	cli.conn.Write(askP.Bytes())

	// read 512 byte packets. anything that is not 512 bytes means something is wrong.
	res := make([]byte, 512)
	_, err = io.ReadFull(cli.conn, res)
	if err != nil {
		log.Fatal(err)
	}

	skP := packet.NewPacketFromBytes(res)
	skP.Trim()

	// decrypt the packet based on how many relays it has been through
	for i := range relays {
		skP.AESDecrypt(cli.secrets[i])
	}

	// pop the data frame header, it isnt needed
	skP.PopBytes(4)
	sk := skP.Bytes() // the only data left will be the node secret

	sharedKey := append(ck, sk...)
	hashed := sha256.New()
	hashed.Write(sharedKey)
	secret := hashed.Sum(nil) // create the final secret for the input node

	return secret
}

// do performs a key exchange with the node network, then sends a request through it and receives a response
func (cli *Client) do(req *gonion.HTTPRequest) *bytes.Buffer {
	if req == nil {
		log.Fatal("request body cannot be nil")
	}

	// make a buffer from the request input
	inner := bytes.NewBuffer(marshalRequest(req))

	// first we must get the node info
	nodes := cli.getNodes()

	if len(nodes) < 3 {
		log.Fatal("too few nodes")
	}

	// connect with the first node and keep track of it
	cli.connect(nodes[0])
	defer cli.closeConnection()

	// exchange secrets with each node and keep track of them
	cli.exchangeSecrets()

	// partition the body into sizes we want to manage
	// send each packet separately to the next node
	for {
		partialMsg := make([]byte, MaxContent)
		n, err := io.ReadFull(inner, partialMsg) // read from the inner message buffer into several partial messages
		if err != nil && err != io.ErrUnexpectedEOF {
			log.Fatal(err)
		}
		p := packet.NewPacket()
		p.AddDataFrame(partialMsg[:n], n != MaxContent) // if n != max content, it means we reached the end of the data.

		// packet should be encrypted here with node 3 key
		p.AESEncrypt(cli.secrets[len(cli.secrets)-1])

		// add 2 encrypted relay frames, we want different nodes based on the layer of encryption we are doing, so the indices will be funny
		for i := 2; i > 0; i-- {
			node := nodes[i-1]

			// parse ip:port
			ap, err := netip.ParseAddrPort(fmt.Sprintf("%v:%v", node.IP, node.Port))
			if err != nil {
				log.Fatal(err)
			}
			nodeIP := ap.Addr().As4()
			nodePort := ap.Port()
			p.AddRelayFrame(nodeIP, [2]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, n != MaxContent)

			// layer of encryption here
			p.AESEncrypt(cli.secrets[i-1])
		}

		// pad the packet before sending
		p.Pad()

		// partial request is written to first node
		_, err = cli.conn.Write(p.Bytes())
		if err != nil {
			log.Fatal(err)
		}

		// if we didnt write max content, it means we reached the end
		if n != MaxContent {
			break
		}
	}

	// make a response buffer that will keep the response data
	resp := new(bytes.Buffer)
	for {
		tmp := make([]byte, packet.MaxPacketSize)
		_, err := io.ReadFull(cli.conn, tmp)
		if err != nil {
			log.Fatal(err)
		}
		p := packet.NewPacketFromBytes(tmp)
		p.Trim() // make a packet from the incoming bytes and trim it

		// 3x AES decrypt with the shared node secrets
		for i := 0; i < 3; i++ {
			p.AESDecrypt(cli.secrets[i])
		}

		header := p.PopBytes(2)
		length := int(binary.BigEndian.Uint16(p.PopBytes(2))) // read the length from the packet
		resp.Write(p.Bytes()[:length])                        // write that length to the response buffer
		if header[0]&1 == 1 {                                 // if it has a final bit, we can break
			break
		}
	}

	fmt.Println(fmt.Sprintf("received data with length of %v bytes", resp.Len()))

	return resp
}

func closeConn(c net.Conn) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println("closed connection")

}

func Encrypt(data []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, []byte(""))
}

func Decrypt(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, []byte(""))
}

// BytesToPublicKey turns the byte array of a public key to a *rsa.PublicKey struct
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
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
