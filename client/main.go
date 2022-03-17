package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
)

type Node struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	PublicKey []byte `json:"public_key"`
}

func PKCSPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCSTrimming(ciphertext []byte) []byte {
	padding := ciphertext[len(ciphertext)-1]
	return ciphertext[:len(ciphertext)-int(padding)]
}

func AESEncrypt(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	data = PKCSPadding(data, c.BlockSize())
	out := make([]byte, len(data))
	fmt.Println("before encoding with padding", data)
	fmt.Println(hex.EncodeToString(data))
	c.Encrypt(out, data)
	return out
}

func AESDecrypt(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	pt := make([]byte, len(data))
	c.Decrypt(pt, data)
	//fmt.Println("DECODED BEFORE REMOVE PADDING:",pt)
	pt = PKCSTrimming(pt)
	return pt
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Queries map[string][]string `json:"queries"`
}

func main() {

	a := "http://localhost:9051/api/nodes?weed=fart"
	adr, err := url.Parse(a)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(adr.Scheme, adr.Host, adr.Path, adr.Query())

	req := &HTTPRequest{
		Method:  "GET",
		Scheme:  adr.Scheme,
		Host:    adr.Host,
		Path:    adr.Path,
		Queries: adr.Query(),
	}

	d, _ := json.Marshal(req)

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

	if len(nodes) < 3 {
		log.Fatal("too few nodes")
	}

	// this creates the inner packet, with the actual message.
	var packet []byte
	packet = append(packet, 0x81, 0x00)
	packet = append(packet, d...)

	// can make a for loop here to loop if request is large, breaking if its small enough and sends the final message

	// create the packets
	node1 := nodes[0]

	// add 2x relay header
	for i := 2; i > 0; i-- {
		node := nodes[i]
		ap, err := netip.ParseAddrPort(fmt.Sprintf("%v:%v", node.IP, node.Port))
		if err != nil {
			log.Fatal(err)
		}
		nodeIP := ap.Addr().As4()
		nodePort := ap.Port()

		packet = append([]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, packet...) // add port
		packet = append([]byte{nodeIP[0], nodeIP[1], nodeIP[2], nodeIP[3]}, packet...)            // add ip
		packet = append([]byte{0x40, 0x00}, packet...)                                            // add header
	}

	// dont need a layer for node 1 as its directly connected
	c, err := net.Dial("tcp", fmt.Sprintf("%v:%v", node1.IP, node1.Port))
	if err != nil {
		log.Fatal(err)
	}
	c.Write(packet)
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

func RelayHeader() byte {
	return 0b00100001
}

type DataFrame []byte

func fireRequest() {
	// get the nodes from the node directory

	// get secret for first node

	// get secret for second node

	// get secret for last node

	// create the request

	// encrypt request with 3 layers from public keys

	// fire request to the first node

	// wait for a response

	// decrypt response using the 3 node secrets

}
