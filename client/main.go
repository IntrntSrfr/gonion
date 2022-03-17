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
	"io"
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

func closeConn(c net.Conn) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println("closed connection")

}

type HTTPRequest struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Queries map[string][]string `json:"queries"`
}

const MaxContent = 64

func main() {
	/*
		r := make([]byte, 256)
		rand.Read(r)
		fmt.Println(string(r))
		reader := bytes.NewReader(r)

		buf := new(bytes.Buffer)
		for{
			tmp := make([]byte, 70)
			n, err := reader.Read(tmp)
			if err != nil {
				log.Println(err)
				break
			}
			buf.Write(tmp)
			fmt.Println("bytes read:", n)
		}

		fmt.Println(buf.String())

		return*/

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
	innerMsgBuffer := bytes.NewBuffer(d)
	fmt.Println(innerMsgBuffer.Len())

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
		partialMsg = partialMsg[:n]
		if n != MaxContent {
			// final packet
			partialMsg = append([]byte{0x81, 0x00}, partialMsg...)
		} else {
			// full size packet
			partialMsg = append([]byte{0x80, 0x00}, partialMsg...)
		}

		// packet should be encrypted here with node 3 key

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

			partialMsg = append([]byte{byte((nodePort & 0xff00) >> 8), byte(nodePort & 0xff)}, partialMsg...) // add port
			partialMsg = append([]byte{nodeIP[0], nodeIP[1], nodeIP[2], nodeIP[3]}, partialMsg...)            // add ip
			if n != MaxContent {
				// final packet
				partialMsg = append([]byte{0x41, 0x00}, partialMsg...) // add header
			} else {
				// full size packet
				partialMsg = append([]byte{0x40, 0x00}, partialMsg...) // add header
			}

			// it should be a layer of encryption here
		}

		_, err = c.Write(partialMsg)
		if err != nil {
			log.Fatal(err)
		}
		if n != MaxContent {
			break
		}
	}
	/*
		ans := make([]byte, 1024)
		c.Read(ans)
		fmt.Println(string(ans))
	*/
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
