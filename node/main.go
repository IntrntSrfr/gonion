package main

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
	"strconv"
)

type Handler struct {
	listener net.Listener
	privKey  *rsa.PrivateKey
	pubKey   *rsa.PublicKey
}

type NodeData struct {
	IP   string `json:"ip"`
	Data []byte `json:"data"`
}

type Node struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	PublicKey []byte `json:"public_key"`
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Queries map[string][]string `json:"queries"`
}

func GetOutIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	return conn.LocalAddr().String()
}

func main() {

	var p string
	fmt.Print("what port u wanna use:")
	fmt.Scan(&p)
	fmt.Println()

	localIP := GetOutIP()
	host, _, _ := net.SplitHostPort(localIP)
	fmt.Println("local ip:", host)

	// a node must first create its keypair
	bitSize := 2048

	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	encPub, err := PublicKeyToBytes(&private.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	node := &Node{
		IP:        host,
		Port:      p,
		PublicKey: encPub,
	}
	d, _ := json.MarshalIndent(node, "", "\t")

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
	ln, err := net.Listen("tcp", ":"+p)
	if err != nil {
		log.Fatal(err)
	}

	h := &Handler{
		listener: ln,
		privKey:  private,
		pubKey:   &private.PublicKey,
	}

	h.lissen()
}

func (h *Handler) lissen() {
	log.Println("listening for requests;", h.listener.Addr())
	for {
		c, err := h.listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		//c.SetDeadline(time.Now().Add(time.Second * 30))
		go h.handle(c)
	}
}

func (h *Handler) handle(c net.Conn) {
	defer c.Close()

	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		log.Println(err)
	}
	fmt.Println("bytes read:", n)

	fmt.Println(buf)
	fmt.Println(string(buf))

	header := buf[0]

	// first we want to know what kinda packet header it is
	if header&0x80 == 0x80 {
		// if its a data packet
		fmt.Println("this is a data packet")
		req := HTTPRequest{}
		err = json.Unmarshal(buf[2:n], &req)
		if err != nil {
			log.Println(err)
			return
		}

		// here we can do http request, get a result, and write it back to the other guy! :)

		fmt.Println(req)
	} else if header&0x40 == 0x40 {
		// if its a relay packet
		fmt.Println("this is a relay packet")

		// read byte 2,3,4,5,6,7 for ip and port
		ip := net.IP{buf[2], buf[3], buf[4], buf[5]}
		portInt := binary.BigEndian.Uint16(buf[6:8])
		portString := strconv.Itoa(int(portInt))
		fmt.Println(ip.String(), portString)

		nc, err := net.Dial("tcp", fmt.Sprintf("%v:%v", ip.To4().String(), portString))
		if err != nil {
			log.Println(err)
			return
		}
		nc.Write(buf[8:n])
	} else if header&0x20 == 0x20 {
		// this is an ask packet
		// we use this to find the client secret in the data and return one as well
	}
}

/*
func (h *Handler) handle(c net.Conn) {
	defer c.Close()

	var clientSecret []byte

	buf := make([]byte, 256)

	n, err := c.Read(buf)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("bytes read:", n)

	// for any connection, we will first decrypt their message, get their secret and store it
	decrypted, err := h.Decrypt(buf)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(decrypted, len(decrypted))

	// this should be 65
	clientSecret = decrypted[1:66]
	log.Println("client secret:", clientSecret)

	nodeSecret := make([]byte, 8)
	_, err = rand.Read(nodeSecret)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("node secret:", nodeSecret)

	var key []byte
	key = append(key, clientSecret...)
	key = append(key, nodeSecret...)

	_, err = c.Write(nodeSecret)
	if err != nil {
		log.Println(err)
		return
	}

}
*/

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

func (h *Handler) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, h.pubKey, data, []byte(""))
}

func (h *Handler) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, h.privKey, data, []byte(""))
}

func handle(c net.Conn) {
	defer c.Close()
	log.Println(c.RemoteAddr())
}
