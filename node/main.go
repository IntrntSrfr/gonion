package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
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
	IP        string
	PublicKey string
}

func main() {
	// a node must first create its keypair
	bitSize := 2048

	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}


	

	// the node can then add itself to the node directory
	res, err := http.Post("localhost:9002", "application/json", )
	if err != nil {
		log.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		log.Fatal("unable to join the node network")
	}

	log.Println("joined node network")

	// start listening for connections
	ln, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatal(err)
	}

	h := &Handler{
		listener: ln,
		privKey:  private,
		pubKey:   &private.PublicKey,
	}

	h.lissen()

	/*
		b, err := h.Encrypt([]byte("weed"))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println([]byte("weed"))
		fmt.Println(b)

		c, err := h.Decrypt(b)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(c))
	*/
}

func (h *Handler) lissen() {
	log.Println("listening for requests;", h.listener.Addr())
	for {
		c, err := h.listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go h.handle(c)
	}
}

func (h *Handler) handle(c net.Conn) {
	defer c.Close()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 256)

	for {
		n, err := c.Read(tmp)
		if err != nil {
			if err != io.EOF {
				c.Write([]byte(err.Error()))
				log.Println(err)
				return
			}
			break
		}
		buf = append(buf, tmp[:n]...)
	}

	decrypted, err := h.Decrypt(buf)
	if err != nil {
		c.Write([]byte(err.Error()))
		log.Println(err)
		return
	}

	data := &NodeData{}
	err = json.Unmarshal(decrypted, data)
	if err != nil {
		// this means that it does not contain node data. AKA it should be an HTTP request.

	}

	// if we are here, then we have node data and should dial the next node and send it data.

	nc, err := net.Dial("tcp", data.IP)
	if err != nil {
		c.Write([]byte(err.Error()))
		log.Println(err)
		return
	}
	defer nc.Close()

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
