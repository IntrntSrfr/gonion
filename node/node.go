package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/packet"
)

// Node represents a node in the gonion-network, it allows users to connect to it and relay data, ask it for requests, or exchange keys
type Node struct {
	privKey     *rsa.PrivateKey
	pubKey      *rsa.PublicKey
	connections map[string]net.Conn
}

// GenerateKeypair generates an RSA keypair and stores them in the *Node
func (h *Node) GenerateKeypair() error {
	bitSize := 2048
	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return err
	}

	h.privKey = private
	h.pubKey = &private.PublicKey
	return nil
}

// PubKeyBytes returns a byte representation of the node public key
func (h *Node) PubKeyBytes() []byte {
	encPub, err := gonion.PublicKeyToBytes(h.pubKey)
	if err != nil {
		log.Fatal(err)
	}
	return encPub
}

func (h *Node) JoinNetwork(host, port string) error {
	n := &gonion.NodeInfo{
		IP:        host,
		Port:      port,
		PublicKey: h.PubKeyBytes(),
	}
	d, err := json.MarshalIndent(n, "", "\t")
	if err != nil {
		return err
	}

	// the node can then add itself to the node directory
	res, err := http.Post(gonion.EndpointNodes, "application/json", bytes.NewBuffer(d))
	if err != nil {
		return err
	}

	// if OK is not returned, something went wrong and the program will exit
	if res.StatusCode != http.StatusOK {
		log.Fatal("unable to join the node network")
	}

	return nil
}

// Run will connect the node to the node network, then start accepting incoming connections and handling them
func (h *Node) Run(host, port string) error {
	err := h.GenerateKeypair()
	if err != nil {
		return err
	}

	err = h.JoinNetwork(host, port)
	if err != nil {
		return err
	}

	return h.StartListen(port)
}

func (h *Node) StartListen(port string) error {
	// start listening for connections at port
	ln, err := net.Listen("tcp", fmt.Sprint(":", port))
	if err != nil {
		return err
	}
	log.Println("started listener at:", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		//c.SetDeadline(time.Now().Add(time.Second * 30))
		go h.Handle(c)
	}
}

func closeConn(c net.Conn, direction string) {
	err := c.Close()
	if err != nil {
		log.Println(err)
	}
	log.Println(fmt.Sprint("closed ", direction, " connection"))
}

func (h *Node) createSecret(cs []byte) ([]byte, []byte, error) {
	// create the node secret
	ns := make([]byte, 16)
	_, err := rand.Read(ns)
	if err != nil {
		return nil, nil, err
	}

	// combine client and node secret, then hash together to complete the AES key
	combined := append(cs, ns...)
	hashed := sha256.New()
	hashed.Write(combined)
	secret := hashed.Sum(nil)

	return secret, ns, nil
}

func (h *Node) Handle(c net.Conn) {
	defer closeConn(c, "incoming")

	first := true // if it is the first connection, we do an RSA decryption check
	var secret []byte

	// read infinitely
	for {
		tmp := make([]byte, 512)
		_, err := io.ReadFull(c, tmp) // always read exactly 512 bytes, as this is equal to one packet. everything else is not interesting
		if err != nil {
			fmt.Println(err)
			return
		}

		p := packet.NewPacketFromBytes(tmp)
		p.Trim()

		// if its the first packet to arrive, we want to RSA decrypt it and to a key exchange
		if first {
			err = p.RSADecrypt(h.privKey)
			if err != nil {
				log.Println(err)
				return
			}

			// if its not an ask packet, we dont care
			if p.CurrentFrameType() != packet.AskPacket {
				return
			}

			// get the key from the packet, store it, then create and return a new key to the client
			p.PopBytes(2)

			// get a combined secret and node secret
			s, ns, err := h.createSecret(p.Bytes())
			if err != nil {
				log.Println(err)
				return
			}
			secret = s

			// send the node secret back to client
			skP := packet.NewPacket().AddDataFrame(ns, true)
			_, err = c.Write(skP.Pad().Bytes())
			if err != nil {
				log.Println(err)
				return
			}

			// we only want to use RSA for the first packet
			first = false
			continue
		}

		// AES decrypt using the AES key
		p.AESDecrypt(secret)

		switch p.CurrentFrameType() {
		case packet.DataPacket:
			h.processData(c, p, secret)
		case packet.RelayPacket:
			h.processRelay(c, p, secret)
		default:
			continue
		}
	}
}

func (h *Node) processData(c net.Conn, f *packet.Packet, key []byte) {
	log.Println("this is a data packet")

	req := new(bytes.Buffer) // track incoming data, put it together after all data packets have been read
	for {
		header := f.PopBytes(2)                               // pop header bytes
		length := int(binary.BigEndian.Uint16(f.PopBytes(2))) // pop the length bytes

		req.Write(f.Bytes()[:length]) // write the length of the packet to the buffer

		if header[0]&0x1 == 1 {
			// if header has FIN bit, break out
			break
		}

		tmp := make([]byte, 512)
		_, err := io.ReadFull(c, tmp)
		f = packet.NewPacketFromBytes(tmp)

		f.AESDecrypt(key)
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				c.Close()
				return
			}
		}
		f.Trim()
	}

	//fmt.Println(req.String())
	httpreq := gonion.HTTPRequest{}
	json.Unmarshal(req.Bytes(), &httpreq)

	//fmt.Println("http request struct:", httpreq)

	res, err := http.Get(fmt.Sprintf("%v://%v%v", httpreq.Scheme, httpreq.Host, httpreq.Path))
	if err != nil {
		c.Write(packet.NewPacket().AddDataFrame([]byte(err.Error()), true).Pad().Bytes())
		c.Close()
		return
	}
	defer res.Body.Close()

	for {
		p := packet.NewPacket()
		part := make([]byte, 256) // we need to read less than MaxPacketSize due to padding being added later
		n, err := io.ReadFull(res.Body, part)
		p.AddDataFrame(part[:n], n != 256)
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				c.Close()
				return
			}
		}
		p.AESEncrypt(key)
		p.Pad()
		c.Write(p.Bytes())
		if n != 256 {
			break
		}
	}
}

// getConnection returns a net.Conn to a given address. If one does not exist, a new is created
func (h *Node) getConnection(ip, port string) (net.Conn, error) {
	cStr := fmt.Sprintf("%v:%v", ip, port)
	if c, ok := h.connections[cStr]; ok {
		return c, nil
	}

	// dial next node
	c, err := net.Dial("tcp", fmt.Sprintf("%v:%v", ip, port))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return c, nil
}

// closeConnection closes and removes a connection from the pool
func (h *Node) closeConnection() {

}

func (h *Node) processRelay(c net.Conn, f *packet.Packet, key []byte) {
	f.PopBytes(2) // pop header
	ipBytes := f.PopBytes(4)
	portBytes := f.PopBytes(2)
	ip := net.IP{ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))

	nc, err := h.getConnection(ip.To4().String(), port)
	if err != nil {
		log.Println(err)
		return
	}

	go func() {
		for {
			f.Pad()
			nc.Write(f.Bytes())
			tmp := make([]byte, 512)
			_, err := io.ReadFull(c, tmp) // read exactly 512 bytes
			if err != nil {
				// if anything goes wrong, close everything
				closeConn(nc, "outgoing")
				closeConn(c, "incoming")
				return
			}
			f = packet.NewPacketFromBytes(tmp) // put the incoming packet bytes into a packet struct
			f.Trim()
			f.AESDecrypt(key)
			f.PopBytes(8) // pop 8 to remove the header from incoming packets. there should be a check to see if its still the same packet type.
		}
	}()

	for {
		tmp := make([]byte, 512)
		_, err := io.ReadFull(nc, tmp) // read exactly 512 bytes again
		if err != nil {
			closeConn(nc, "outgoing")
			closeConn(c, "incoming")
			return
		}
		p := packet.NewPacketFromBytes(tmp)
		p.Trim()

		// trim returning packet, then encrypt, then pad
		p.AESEncrypt(key)

		p.Pad()
		c.Write(p.Bytes())
	}
}
