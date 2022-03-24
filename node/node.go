package node

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

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/packet"
)

type Node struct {
	listener    net.Listener
	privKey     *rsa.PrivateKey
	pubKey      *rsa.PublicKey
	connections map[string]net.Conn
}

func (h *Node) GenerateKeypair() {

	// a node must first create its keypair
	bitSize := 2048
	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}
	h.privKey = private
	h.pubKey = &private.PublicKey
}

func (h *Node) PubKeyBytes() []byte {
	encPub, err := PublicKeyToBytes(h.pubKey)
	if err != nil {
		log.Fatal(err)
	}
	return encPub
}

func (h *Node) StartListenAtPort(port string) {

	// start listening for connections
	ln, err := net.Listen("tcp", fmt.Sprint(":", port))
	if err != nil {
		log.Fatal(err)
	}
	h.listener = ln
}

func (h *Node) Listen() {
	log.Println("listening for requests;", h.listener.Addr())
	for {
		c, err := h.listener.Accept()
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

func (h *Node) Handle(c net.Conn) {
	defer closeConn(c, "incoming")

	first := true
	var secret []byte

	// read infinitely
	for {
		tmp := make([]byte, 512)
		_, err := io.ReadFull(c, tmp) // always read exactly 512 bytes, as this is equal to one packet. everything else is not interesting
		if err != nil {
			return
		}

		p := packet.NewPacketFromBytes(tmp)
		//p.PrintInfo()
		p.Trim()

		if first {
			err = p.RSADecrypt(h.privKey)
			if err != nil {
				log.Println(err)
				return
			}
			if p.CurrentFrameType() != packet.AskPacket {
				return
			}
			fmt.Println("this is the decrypted packet")
			p.PrintInfo()

			// get the key from the packet, store it, then create and return a new key to the client
			p.PopBytes(2)

			ck := p.Bytes()

			sk := make([]byte, 16)
			rand.Read(sk)

			skP := packet.NewPacket().AddDataFrame(sk, true)

			combined := append(ck, sk...)

			fmt.Println("SHARED KEY:", combined)

			hashed := sha256.New()
			hashed.Write(combined)
			secret = hashed.Sum(nil)

			fmt.Println("HASHED SHARED KEY:", secret)

			c.Write(skP.Pad().Bytes())
			fmt.Println("SENT KEY BACK TO CLIENT")
			first = false
			continue
		}

		//p.PrintInfo()
		// decrypt one layer here
		//key := "siggarett"
		p.AESDecrypt(secret)
		//p.PrintInfo()

		switch p.CurrentFrameType() {
		case packet.DataPacket:
			h.processData(c, p, secret)
		case packet.RelayPacket:
			h.processRelay(c, p, secret)
		case packet.AskPacket:
			h.processAsk(c, p)
		default:
			continue
		}
	}
}

func (h *Node) processData(c net.Conn, f *packet.Packet, key []byte) {
	log.Println("this is a data packet")

	req := new(bytes.Buffer) // track incoming data, put it together after all data packets have been read
	for {
		f.PrintInfo()
		header := f.PopBytes(2)                               // pop header bytes
		length := int(binary.BigEndian.Uint16(f.PopBytes(2))) // pop the length bytes

		req.Write(f.Bytes()[:length]) // write the length of the packet to the buffer

		if header[0]&0x1 == 1 {
			// if header has FIN bit, break out
			break
		}

		tmp := make([]byte, 512)
		_, err := io.ReadFull(c, tmp)
		//n, err := c.Read(tmp)
		f = packet.NewPacketFromBytes(tmp)

		//key := "siggarett"
		f.AESDecrypt(key)
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				c.Close()
				return
			}
		}
		f.Trim()
		//f = packet.NewPacketFromBytes(tmp)
	}

	fmt.Println(req.String())
	httpreq := gonion.HTTPRequest{}
	json.Unmarshal(req.Bytes(), &httpreq)

	fmt.Println("http request struct:", httpreq)

	res, err := http.Get(fmt.Sprintf("%v://%v%v", httpreq.Scheme, httpreq.Host, httpreq.Path))
	if err != nil {
		c.Write(packet.NewPacket().AddDataFrame([]byte(err.Error()), true).Pad().Bytes())
		c.Close()
		return
	}
	defer res.Body.Close()

	//log.Println("attempting to reply")
	for {
		//fmt.Println("reading response...")
		p := packet.NewPacket()
		part := make([]byte, 256) // we need to read 506, as 4 bytes will be for data header, and 2 bytes for padding
		n, err := io.ReadFull(res.Body, part)
		p.AddDataFrame(part[:n], n != 256)
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				c.Close()
				return
			}
		}
		/*
			//n, err := res.Body.Read(part)
			if err != nil {
				fmt.Println(err)
				if err != io.EOF {
					c.Write(packet.NewPacket().AddDataFrame([]byte("fail army"), true).Pad().Bytes())
					c.Close()
					return
				}
			} */

		//p := packet.NewPacket()
		//p.AddDataFrame(part[:n], n != 508)
		//p.PrintInfo()
		p.AESEncrypt(key)
		p.Pad()
		//p.PrintInfo()
		//fmt.Println("sending reply packet...")
		c.Write(p.Bytes())
		if n != 256 {
			break
		}
	}
}

// getConnection returns a net.Conn to a given address. If one does not exist, a new is created
func (h *Node) getConnection(ip, port string) (net.Conn, error) {
	cStr := fmt.Sprint("%v:%v", ip, port)
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
	log.Println("this is a relay packet")
	//f.PrintInfo()
	f.PopBytes(2)

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
			//f.PrintInfo()
			f.Pad()
			nc.Write(f.Bytes())

			if f.Final() {
				break
			}

			tmp := make([]byte, 512)
			_, err := io.ReadFull(c, tmp) // read exactly 512 bytes
			//_, err := c.Read(tmp)
			if err != nil {
				// if anything goes wrong, close everything
				nc.Close()
				c.Close()
				return
			}
			f = packet.NewPacketFromBytes(tmp) // put the incoming packet bytes into a packet struct
			f.Trim()
			f.AESDecrypt(key)
			//f.PrintInfo()
			f.PopBytes(8) // pop 8 to remove the header from incoming packets. there should be a check to see if its still the same packet type.
		}
	}()

	for {
		//fmt.Println("sending back...")
		tmp := make([]byte, 512)
		_, err := io.ReadFull(nc, tmp) // read exactly 512 bytes again
		if err != nil {
			nc.Close()
			c.Close()
			return
		}
		p := packet.NewPacketFromBytes(tmp)
		//p.PrintInfo()
		p.Trim()
		//p.PrintInfo()

		// trim returning packet, then encrypt, then pad
		p.AESEncrypt(key)

		p.Pad()
		//p.PrintInfo()
		c.Write(p.Bytes())
		/*
			if p.Final() {
				break
			} */
	}
}

func (h *Node) processAsk(c net.Conn, f *packet.Packet) {
	log.Println("this is an ask packet")
	f.PrintInfo()
	f.PopBytes(2)
}

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

func (h *Node) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, h.pubKey, data, []byte(""))
}

func (h *Node) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, h.privKey, data, []byte(""))
}
