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
	listener net.Listener
	privKey  *rsa.PrivateKey
	pubKey   *rsa.PublicKey
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

	// read infinitely
	for {
		tmp := make([]byte, 512)
		_, err := io.ReadFull(c, tmp)
		if err != nil {
			return
			/*
				if err != io.EOF {
					log.Println(err)
					return
				}
				continue
			*/
		}

		p := packet.NewPacketFromBytes(tmp)
		p.PrintInfo()
		p.Trim()
		// decrypt one layer here
		//key := "siggarett"

		//p.AESDecrypt([]byte(key))

		switch p.CurrentFrameType() {
		case packet.DataPacket:
			h.processData(c, p)
		case packet.RelayPacket:
			h.processRelay(c, p)
		case packet.AskPacket:
			h.processAsk(c, p)
		default:
			continue
		}
	}
}

func (h *Node) processData(c net.Conn, f *packet.Packet) {
	log.Println("this is a data packet")

	req := new(bytes.Buffer)

	for {
		//f.PrintInfo()
		header := f.PopBytes(2)
		length := int(binary.BigEndian.Uint16(f.PopBytes(2)))
		fmt.Println(header, length)

		req.Write(f.Bytes()[:length])

		if header[0]&0x1 == 1 {
			break
		}

		tmp := make([]byte, 512)
		_, err := c.Read(tmp)
		if err != nil {
			return
		}
		f = packet.NewPacketFromBytes(tmp)
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
	/*
		resp, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
			return
		}

		fmt.Println("response bytes:", resp)
		fmt.Println("response string:", string(resp))
	*/
	log.Println("attempting to reply")
	for {
		p := packet.NewPacket()
		part := make([]byte, 508)
		n, err := io.ReadFull(res.Body, part)
		p.AddDataFrame(part[:n], n != 508)
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
		p.Pad()
		//p.PrintInfo()
		fmt.Println("sending reply packet...")
		c.Write(p.Bytes())
		if n != 508 {
			break
		}
	}
}

func (h *Node) processRelay(c net.Conn, f *packet.Packet) {
	log.Println("this is a relay packet")
	//f.PrintInfo()
	f.PopBytes(2)

	ipBytes := f.PopBytes(4)
	portBytes := f.PopBytes(2)
	ip := net.IP{ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))

	// dial next node
	nc, err := net.Dial("tcp", fmt.Sprint(ip.To4().String(), ":", port))
	if err != nil {
		log.Println(err)
		return
	}
	defer closeConn(nc, "outgoing")

	for {
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
		//f.PrintInfo()
		f.PopBytes(8) // pop 8 to remove the header from incoming packets. there should be a check to see if its still the same packet type.
	}

	for {
		fmt.Println("sending back...")
		tmp := make([]byte, 512)
		_, err := io.ReadFull(nc, tmp) // read exactly 512 bytes again
		if err != nil {
			nc.Close()
			c.Close()
			return
		}
		p := packet.NewPacketFromBytes(tmp)
		//p.PrintInfo()

		// trim returning packet, then encrypt, then pad

		p.Pad()
		c.Write(p.Bytes())
		if p.Final() {
			break
		}
	}
}

func (h *Node) processAsk(c net.Conn, f *packet.Packet) {
	log.Println("this is an ask packet")
	f.PrintInfo()
	f.PopBytes(2)

}

/*
func (h *Node) handle(c net.Conn) {
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

func (h *Node) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, h.pubKey, data, []byte(""))
}

func (h *Node) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, h.privKey, data, []byte(""))
}
