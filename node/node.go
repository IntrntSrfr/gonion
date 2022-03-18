package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/intrntsrfr/gonion/packet"
	"io"
	"log"
	"net"
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
		go h.handle(c)
	}
}

func (h *Node) handle(c net.Conn) {
	defer func() {
		err := c.Close()
		if err != nil {
			log.Println(err)
		}
		log.Println("closed incoming connection")
	}()

	//nodeBody := new(bytes.Buffer)

	// read a new 1kb packet
	tmp := make([]byte, 1024)
	n, err := c.Read(tmp)
	if err != nil && err != io.EOF {
		log.Println(err)
		return
	}
	fmt.Println("read packet with byte length:", n)

	p := packet.NewPacketFromBytes(tmp[:n])

	// here we should also decrypt the packet to see whatever contents come next

	// find what kinda packet it is
	switch p.CurrentFrameType() {
	case packet.DataPacket:
		fmt.Println("this is a data packet")
		// if data packets are present, read till FIN bit, then break?

	case packet.RelayPacket:
		fmt.Println("this is a relay packet")
		// decode packet, send it to next receiver
		// start reading all incoming data, then write it back to the old connection, until EOF?
		/*
			ip := net.IP{tmp[2], tmp[3], tmp[4], tmp[5]}
			portInt := binary.BigEndian.Uint16(tmp[6:8])
			portString := strconv.Itoa(int(portInt))
			fmt.Println(ip.String(), portString)

			// dial the next connection
			nc, err := net.Dial("tcp", fmt.Sprintf("%v:%v", ip.To4().String(), portString))
			if err != nil {
				log.Println(err)
				return
			}
			defer nc.Close()
		*/
	case packet.AskPacket:
		fmt.Println("this is an ask packet")
		// here we should read the body contents after 2 bytes to find the secret from the client.
		// store the secret. generate a secret, send it back to the previous connection.
	default:
	}

	p.PrintInfo()

	//c.Write([]byte("this is your response!!!"))

	/*

		// change this so it reads till its got a final packet?
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil && err != io.EOF {
			log.Println(err)
		}
		fmt.Println("bytes read:", n)

		fmt.Println(buf[:n])
		fmt.Println(string(buf[:n]))

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

			res, _ := http.Get(fmt.Sprintf("%v://%v%v", req.Scheme, req.Host, req.Path))
			defer res.Body.Close()

			for {
				part := make([]byte, 1024)
				_, err = res.Body.Read(part)
				if err != nil && err == io.EOF {
					break
				}
			}

			fmt.Println(req)
			return

			// write back
			//c.Write([]byte("here is your response!!!"))

			// here we can do http request, get a result, and write it back to the other guy! :)

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
			defer func() {
				err := nc.Close()
				if err != nil {
					log.Println()
				}
				log.Println("closed outgoing connection")
			}()

			// write the entire buffer to the next relay
			nc.Write(buf[8:n])

			// read the whole answer
			ans := make([]byte, 1024)
			for {
				_, err = nc.Read(ans)
				if err != nil {
					log.Println(err)
					break
				}

				c.Write(ans)
			}
		} else if header&0x20 == 0x20 {
			// this is an ask packet
			// we use this to find the client secret in the data and return one as well
		}
	*/
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

func handle(c net.Conn) {
	defer c.Close()
	log.Println(c.RemoteAddr())
}
