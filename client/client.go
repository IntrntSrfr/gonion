package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/packet"
)

var ErrTooFewNodes = errors.New("too few nodes were passed")

// NodeCount will be 3 for this client.
const NodeCount = 3

// MaxContent is the max amount of bytes a data frame can hold as a maximum
const MaxContent = 256

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
	err := cli.conn.Close()
	if err != nil {
		log.Println(err)
	}
}

// Do uses the client to send an HTTPRequest through the node network and get a response back.
// It creates a new Client for every request to make sure that secrets and nodes are new for each request.
func Do(req *gonion.HTTPRequest) (*bytes.Buffer, error) {
	rand2.Seed(time.Now().Unix())                    // init random for node selection
	c := &Client{directoryURL: gonion.EndpointNodes} // for each request, create a new client
	return c.do(req)
}

// do performs a key exchange with the node network, then sends a request through it and receives a response
func (cli *Client) do(req *gonion.HTTPRequest) (*bytes.Buffer, error) {
	if req == nil {
		log.Fatal("request body cannot be nil")
	}

	// make a buffer from the request input
	inner := bytes.NewBuffer(marshalRequest(req))

	// first we must get the node info
	nodes, err := cli.getNodeNetwork()
	if err != nil {
		return nil, err
	}
	/*
		// random selection is not working as intended, so for now this will have to wait
		nodes, err := cli.getNodeSelection(network, NodeCount)
		if err != nil {
			log.Fatal(err)
		}
	*/
	if len(nodes) < NodeCount {
		log.Fatal("too few nodes")
	}

	// connect with the first node and keep track of it
	cli.connect(nodes[0])
	defer cli.closeConnection()

	// exchange secrets with each node and keep track of them
	err = cli.exchangeSecrets()
	if err != nil {
		return nil, err
	}

	// partition the body into sizes we want to manage
	// send each packet separately to the next node
	for {
		partialMsg := make([]byte, MaxContent)
		n, err := io.ReadFull(inner, partialMsg) // read from the inner message buffer into several partial messages
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		p := packet.NewPacket()
		p.AddDataFrame(partialMsg[:n], n != MaxContent) // if n != max content, it means we reached the end of the data.

		// packet should be encrypted here with node 3 key
		err = p.AESEncrypt(cli.secrets[len(cli.secrets)-1])
		if err != nil {
			return nil, err
		}

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
			err = p.AESEncrypt(cli.secrets[i-1])
			if err != nil {
				return nil, err
			}
		}

		// pad the packet before sending
		p.Pad()

		// partial request is written to first node
		_, err = cli.conn.Write(p.Bytes())
		if err != nil {
			log.Fatal(err)
		}

		// if we did not write max content, it means we reached the end
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
			return nil, err
		}
		p := packet.NewPacketFromBytes(tmp)
		p.Trim() // make a packet from the incoming bytes and trim it

		// 3x AES decrypt with the shared node secrets
		for i := 0; i < 3; i++ {
			err = p.AESDecrypt(cli.secrets[i])
			if err != nil {
				return nil, err
			}
		}

		header := p.PopBytes(2)
		length := int(binary.BigEndian.Uint16(p.PopBytes(2))) // read the length from the packet
		resp.Write(p.Bytes()[:length])                        // write that length to the response buffer
		if header[0]&1 == 1 {                                 // if it has a final bit, we can break
			break
		}
	}

	fmt.Println(fmt.Sprintf("received data with length of %v bytes", resp.Len()))

	return resp, nil
}

// getNodeNetwork fetches node info from the directory node, tracks and returns it
func (cli *Client) getNodeNetwork() ([]*gonion.NodeInfo, error) {
	res, err := http.DefaultClient.Get(cli.directoryURL)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	cli.nodes = nodes
	return nodes, nil
}

// getNodeSelection returns n *NodeInfo objects, selected in a random order.
func (cli *Client) getNodeSelection(nodes []*gonion.NodeInfo, n int) ([]*gonion.NodeInfo, error) {
	if len(nodes) < n {
		return nil, ErrTooFewNodes
	}

	var selection []*gonion.NodeInfo
	indices := rand2.Perm(len(nodes))
	for i := 0; i < 3; i++ {
		selection = append(selection, nodes[indices[i]])
	}

	return selection, nil
}

// exchangeSecrets exchanges secrets with 3 nodes and tracks them for later use
func (cli *Client) exchangeSecrets() error {
	s1, err := cli.exchangeSecret(cli.nodes[0])
	if err != nil {
		return err
	}
	cli.secrets = append(cli.secrets, s1)

	s2, err := cli.exchangeSecret(cli.nodes[1], cli.nodes[1])
	if err != nil {
		return err
	}
	cli.secrets = append(cli.secrets, s2)

	s3, err := cli.exchangeSecret(cli.nodes[2], cli.nodes[2], cli.nodes[1])
	if err != nil {
		return err
	}
	cli.secrets = append(cli.secrets, s3)

	return nil
}

// exchangeSecret connects to a node through an amount of relays and exchanges a secret with it
func (cli *Client) exchangeSecret(node *gonion.NodeInfo, relays ...*gonion.NodeInfo) ([]byte, error) {
	pub, _ := gonion.BytesToPublicKey(node.PublicKey)
	askP := packet.NewPacket()

	// make the client secret
	ck := make([]byte, 16)
	_, err := rand.Read(ck)
	if err != nil {
		return nil, err
	}

	// add an ask frame containing the client secret
	askP.AddAskFrame(ck, true)

	// RSA encrypt the client secret with the public key from the input node
	err = askP.RSAEncrypt(pub)
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
		err = askP.AESEncrypt(cli.secrets[len(cli.secrets)-i-1])
		if err != nil {
			return nil, err
		}
	}
	askP.Pad() // pad packet before sending

	// send ask packet
	_, err = cli.conn.Write(askP.Bytes())
	if err != nil {
		return nil, err
	}

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
		err = skP.AESDecrypt(cli.secrets[i])
		if err != nil {
			return nil, err
		}
	}

	// pop the data frame header, it isnt needed
	skP.PopBytes(4)
	sk := skP.Bytes() // the only data left will be the node secret

	sharedKey := append(ck, sk...)
	hashed := sha256.New()
	hashed.Write(sharedKey)
	secret := hashed.Sum(nil) // create the final secret for the input node

	return secret, nil
}
