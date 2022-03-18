package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/intrntsrfr/gonion"
	"log"
	"net/http"
	"net/url"
)

func ParseRequest(inp string) *gonion.HTTPRequest {
	u, err := url.Parse(inp)
	if err != nil {
		log.Fatal(err)
	}
	return &gonion.HTTPRequest{
		Method:  "GET",
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		Queries: u.Query(),
	}
}

func GetNodes() []*gonion.NodeInfo {
	res, err := http.DefaultClient.Get("http://localhost:9051/api/nodes")
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
	return nodes
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
