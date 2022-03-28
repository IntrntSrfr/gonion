package gonion

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrFailedAssertion = errors.New("could not assert rsa public key")
	ErrFailedRSADecode = errors.New("block is nil or not RSA PUBLIC KEY type")
)

// conversion to and from bytes is heavily inspired from a gist
// https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a

// PublicKeyToBytes converts a public key to its []byte representation in PEM format
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPublicKey converts a []byte to a *rsa.PublicKey from a PEM format
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, ErrFailedRSADecode
	}
	ifc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, ErrFailedAssertion
	}
	return key, nil
}
