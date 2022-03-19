package packet

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

// Packet represents a packet of information used by gonion. It supports layering of information for relaying
// information to nodes. The layers also support encryption with both RSA and AES-256.
type Packet struct {
	data []byte
}

const MaxPacketSize = 512

type Type int

const (
	UnknownPacket Type = 1 << iota
	RelayPacket
	DataPacket
	AskPacket
)

func NewPacket() *Packet {
	return &Packet{data: []byte{}}
}

func NewPacketFromBytes(data []byte) *Packet {
	return &Packet{data: data}
}

func (p *Packet) CurrentFrameType() Type {
	if p.data[0]&0x80 == 0x80 {
		return DataPacket
	} else if p.data[0]&0x40 == 0x40 {
		return RelayPacket
	} else if p.data[0]&0x20 == 0x20 {
		return AskPacket
	}
	return UnknownPacket
}

func (p *Packet) Final() bool {
	return p.data[0]&1 == 1
}

func (p *Packet) Pad() {
	p.data = append(p.data, make([]byte, MaxPacketSize-len(p.data))...)
}

func (p *Packet) AddDataFrame(data []byte, final bool) *Packet {
	p.data = append(data, p.data...)
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, uint16(len(data)))

	p.data = append(size, p.data...)
	if final {
		p.data = append([]byte{0x81, 0x00}, p.data...)
	} else {
		p.data = append([]byte{0x80, 0x00}, p.data...)
	}
	return p
}

func (p *Packet) AddRelayFrame(ip [4]byte, port [2]byte, final bool) *Packet {
	p.data = append([]byte{port[0], port[1]}, p.data...)
	p.data = append([]byte{ip[0], ip[1], ip[2], ip[3]}, p.data...)
	if final {
		p.data = append([]byte{0x41, 0x00}, p.data...)
	} else {
		p.data = append([]byte{0x40, 0x00}, p.data...)
	}
	return p
}

func (p *Packet) AddAskFrame(key []byte, final bool) *Packet {
	p.data = append(key, p.data...)
	if final {
		p.data = append([]byte{0x21, 0x00}, p.data...)
	} else {
		p.data = append([]byte{0x20, 0x00}, p.data...)
	}
	return p
}

// PopBytes pops n leading bytes from the current bytearray and returns it
func (p *Packet) PopBytes(n int) []byte {
	pop := p.data[:n]
	p.data = p.data[n:]
	return pop
}

func (p *Packet) PrintInfo() {
	fmt.Println("--- PACKET  INFO ---")
	fmt.Println("packet length:", len(p.Bytes()))
	fmt.Println("packet data as string:", string(p.Bytes()))
	fmt.Println("packet data as bytes:", p.Bytes())
	fmt.Println("---  PACKET END  ---")
	fmt.Println()
}

// AESEncrypt AES encrypts the current bytearray with a provided key
func (p *Packet) AESEncrypt(key []byte) {

}

// AESDecrypt AES decrypts the current bytearray with a provided key
func (p *Packet) AESDecrypt(key []byte) {

}

// RSAEncrypt RSA encrypts the current bytearray with a provided key
func (p *Packet) RSAEncrypt(key *rsa.PublicKey) {

}

// RSADecrypt DSA encrypts the current bytearray with a provided key
func (p *Packet) RSADecrypt(key *rsa.PrivateKey) {

}

// Bytes returns the underlying bytearray
func (p *Packet) Bytes() []byte {
	return p.data
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
