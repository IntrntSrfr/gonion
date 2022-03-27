package packet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/tidwall/secret"
)

// Packet represents a packet of information used by gonion. It supports layering of information for relaying
// information to nodes. The layers also support encryption with both RSA and AES-256.
type Packet struct {
	data []byte
}

const MaxPacketSize = 512

// Type represents the type of data we are looking at
type Type int

const (
	UnknownPacket Type = 1 << iota
	RelayPacket
	DataPacket
	AskPacket
)

// NewPacket creates a new packet with zero data
func NewPacket() *Packet {
	return &Packet{data: []byte{}}
}

// NewPacketFromBytes wraps existing data into a new Packet struct
func NewPacketFromBytes(data []byte) *Packet {
	return &Packet{data: data}
}

// CurrentFrameType returns the Type of the packet at the current top layer
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

// Pad pads the packet with null bytes up to MaxPacketLength - 2. The 2 final bytes tells how much padding
//was added, such that Packet.Trim() might function properly.
func (p *Packet) Pad() *Packet {
	dst := make([]byte, MaxPacketSize)                           // make a new buffer
	padAmt := MaxPacketSize - len(p.data) - 2                    // find how much we need to pad
	copy(dst, p.data)                                            // copy the current data into the new buffer
	binary.BigEndian.PutUint16(dst[len(dst)-2:], uint16(padAmt)) // set the final 2 bytes to the pad amount
	p.data = dst
	return p
}

// Trim trims the packet n bytes, where n is the 2 final bytes in the packet data.
func (p *Packet) Trim() *Packet {
	trimAmt := binary.BigEndian.Uint16(p.data[len(p.data)-2:])
	p.data = p.data[:len(p.data)-int(trimAmt)-2]
	return p
}

// AddDataFrame adds a data frame to a Packet. It will take some data, wrap it in a frame
// that contains a DataPacket header, and the data length
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
	enc, err := secret.Encrypt(string(key), p.data)
	if err != nil {
		panic(err)
	}
	p.data = enc
}

// AESDecrypt AES decrypts the current bytearray with a provided key
func (p *Packet) AESDecrypt(key []byte) {
	dec, err := secret.Decrypt(string(key), p.data)
	if err != nil {
		panic(dec)
	}
	p.data = dec
}

// RSAEncrypt RSA encrypts the current bytearray with a provided key
func (p *Packet) RSAEncrypt(pub *rsa.PublicKey) error {
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, p.data, []byte(""))
	p.data = enc
	return err
}

// RSADecrypt DSA encrypts the current bytearray with a provided key
func (p *Packet) RSADecrypt(priv *rsa.PrivateKey) error {
	dec, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, p.data, []byte(""))
	p.data = dec
	return err
}

// Bytes returns the underlying bytearray
func (p *Packet) Bytes() []byte {
	return p.data
}
