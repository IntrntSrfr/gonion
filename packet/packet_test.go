package packet

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestNewPacket(t *testing.T) {
	p := NewPacket()
	if len(p.data) != 0 {
		t.Errorf("packet should be empty, but has length of %v bytes", len(p.data))
	}
}

func TestNewPacketFromBytes(t *testing.T) {
	// valid, final data packet with length 4 and []byte("test") as data
	data := []byte{129, 0, 0, 4, 116, 101, 115, 116}
	p := NewPacketFromBytes(data)
	if !p.Final() {
		t.Errorf("packet should be final, it is not")
	}

	if ct := p.CurrentFrameType(); ct != DataPacket {
		t.Errorf("packet type should be %v, it is %v", DataPacket, ct)
	}
}

func TestPacket_CurrentFrameType(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want Type
	}{
		{
			name: "valid data packet",
			p:    NewPacket().AddDataFrame([]byte("test"), false),
			want: DataPacket,
		},
		{
			name: "valid relay packet",
			p:    NewPacket().AddRelayFrame([4]byte{1, 2, 3, 4}, [2]byte{1, 2}, false),
			want: RelayPacket,
		},
		{
			name: "valid ask packet",
			p:    NewPacket().AddAskFrame([]byte("test"), false),
			want: AskPacket,
		},
		{
			name: "invalid packet",
			p:    NewPacketFromBytes([]byte{1, 2, 3, 4}),
			want: UnknownPacket,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.CurrentFrameType(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.CurrentFrameType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_Final(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want bool
	}{
		// TODO: Add test cases.
		{
			name: "packet is final",
			p:    NewPacket().AddDataFrame([]byte("test"), true),
			want: true,
		},
		{
			name: "packet is not final",
			p:    NewPacket().AddDataFrame([]byte("test"), false),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Final(); got != tt.want {
				t.Errorf("Packet.Final() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_AddDataFrame(t *testing.T) {
	p := NewPacket()
	p.AddDataFrame([]byte("test"), true)
	if got := p.CurrentFrameType(); got != DataPacket {
		t.Errorf("wanted frame type: %v; got: %v", DataPacket, got)
	}
	p.PopBytes(2) // remove type header

	// test length written in header
	length := binary.BigEndian.Uint16(p.PopBytes(2))
	if length != 4 {
		t.Errorf("wanted length: %v; got: %v", 4, length)
	}

	// test actual length of remaining data
	if len(p.data) != int(length) {
		t.Errorf("wanted length: %v; got: %v", length, len(p.data))
	}
}

func TestPacket_AddRelayFrame(t *testing.T) {
	p := NewPacket()
	p.AddRelayFrame([4]byte{1, 2, 3, 4}, [2]byte{1, 2}, true)
	if got := p.CurrentFrameType(); got != RelayPacket {
		t.Errorf("wanted frame type: %v; got: %v", RelayPacket, got)
	}
}

func TestPacket_AddAskFrame(t *testing.T) {
	p := NewPacket()
	p.AddAskFrame([]byte("key"), true)
	if got := p.CurrentFrameType(); got != AskPacket {
		t.Errorf("wanted frame type: %v; got: %v", AskPacket, got)
	}
}

func TestPacket_PopBytes(t *testing.T) {
	p := NewPacket()
	p.AddDataFrame([]byte("testing"), true)

	got := p.PopBytes(2)

	if len(got) != 2 {
		t.Errorf("wanted to receive 2 bytes from PopBytes(), received %v", len(got))
	}

	if len(p.data) != len([]byte("testing"))+2 {
		t.Errorf("packet data should be %v, it is %v", len([]byte("testing"))+2, len(p.data))
	}
}

func TestPacketAESCrypto(t *testing.T) {
	key := "testing key"
	start := "this is a test string"

	p := NewPacket()
	p.AddDataFrame([]byte(start), true)

	// encrypt 10x
	for i := 0; i < 10; i++ {
		p.AESEncrypt([]byte(key))
	}

	// decrypt 10x
	for i := 0; i < 10; i++ {
		p.AESDecrypt([]byte(key))
	}

	// remove header
	p.PopBytes(4)
	got := string(p.data)
	if got != start {
		t.Errorf("got: %v; want: %v", got, start)
	}
}

func TestPacketRSACrypto(t *testing.T) {
	// generate keypair with 2048 bits
	bitSize := 2048
	private, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Error(err)
	}
	start := "this is a test string"

	p := NewPacket()
	p.AddDataFrame([]byte(start), true)

	err = p.RSAEncrypt(&private.PublicKey)
	if err != nil {
		t.Error(err)
	}

	err = p.RSADecrypt(private)
	if err != nil {
		t.Error(err)
	}

	// remove packet header
	p.PopBytes(4)
	if string(p.data) != start {
		t.Errorf("RSA encryption failed. wanted %v after decrypt; got %v", start, string(p.data))
	}
}

func TestPacket_Bytes(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want []byte
	}{
		{
			name: "valid bytes from data frame",
			p:    NewPacket().AddDataFrame([]byte{1, 2, 3}, true),
			want: []byte{0x81, 0x0, 0x0, 0x3, 0x1, 0x2, 0x3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacketPadTrim(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want []byte
	}{
		{
			name: "valid bytes from data frame",
			p:    NewPacket().AddDataFrame([]byte{1, 2, 3}, true).Pad().Trim(),
			want: []byte{0x81, 0x0, 0x0, 0x3, 0x1, 0x2, 0x3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Bytes(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.Bytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
