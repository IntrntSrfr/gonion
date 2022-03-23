package packet

import (
	"reflect"
	"testing"
)

func TestNewPacket(t *testing.T) {
	tests := []struct {
		name string
		want *Packet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPacket(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPacketFromBytes(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want *Packet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPacketFromBytes(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPacketFromBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_CurrentFrameType(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want Type
	}{
		// TODO: Add test cases.
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
	type args struct {
		data  []byte
		final bool
	}
	tests := []struct {
		name string
		p    *Packet
		args args
		want *Packet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AddDataFrame(tt.args.data, tt.args.final); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.AddDataFrame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_AddRelayFrame(t *testing.T) {
	type args struct {
		ip    [4]byte
		port  [2]byte
		final bool
	}
	tests := []struct {
		name string
		p    *Packet
		args args
		want *Packet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AddRelayFrame(tt.args.ip, tt.args.port, tt.args.final); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.AddRelayFrame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_AddAskFrame(t *testing.T) {
	type args struct {
		key   []byte
		final bool
	}
	tests := []struct {
		name string
		p    *Packet
		args args
		want *Packet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AddAskFrame(tt.args.key, tt.args.final); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.AddAskFrame() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_PopBytes(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name string
		p    *Packet
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.PopBytes(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Packet.PopBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPacket_AESEncrypt(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		p    *Packet
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.AESEncrypt(tt.args.key)
		})
	}
}

func TestPacket_AESDecrypt(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name string
		p    *Packet
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.AESDecrypt(tt.args.key)
		})
	}
}

func TestPacket_Bytes(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want []byte
	}{
		// TODO: Add test cases.
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

func TestPacket_PadTrim(t *testing.T) {
	tests := []struct {
		name string
		p    *Packet
		want []byte
	}{
		// TODO: Add test cases.
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

func TestPKCSPadding(t *testing.T) {
	type args struct {
		ciphertext []byte
		blockSize  int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCSPadding(tt.args.ciphertext, tt.args.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCSPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCSTrimming(t *testing.T) {
	type args struct {
		ciphertext []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCSTrimming(tt.args.ciphertext); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCSTrimming() = %v, want %v", got, tt.want)
			}
		})
	}
}
