package network

import "context"

type Interface struct {
	Name  string
	IP    string
	Stats InterfaceStats
}

type InterfaceStats struct {
	Packets uint64
	Bytes   uint64
	Errors  uint64
}

type PacketIO interface {
	ReadPacket(ctx context.Context) (Packet, error)
	WritePacket(ctx context.Context, pkt Packet) error
	Close() error
}
