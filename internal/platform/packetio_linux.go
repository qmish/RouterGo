//go:build linux

package platform

import (
	"context"

	"router-go/pkg/network"
)

type linuxPacketIO struct{}

func NewPacketIO(opts Options) (network.PacketIO, error) {
	return &linuxPacketIO{}, nil
}

func (l *linuxPacketIO) ReadPacket(ctx context.Context) (network.Packet, error) {
	return network.Packet{}, ErrNotSupported
}

func (l *linuxPacketIO) WritePacket(ctx context.Context, pkt network.Packet) error {
	return ErrNotSupported
}

func (l *linuxPacketIO) Close() error {
	return nil
}
