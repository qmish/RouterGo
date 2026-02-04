//go:build linux

package platform

import "router-go/pkg/network"

func NewPacketIO(opts Options) (network.PacketIO, error) {
	return nil, ErrNotSupported
}
