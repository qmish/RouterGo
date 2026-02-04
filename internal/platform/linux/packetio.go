//go:build linux

package linux

import (
	"fmt"

	"router-go/internal/config"
	"router-go/pkg/network"
)

type Options struct {
	Interface config.InterfaceConfig
}

type packetIO struct{}

func NewPacketIO(opts Options) (network.PacketIO, error) {
	return nil, fmt.Errorf("linux packet io not implemented")
}
