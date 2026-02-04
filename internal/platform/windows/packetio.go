//go:build windows

package windows

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
	return nil, fmt.Errorf("windows packet io not implemented")
}
