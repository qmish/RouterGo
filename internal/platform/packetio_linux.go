//go:build linux

package platform

import (
	"router-go/internal/platform/linux"
	"router-go/pkg/network"
)

func NewPacketIO(opts Options) (network.PacketIO, error) {
	return linux.NewPacketIO(linux.Options{Interface: opts.Interface})
}
