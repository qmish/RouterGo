//go:build windows

package platform

import (
	"router-go/internal/platform/windows"
	"router-go/pkg/network"
)

func NewPacketIO(opts Options) (network.PacketIO, error) {
	return windows.NewPacketIO(windows.Options{Interface: opts.Interface})
}
