//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"router-go/pkg/network"

	"golang.org/x/sys/unix"
)

type linuxPacketIO struct {
	fd      int
	ifindex int
}

func NewPacketIO(opts Options) (network.PacketIO, error) {
	if opts.Interface.Name == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	iface, err := net.InterfaceByName(opts.Interface.Name)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set nonblock: %w", err)
	}

	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	return &linuxPacketIO{fd: fd, ifindex: iface.Index}, nil
}

func (p *linuxPacketIO) ReadPacket(ctx context.Context) (network.Packet, error) {
	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(p.fd, buf, 0)
		if err == nil {
			return network.Packet{Data: append([]byte(nil), buf[:n]...)}, nil
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			select {
			case <-ctx.Done():
				return network.Packet{}, ctx.Err()
			default:
				time.Sleep(1 * time.Millisecond)
				continue
			}
		}
		return network.Packet{}, err
	}
}

func (p *linuxPacketIO) WritePacket(ctx context.Context, pkt network.Packet) error {
	if len(pkt.Data) == 0 {
		return nil
	}
	sa := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  p.ifindex,
	}
	if err := unix.Sendto(p.fd, pkt.Data, 0, sa); err != nil {
		return err
	}
	return nil
}

func (p *linuxPacketIO) Close() error {
	return unix.Close(p.fd)
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
