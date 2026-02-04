package p2p

import (
	"context"
	"net"
	"time"
)

type Transport interface {
	Send(data []byte) error
	Receive(ctx context.Context) ([]byte, string, error)
	Close() error
}

type UDPTransport struct {
	conn          net.PacketConn
	multicastAddr *net.UDPAddr
}

func NewUDPTransport(listenAddr string, multicastAddr string) (*UDPTransport, error) {
	conn, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	maddr, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &UDPTransport{conn: conn, multicastAddr: maddr}, nil
}

func (t *UDPTransport) Send(data []byte) error {
	_, err := t.conn.WriteTo(data, t.multicastAddr)
	return err
}

func (t *UDPTransport) Receive(ctx context.Context) ([]byte, string, error) {
	buf := make([]byte, 8192)
	for {
		t.conn.SetReadDeadline(deadlineFromContext(ctx))
		n, addr, err := t.conn.ReadFrom(buf)
		if err == nil {
			return append([]byte(nil), buf[:n]...), addr.String(), nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			select {
			case <-ctx.Done():
				return nil, "", ctx.Err()
			default:
				continue
			}
		}
		return nil, "", err
	}
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

func deadlineFromContext(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(1 * time.Second)
}
