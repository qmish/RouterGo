package p2p

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDeadlineFromContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(200*time.Millisecond))
	defer cancel()
	deadline := deadlineFromContext(ctx)
	if deadline.Before(time.Now()) {
		t.Fatalf("expected future deadline")
	}

	noDeadline := deadlineFromContext(context.Background())
	if noDeadline.Before(time.Now().Add(500 * time.Millisecond)) || noDeadline.After(time.Now().Add(2*time.Second)) {
		t.Fatalf("expected fallback deadline around 1s")
	}
}

func TestUDPTransportSendReceive(t *testing.T) {
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen receiver failed: %v", err)
	}
	defer receiver.Close()

	tp, err := NewUDPTransport("127.0.0.1:0", receiver.LocalAddr().String())
	if err != nil {
		t.Fatalf("new transport failed: %v", err)
	}
	defer tp.Close()

	msg := []byte("hello")
	if err := tp.Send(msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	buf := make([]byte, 16)
	_ = receiver.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("unexpected payload: %q", string(buf[:n]))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn := tp.conn
	local := conn.LocalAddr().String()
	caddr, err := net.ResolveUDPAddr("udp4", local)
	if err != nil {
		t.Fatalf("resolve local addr failed: %v", err)
	}
	sender, err := net.DialUDP("udp4", nil, caddr)
	if err != nil {
		t.Fatalf("dial sender failed: %v", err)
	}
	_, _ = sender.Write([]byte("ping"))
	_ = sender.Close()

	data, _, err := tp.Receive(ctx)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if string(data) != "ping" {
		t.Fatalf("unexpected received payload: %q", string(data))
	}
}

func TestUDPTransportReceiveTimeout(t *testing.T) {
	tp, err := NewUDPTransport("127.0.0.1:0", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("new transport failed: %v", err)
	}
	defer tp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err = tp.Receive(ctx)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}
