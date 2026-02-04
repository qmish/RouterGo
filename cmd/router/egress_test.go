package main

import (
	"context"
	"testing"

	"router-go/pkg/network"
	"router-go/pkg/qos"
)

type fakePacketIO struct {
	writeCount int
	lastPkt    network.Packet
}

func (f *fakePacketIO) ReadPacket(ctx context.Context) (network.Packet, error) {
	return network.Packet{}, nil
}

func (f *fakePacketIO) WritePacket(ctx context.Context, pkt network.Packet) error {
	f.writeCount++
	f.lastPkt = pkt
	return nil
}

func (f *fakePacketIO) Close() error {
	return nil
}

func TestDequeueAndWrite(t *testing.T) {
	queue := qos.NewQueueManager(nil)
	writer := &fakePacketIO{}

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "UDP",
		},
	}
	queue.Enqueue(pkt)

	if ok := dequeueAndWrite(queue, writer); !ok {
		t.Fatalf("expected dequeue success")
	}
	if writer.writeCount != 1 {
		t.Fatalf("expected one write, got %d", writer.writeCount)
	}
	if writer.lastPkt.Metadata.Protocol != "UDP" {
		t.Fatalf("unexpected packet written")
	}
}

func TestDequeueAndWriteEmpty(t *testing.T) {
	queue := qos.NewQueueManager(nil)
	writer := &fakePacketIO{}

	if ok := dequeueAndWrite(queue, writer); ok {
		t.Fatalf("expected dequeue false")
	}
	if writer.writeCount != 0 {
		t.Fatalf("expected no writes, got %d", writer.writeCount)
	}
}
