package main

import (
	"context"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/network"
	"router-go/pkg/qos"

	"github.com/prometheus/client_golang/prometheus"
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

func TestDequeueAndWriteBatch(t *testing.T) {
	queue := qos.NewQueueManager(nil)
	writer := &fakePacketIO{}
	m := metrics.NewWithRegistry(prometheus.NewRegistry())

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "UDP",
		},
	}
	queue.Enqueue(pkt)

	if ok := dequeueAndWriteBatch(queue, writer, m, 2); !ok {
		t.Fatalf("expected dequeue success")
	}
	if writer.writeCount != 1 {
		t.Fatalf("expected one write, got %d", writer.writeCount)
	}
	if m.Snapshot().TxPackets != 1 {
		t.Fatalf("expected tx packets 1, got %d", m.Snapshot().TxPackets)
	}
	if writer.lastPkt.Metadata.Protocol != "UDP" {
		t.Fatalf("unexpected packet written")
	}
}

func TestDequeueAndWriteBatchEmpty(t *testing.T) {
	queue := qos.NewQueueManager(nil)
	writer := &fakePacketIO{}
	m := metrics.NewWithRegistry(prometheus.NewRegistry())

	if ok := dequeueAndWriteBatch(queue, writer, m, 2); ok {
		t.Fatalf("expected dequeue false")
	}
	if writer.writeCount != 0 {
		t.Fatalf("expected no writes, got %d", writer.writeCount)
	}
	if m.Snapshot().TxPackets != 0 {
		t.Fatalf("expected tx packets 0, got %d", m.Snapshot().TxPackets)
	}
}
