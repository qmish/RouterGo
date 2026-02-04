package qos

import (
	"testing"
	"time"

	"router-go/pkg/network"
)

func TestClassifierMatch(t *testing.T) {
	classifier := NewClassifier([]Class{
		{
			Name:     "voice",
			Protocol: "UDP",
			DstPort:  5060,
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "UDP",
			DstPort:  5060,
		},
	}

	class := classifier.Classify(pkt)
	if class == nil || class.Name != "voice" {
		t.Fatalf("expected voice class")
	}
}

func TestClassifierNoMatch(t *testing.T) {
	classifier := NewClassifier([]Class{
		{
			Name:     "voice",
			Protocol: "UDP",
			DstPort:  5060,
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			DstPort:  5060,
		},
	}

	if class := classifier.Classify(pkt); class != nil {
		t.Fatalf("expected nil class")
	}
}

func TestTokenBucketAllow(t *testing.T) {
	tb := NewTokenBucket(10, 10)
	base := time.Now()
	tb.last = base
	tb.now = func() time.Time { return base }

	if !tb.Allow(10) {
		t.Fatalf("expected initial allow")
	}
	if tb.Allow(1) {
		t.Fatalf("expected deny when empty")
	}

	tb.now = func() time.Time { return base.Add(1 * time.Second) }
	if !tb.Allow(10) {
		t.Fatalf("expected refill allow")
	}
}

func TestQueuePriorityOrder(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "high", Priority: 10, Protocol: "UDP"},
		{Name: "low", Priority: 1, Protocol: "TCP"},
	})

	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "TCP"}}) // low
	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP"}}) // high

	pkt, ok := q.Dequeue()
	if !ok {
		t.Fatalf("expected packet")
	}
	if pkt.Metadata.Protocol != "UDP" {
		t.Fatalf("expected high priority packet")
	}
}

func TestQueueRateLimit(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "limited", Priority: 5, RateLimitKbps: 8},
	})
	base := time.Now()
	q.SetNow(func() time.Time { return base })

	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Length: 1000}})
	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Length: 1000}})

	if _, ok := q.Dequeue(); !ok {
		t.Fatalf("expected first dequeue")
	}
	if _, ok := q.Dequeue(); ok {
		t.Fatalf("expected rate limited dequeue")
	}

	q.SetNow(func() time.Time { return base.Add(1 * time.Second) })
	if _, ok := q.Dequeue(); !ok {
		t.Fatalf("expected dequeue after refill")
	}
}

func TestQueueMaxSizeDrop(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "limited", Protocol: "UDP", Priority: 5, MaxQueue: 1},
	})

	ok, dropped, className := q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP"}})
	if !ok || dropped {
		t.Fatalf("expected first enqueue ok")
	}
	if className != "limited" {
		t.Fatalf("expected class limited, got %s", className)
	}
	ok, dropped, _ = q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP"}})
	if ok || !dropped {
		t.Fatalf("expected enqueue drop due to max_queue")
	}
}

func TestQueueHeadDrop(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "limited", Protocol: "UDP", Priority: 5, MaxQueue: 1, DropPolicy: "head"},
	})

	ok, dropped, className := q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP", SrcPort: 1000}})
	if !ok || dropped {
		t.Fatalf("expected first enqueue ok")
	}
	if className != "limited" {
		t.Fatalf("expected class limited, got %s", className)
	}
	ok, dropped, _ = q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP", SrcPort: 2000}})
	if !ok || !dropped {
		t.Fatalf("expected enqueue with head drop")
	}

	pkt, ok := q.Dequeue()
	if !ok {
		t.Fatalf("expected packet")
	}
	if pkt.Metadata.SrcPort != 2000 {
		t.Fatalf("expected newest packet after head drop")
	}
}
