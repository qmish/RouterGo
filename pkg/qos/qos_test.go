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

func TestQueueDequeueBatchPriority(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "high", Priority: 10, Protocol: "UDP"},
		{Name: "low", Priority: 1, Protocol: "TCP"},
	})

	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "TCP"}}) // low
	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "UDP"}}) // high
	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "TCP"}}) // low

	batch := q.DequeueBatch(2)
	if len(batch) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(batch))
	}
	if batch[0].Metadata.Protocol != "UDP" {
		t.Fatalf("expected high priority packet first")
	}
	if batch[1].Metadata.Protocol != "TCP" {
		t.Fatalf("expected low priority packet second")
	}
}

func TestQueueDequeueBatchMax(t *testing.T) {
	q := NewQueueManager([]Class{
		{Name: "default", Priority: 0},
	})
	q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "TCP"}})

	batch := q.DequeueBatch(3)
	if len(batch) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(batch))
	}
}

func TestQueueAddClassAndClassesCopy(t *testing.T) {
	q := NewQueueManager(nil)
	q.AddClass(Class{Name: "video", Priority: 5, Protocol: "UDP"})

	classes := q.Classes()
	if len(classes) < 2 {
		t.Fatalf("expected at least 2 classes, got %d", len(classes))
	}
	foundVideo := false
	for _, cl := range classes {
		if cl.Name == "video" {
			foundVideo = true
			break
		}
	}
	if !foundVideo {
		t.Fatalf("expected video class")
	}
	classes[0].Name = "changed"
	if q.Classes()[0].Name == "changed" {
		t.Fatalf("expected classes slice to be a copy")
	}
}

func TestQueueReplaceClasses(t *testing.T) {
	q := NewQueueManager([]Class{{Name: "voice", Priority: 5, Protocol: "UDP"}})
	q.ReplaceClasses([]Class{{Name: "bulk", Priority: 1, Protocol: "TCP"}})

	classes := q.Classes()
	foundBulk := false
	for _, cl := range classes {
		if cl.Name == "bulk" {
			foundBulk = true
		}
		if cl.Name == "voice" {
			t.Fatalf("expected voice class removed after replace")
		}
	}
	if !foundBulk {
		t.Fatalf("expected bulk class after replace")
	}

	ok, dropped, className := q.Enqueue(network.Packet{Metadata: network.PacketMetadata{Protocol: "TCP"}})
	if !ok || dropped || className != "bulk" {
		t.Fatalf("expected enqueue into bulk class")
	}
}

func TestAppendOrReplaceClass(t *testing.T) {
	initial := []Class{
		{Name: "one", Priority: 1},
		{Name: "two", Priority: 2},
	}
	out := appendOrReplaceClass(initial, Class{Name: "two", Priority: 5})
	countTwo := 0
	for _, cl := range out {
		if cl.Name == "two" {
			countTwo++
			if cl.Priority != 5 {
				t.Fatalf("expected replaced priority 5, got %d", cl.Priority)
			}
		}
	}
	if countTwo != 1 {
		t.Fatalf("expected one 'two' class, got %d", countTwo)
	}
	out = appendOrReplaceClass(initial, Class{Name: "three", Priority: 3})
	foundThree := false
	for _, cl := range out {
		if cl.Name == "three" {
			foundThree = true
		}
	}
	if !foundThree {
		t.Fatalf("expected appended class three")
	}
}

func TestQueueRemoveClass(t *testing.T) {
	q := NewQueueManager([]Class{{Name: "voice", Priority: 10}})
	if !q.RemoveClass("voice") {
		t.Fatalf("expected class removed")
	}
	if !containsClass(q.Classes(), "default") {
		t.Fatalf("expected default class to remain")
	}
	if q.RemoveClass("default") {
		t.Fatalf("expected default class to be protected")
	}
	if q.RemoveClass("missing") {
		t.Fatalf("expected remove to fail for missing class")
	}
}

func TestQueueUpdateClass(t *testing.T) {
	q := NewQueueManager([]Class{{Name: "voice", Priority: 1}})
	if !q.UpdateClass("voice", Class{Name: "voice", Priority: 5}) {
		t.Fatalf("expected update to succeed")
	}
	classes := q.Classes()
	if !containsClass(classes, "voice") {
		t.Fatalf("expected voice class to exist")
	}
	if q.UpdateClass("missing", Class{Name: "missing"}) {
		t.Fatalf("expected update to fail for missing class")
	}
	if q.UpdateClass("default", Class{Name: "default", Priority: 1}) {
		t.Fatalf("expected update to fail for default class")
	}
}

func containsClass(classes []Class, name string) bool {
	for _, cl := range classes {
		if cl.Name == name {
			return true
		}
	}
	return false
}
