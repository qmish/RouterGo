package qos

import (
	"strings"
	"sync"
	"time"

	"router-go/pkg/network"
)

type Class struct {
	Name          string
	Protocol      string
	SrcPort       int
	DstPort       int
	RateLimitKbps int
	Priority      int
}

type Classifier struct {
	classes []Class
}

func NewClassifier(classes []Class) *Classifier {
	return &Classifier{classes: classes}
}

func (c *Classifier) Classify(pkt network.Packet) *Class {
	for i := range c.classes {
		cl := &c.classes[i]
		if cl.Protocol != "" && !strings.EqualFold(cl.Protocol, pkt.Metadata.Protocol) {
			continue
		}
		if cl.SrcPort != 0 && cl.SrcPort != pkt.Metadata.SrcPort {
			continue
		}
		if cl.DstPort != 0 && cl.DstPort != pkt.Metadata.DstPort {
			continue
		}
		return cl
	}
	return nil
}

type QueueManager struct {
	mu      sync.Mutex
	classes []Class
	queues  map[string][]network.Packet
	buckets map[string]*TokenBucket
}

func NewQueueManager(classes []Class) *QueueManager {
	out := normalizeClasses(classes)
	return &QueueManager{
		classes: out,
		queues:  makeQueueMap(out),
		buckets: makeBucketMap(out),
	}
}

func (q *QueueManager) Enqueue(pkt network.Packet) {
	q.mu.Lock()
	defer q.mu.Unlock()
	class := q.classify(pkt)
	q.queues[class.Name] = append(q.queues[class.Name], pkt)
}

func (q *QueueManager) Dequeue() (network.Packet, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, class := range q.classes {
		queue := q.queues[class.Name]
		if len(queue) == 0 {
			continue
		}

		size := packetSize(queue[0])
		if bucket, ok := q.buckets[class.Name]; ok {
			if !bucket.Allow(size) {
				continue
			}
		}

		pkt := queue[0]
		q.queues[class.Name] = queue[1:]
		return pkt, true
	}
	return network.Packet{}, false
}

func (q *QueueManager) SetNow(now func() time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, bucket := range q.buckets {
		bucket.now = now
	}
}

func (q *QueueManager) AddClass(class Class) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.classes = appendOrReplaceClass(q.classes, class)
	q.classes = normalizeClasses(q.classes)
	q.queues = makeQueueMap(q.classes)
	q.buckets = makeBucketMap(q.classes)
}

func (q *QueueManager) Classes() []Class {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Class, 0, len(q.classes))
	out = append(out, q.classes...)
	return out
}

func (q *QueueManager) classify(pkt network.Packet) Class {
	for i := range q.classes {
		cl := q.classes[i]
		if cl.Name == "default" {
			continue
		}
		if cl.Protocol != "" && !strings.EqualFold(cl.Protocol, pkt.Metadata.Protocol) {
			continue
		}
		if cl.SrcPort != 0 && cl.SrcPort != pkt.Metadata.SrcPort {
			continue
		}
		if cl.DstPort != 0 && cl.DstPort != pkt.Metadata.DstPort {
			continue
		}
		return cl
	}
	for _, cl := range q.classes {
		if cl.Name == "default" {
			return cl
		}
	}
	return Class{Name: "default"}
}

func packetSize(pkt network.Packet) int64 {
	if pkt.Metadata.Length > 0 {
		return int64(pkt.Metadata.Length)
	}
	return int64(len(pkt.Data))
}

func normalizeClasses(classes []Class) []Class {
	out := make([]Class, 0, len(classes)+1)
	out = append(out, classes...)
	hasDefault := false
	for _, cl := range out {
		if cl.Name == "default" {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		out = append(out, Class{Name: "default", Priority: 0})
	}

	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Priority > out[i].Priority {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func appendOrReplaceClass(classes []Class, class Class) []Class {
	out := make([]Class, 0, len(classes)+1)
	replaced := false
	for _, cl := range classes {
		if cl.Name == class.Name {
			if !replaced {
				out = append(out, class)
				replaced = true
			}
			continue
		}
		out = append(out, cl)
	}
	if !replaced {
		out = append(out, class)
	}
	return out
}

func makeQueueMap(classes []Class) map[string][]network.Packet {
	queues := make(map[string][]network.Packet, len(classes))
	for _, cl := range classes {
		if _, ok := queues[cl.Name]; !ok {
			queues[cl.Name] = nil
		}
	}
	return queues
}

func makeBucketMap(classes []Class) map[string]*TokenBucket {
	buckets := make(map[string]*TokenBucket, len(classes))
	for _, cl := range classes {
		if cl.RateLimitKbps > 0 {
			rateBytes := int64(cl.RateLimitKbps) * 1000 / 8
			buckets[cl.Name] = NewTokenBucket(rateBytes, rateBytes)
		}
	}
	return buckets
}

type TokenBucket struct {
	mu       sync.Mutex
	capacity int64
	tokens   int64
	rate     int64
	last     time.Time
	now      func() time.Time
}

func NewTokenBucket(rateBytesPerSec int64, burstBytes int64) *TokenBucket {
	return &TokenBucket{
		capacity: burstBytes,
		tokens:   burstBytes,
		rate:     rateBytesPerSec,
		last:     time.Now(),
		now:      time.Now,
	}
}

func (t *TokenBucket) Allow(n int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if t.now != nil {
		now = t.now()
	}
	elapsed := now.Sub(t.last).Seconds()
	t.last = now

	t.tokens += int64(elapsed * float64(t.rate))
	if t.tokens > t.capacity {
		t.tokens = t.capacity
	}

	if t.tokens < n {
		return false
	}
	t.tokens -= n
	return true
}
