package flow

import (
	"sort"
	"sync"

	"router-go/pkg/network"
)

type TopEntry struct {
	SrcIP string `json:"src_ip"`
	Bytes uint64 `json:"bytes"`
}

type SessionEntry struct {
	DstIP   string `json:"dst_ip"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Engine struct {
	mu       sync.Mutex
	bySrc    map[string]uint64
	sessions map[string]map[string]*SessionEntry
}

func NewEngine() *Engine {
	return &Engine{
		bySrc:    map[string]uint64{},
		sessions: map[string]map[string]*SessionEntry{},
	}
}

func (e *Engine) AddPacket(pkt network.Packet) {
	src := pkt.Metadata.SrcIP.String()
	dst := pkt.Metadata.DstIP.String()
	if src == "" || dst == "" {
		return
	}
	size := packetSize(pkt)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.bySrc[src] += size
	if _, ok := e.sessions[src]; !ok {
		e.sessions[src] = map[string]*SessionEntry{}
	}
	entry := e.sessions[src][dst]
	if entry == nil {
		entry = &SessionEntry{DstIP: dst}
		e.sessions[src][dst] = entry
	}
	entry.Packets++
	entry.Bytes += size
}

func (e *Engine) TopBandwidth(limit int) []TopEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]TopEntry, 0, len(e.bySrc))
	for src, bytes := range e.bySrc {
		out = append(out, TopEntry{SrcIP: src, Bytes: bytes})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Bytes > out[j].Bytes
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (e *Engine) SessionsTree() map[string][]SessionEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string][]SessionEntry, len(e.sessions))
	for src, dsts := range e.sessions {
		list := make([]SessionEntry, 0, len(dsts))
		for _, entry := range dsts {
			list = append(list, *entry)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Bytes > list[j].Bytes
		})
		out[src] = list
	}
	return out
}

func packetSize(pkt network.Packet) uint64 {
	if pkt.Metadata.Length > 0 {
		return uint64(pkt.Metadata.Length)
	}
	return uint64(len(pkt.Data))
}
