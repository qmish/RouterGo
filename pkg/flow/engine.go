package flow

import (
	"net"
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

type sessionStats struct {
	Packets uint64
	Bytes   uint64
}

type Engine struct {
	mu       sync.RWMutex
	bySrc    map[ipKey]uint64
	sessions map[ipKey]map[ipKey]*sessionStats
}

func NewEngine() *Engine {
	return &Engine{
		bySrc:    map[ipKey]uint64{},
		sessions: map[ipKey]map[ipKey]*sessionStats{},
	}
}

func (e *Engine) AddPacket(pkt network.Packet) {
	srcKey := ipToKey(pkt.Metadata.SrcIP)
	dstKey := ipToKey(pkt.Metadata.DstIP)
	if srcKey == (ipKey{}) || dstKey == (ipKey{}) {
		return
	}
	size := packetSize(pkt)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.bySrc[srcKey] += size
	if _, ok := e.sessions[srcKey]; !ok {
		e.sessions[srcKey] = map[ipKey]*sessionStats{}
	}
	entry := e.sessions[srcKey][dstKey]
	if entry == nil {
		entry = &sessionStats{}
		e.sessions[srcKey][dstKey] = entry
	}
	entry.Packets++
	entry.Bytes += size
}

func (e *Engine) TopBandwidth(limit int) []TopEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TopEntry, 0, len(e.bySrc))
	for srcKey, bytes := range e.bySrc {
		out = append(out, TopEntry{SrcIP: keyToString(srcKey), Bytes: bytes})
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
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string][]SessionEntry, len(e.sessions))
	for srcKey, dsts := range e.sessions {
		list := make([]SessionEntry, 0, len(dsts))
		for dstKey, entry := range dsts {
			list = append(list, SessionEntry{
				DstIP:   keyToString(dstKey),
				Packets: entry.Packets,
				Bytes:   entry.Bytes,
			})
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Bytes > list[j].Bytes
		})
		out[keyToString(srcKey)] = list
	}
	return out
}

func packetSize(pkt network.Packet) uint64 {
	if pkt.Metadata.Length > 0 {
		return uint64(pkt.Metadata.Length)
	}
	return uint64(len(pkt.Data))
}

type ipKey [16]byte

func ipToKey(ip net.IP) ipKey {
	var out ipKey
	if ip == nil {
		return out
	}
	if ip4 := ip.To4(); ip4 != nil {
		out[10] = 0xff
		out[11] = 0xff
		copy(out[12:], ip4)
		return out
	}
	if ip16 := ip.To16(); ip16 != nil {
		copy(out[:], ip16)
	}
	return out
}

func keyToString(key ipKey) string {
	if key == (ipKey{}) {
		return ""
	}
	if key[10] == 0xff && key[11] == 0xff {
		return net.IPv4(key[12], key[13], key[14], key[15]).String()
	}
	return net.IP(key[:]).String()
}
