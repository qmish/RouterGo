package nat

import (
	"net"
	"sync"

	"router-go/pkg/network"
)

type Type string

const (
	TypeSNAT Type = "SNAT"
	TypeDNAT Type = "DNAT"
)

type Rule struct {
	Type    Type
	SrcNet  *net.IPNet
	DstNet  *net.IPNet
	SrcPort int
	DstPort int
	ToIP    net.IP
	ToPort  int
}

type ConnKey struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	Proto   string
}

type ConnValue struct {
	TranslatedIP   string
	TranslatedPort int
	Target         string
}

type Table struct {
	mu    sync.Mutex
	rules []Rule
	conns map[ConnKey]ConnValue
}

func NewTable(rules []Rule) *Table {
	return &Table{
		rules: rules,
		conns: make(map[ConnKey]ConnValue),
	}
}

func (t *Table) Apply(pkt network.Packet) network.Packet {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := makeConnKey(pkt)
	if val, ok := t.conns[key]; ok {
		applyTranslation(&pkt, val)
		return pkt
	}

	for _, rule := range t.rules {
		if !matchRule(rule, pkt) {
			continue
		}
		val := ConnValue{}
		switch rule.Type {
		case TypeSNAT:
			val.Target = "src"
			if rule.ToIP != nil {
				val.TranslatedIP = rule.ToIP.String()
			}
			if rule.ToPort != 0 {
				val.TranslatedPort = rule.ToPort
			}
		case TypeDNAT:
			val.Target = "dst"
			if rule.ToIP != nil {
				val.TranslatedIP = rule.ToIP.String()
			}
			if rule.ToPort != 0 {
				val.TranslatedPort = rule.ToPort
			}
		}

		if val.Target != "" {
			t.conns[key] = val
			applyTranslation(&pkt, val)
		}
		return pkt
	}
	return pkt
}

func matchRule(rule Rule, pkt network.Packet) bool {
	if rule.SrcNet != nil {
		if pkt.Metadata.SrcIP == nil || !rule.SrcNet.Contains(pkt.Metadata.SrcIP) {
			return false
		}
	}
	if rule.DstNet != nil {
		if pkt.Metadata.DstIP == nil || !rule.DstNet.Contains(pkt.Metadata.DstIP) {
			return false
		}
	}
	if rule.SrcPort != 0 && rule.SrcPort != pkt.Metadata.SrcPort {
		return false
	}
	if rule.DstPort != 0 && rule.DstPort != pkt.Metadata.DstPort {
		return false
	}
	return true
}

func makeConnKey(pkt network.Packet) ConnKey {
	proto := pkt.Metadata.Protocol
	if proto == "" {
		proto = "UNKNOWN"
	}
	return ConnKey{
		SrcIP:   pkt.Metadata.SrcIP.String(),
		DstIP:   pkt.Metadata.DstIP.String(),
		SrcPort: pkt.Metadata.SrcPort,
		DstPort: pkt.Metadata.DstPort,
		Proto:   proto,
	}
}

func applyTranslation(pkt *network.Packet, val ConnValue) {
	switch val.Target {
	case "src":
		if val.TranslatedIP != "" {
			pkt.Metadata.SrcIP = net.ParseIP(val.TranslatedIP)
		}
		if val.TranslatedPort != 0 {
			pkt.Metadata.SrcPort = val.TranslatedPort
		}
	case "dst":
		if val.TranslatedIP != "" {
			pkt.Metadata.DstIP = net.ParseIP(val.TranslatedIP)
		}
		if val.TranslatedPort != 0 {
			pkt.Metadata.DstPort = val.TranslatedPort
		}
	}
}
