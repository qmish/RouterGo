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
	RuleIndex      int
}

type Table struct {
	mu    sync.Mutex
	rules []Rule
	conns map[ConnKey]ConnValue
	hits  []uint64
}

func NewTable(rules []Rule) *Table {
	return &Table{
		rules: rules,
		conns: make(map[ConnKey]ConnValue),
		hits:  make([]uint64, len(rules)),
	}
}

func (t *Table) AddRule(rule Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = append(t.rules, rule)
	t.hits = append(t.hits, 0)
}

func (t *Table) Rules() []Rule {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Rule, 0, len(t.rules))
	out = append(out, t.rules...)
	return out
}

type RuleStat struct {
	Rule Rule
	Hits uint64
}

func (t *Table) RulesWithStats() []RuleStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]RuleStat, 0, len(t.rules))
	for i, rule := range t.rules {
		out = append(out, RuleStat{
			Rule: rule,
			Hits: t.hits[i],
		})
	}
	return out
}

func (t *Table) ResetStats() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.hits {
		t.hits[i] = 0
	}
}

func (t *Table) ReplaceRules(rules []Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = rules
	t.hits = make([]uint64, len(rules))
	t.conns = make(map[ConnKey]ConnValue)
}

func (t *Table) Apply(pkt network.Packet) network.Packet {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := makeConnKey(pkt)
	if val, ok := t.conns[key]; ok {
		if val.RuleIndex >= 0 && val.RuleIndex < len(t.hits) {
			t.hits[val.RuleIndex]++
		}
		applyTranslation(&pkt, val)
		return pkt
	}

	for i, rule := range t.rules {
		if !matchRule(rule, pkt) {
			continue
		}
		translated, forwardVal, reverseKey, reverseVal := applyRule(rule, pkt)
		t.hits[i]++
		forwardVal.RuleIndex = i
		reverseVal.RuleIndex = i
		if forwardVal.Target != "" {
			t.conns[key] = forwardVal
		}
		if reverseVal.Target != "" {
			t.conns[reverseKey] = reverseVal
		}
		pkt = translated
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

func applyRule(rule Rule, pkt network.Packet) (network.Packet, ConnValue, ConnKey, ConnValue) {
	translated := pkt
	forward := ConnValue{RuleIndex: -1}
	reverseKey := ConnKey{}
	reverse := ConnValue{RuleIndex: -1}

	switch rule.Type {
	case TypeSNAT:
		originalSrcIP := pkt.Metadata.SrcIP
		originalSrcPort := pkt.Metadata.SrcPort

		if rule.ToIP != nil {
			translated.Metadata.SrcIP = rule.ToIP
			forward.TranslatedIP = rule.ToIP.String()
		}
		if rule.ToPort != 0 {
			translated.Metadata.SrcPort = rule.ToPort
			forward.TranslatedPort = rule.ToPort
		}
		forward.Target = "src"

		reverseKey = ConnKey{
			SrcIP:   pkt.Metadata.DstIP.String(),
			DstIP:   translated.Metadata.SrcIP.String(),
			SrcPort: pkt.Metadata.DstPort,
			DstPort: translated.Metadata.SrcPort,
			Proto:   pkt.Metadata.Protocol,
		}
		reverse = ConnValue{
			Target:         "dst",
			TranslatedIP:   originalSrcIP.String(),
			TranslatedPort: originalSrcPort,
			RuleIndex:      -1,
		}
	case TypeDNAT:
		originalDstIP := pkt.Metadata.DstIP
		originalDstPort := pkt.Metadata.DstPort

		if rule.ToIP != nil {
			translated.Metadata.DstIP = rule.ToIP
			forward.TranslatedIP = rule.ToIP.String()
		}
		if rule.ToPort != 0 {
			translated.Metadata.DstPort = rule.ToPort
			forward.TranslatedPort = rule.ToPort
		}
		forward.Target = "dst"

		reverseKey = ConnKey{
			SrcIP:   translated.Metadata.DstIP.String(),
			DstIP:   pkt.Metadata.SrcIP.String(),
			SrcPort: translated.Metadata.DstPort,
			DstPort: pkt.Metadata.SrcPort,
			Proto:   pkt.Metadata.Protocol,
		}
		reverse = ConnValue{
			Target:         "src",
			TranslatedIP:   originalDstIP.String(),
			TranslatedPort: originalDstPort,
			RuleIndex:      -1,
		}
	}

	if forward.Target != "" {
		applyTranslation(&translated, forward)
	}
	return translated, forward, reverseKey, reverse
}
