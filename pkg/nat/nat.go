package nat

import (
	"net"
	"strings"
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
	hasSrcNet  bool
	hasDstNet  bool
	hasSrcPort bool
	hasDstPort bool
}

type ConnKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type ConnValue struct {
	TranslatedIP   net.IP
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
		rules: normalizeRules(rules),
		conns: make(map[ConnKey]ConnValue),
		hits:  make([]uint64, len(rules)),
	}
}

func (t *Table) AddRule(rule Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = append(t.rules, normalizeRule(rule))
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
	t.rules = normalizeRules(rules)
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
	if rule.hasSrcNet {
		if pkt.Metadata.SrcIP == nil || !rule.SrcNet.Contains(pkt.Metadata.SrcIP) {
			return false
		}
	}
	if rule.hasDstNet {
		if pkt.Metadata.DstIP == nil || !rule.DstNet.Contains(pkt.Metadata.DstIP) {
			return false
		}
	}
	if rule.hasSrcPort && rule.SrcPort != pkt.Metadata.SrcPort {
		return false
	}
	if rule.hasDstPort && rule.DstPort != pkt.Metadata.DstPort {
		return false
	}
	return true
}

func makeConnKey(pkt network.Packet) ConnKey {
	return ConnKey{
		SrcIP:   ipToKey(pkt.Metadata.SrcIP),
		DstIP:   ipToKey(pkt.Metadata.DstIP),
		SrcPort: uint16(pkt.Metadata.SrcPort),
		DstPort: uint16(pkt.Metadata.DstPort),
		Proto:   protoKey(pkt.Metadata.Protocol),
	}
}

func applyTranslation(pkt *network.Packet, val ConnValue) {
	switch val.Target {
	case "src":
		if val.TranslatedIP != nil {
			pkt.Metadata.SrcIP = val.TranslatedIP
		}
		if val.TranslatedPort != 0 {
			pkt.Metadata.SrcPort = val.TranslatedPort
		}
	case "dst":
		if val.TranslatedIP != nil {
			pkt.Metadata.DstIP = val.TranslatedIP
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
			forward.TranslatedIP = rule.ToIP
		}
		if rule.ToPort != 0 {
			translated.Metadata.SrcPort = rule.ToPort
			forward.TranslatedPort = rule.ToPort
		}
		forward.Target = "src"

		reverseKey = ConnKey{
			SrcIP:   ipToKey(pkt.Metadata.DstIP),
			DstIP:   ipToKey(translated.Metadata.SrcIP),
			SrcPort: uint16(pkt.Metadata.DstPort),
			DstPort: uint16(translated.Metadata.SrcPort),
			Proto:   protoKey(pkt.Metadata.Protocol),
		}
		reverse = ConnValue{
			Target:         "dst",
			TranslatedIP:   originalSrcIP,
			TranslatedPort: originalSrcPort,
			RuleIndex:      -1,
		}
	case TypeDNAT:
		originalDstIP := pkt.Metadata.DstIP
		originalDstPort := pkt.Metadata.DstPort

		if rule.ToIP != nil {
			translated.Metadata.DstIP = rule.ToIP
			forward.TranslatedIP = rule.ToIP
		}
		if rule.ToPort != 0 {
			translated.Metadata.DstPort = rule.ToPort
			forward.TranslatedPort = rule.ToPort
		}
		forward.Target = "dst"

		reverseKey = ConnKey{
			SrcIP:   ipToKey(translated.Metadata.DstIP),
			DstIP:   ipToKey(pkt.Metadata.SrcIP),
			SrcPort: uint16(translated.Metadata.DstPort),
			DstPort: uint16(pkt.Metadata.SrcPort),
			Proto:   protoKey(pkt.Metadata.Protocol),
		}
		reverse = ConnValue{
			Target:         "src",
			TranslatedIP:   originalDstIP,
			TranslatedPort: originalDstPort,
			RuleIndex:      -1,
		}
	}

	if forward.Target != "" {
		applyTranslation(&translated, forward)
	}
	return translated, forward, reverseKey, reverse
}

func ipToKey(ip net.IP) [16]byte {
	var out [16]byte
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

func protoKey(proto string) uint8 {
	switch {
	case strings.EqualFold(proto, "TCP"):
		return 6
	case strings.EqualFold(proto, "UDP"):
		return 17
	case strings.EqualFold(proto, "ICMP"):
		return 1
	case strings.EqualFold(proto, "ICMPv6"):
		return 58
	default:
		return 0
	}
}

func normalizeRule(rule Rule) Rule {
	rule.hasSrcNet = rule.SrcNet != nil
	rule.hasDstNet = rule.DstNet != nil
	rule.hasSrcPort = rule.SrcPort != 0
	rule.hasDstPort = rule.DstPort != 0
	return rule
}

func normalizeRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, normalizeRule(rule))
	}
	return out
}
