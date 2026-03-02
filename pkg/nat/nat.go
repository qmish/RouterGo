package nat

import (
	"encoding/binary"
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

func (t *Table) RemoveRule(match Rule) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, rule := range t.rules {
		if rulesEqual(rule, normalizeRule(match)) {
			t.rules = append(t.rules[:i], t.rules[i+1:]...)
			t.hits = append(t.hits[:i], t.hits[i+1:]...)
			return true
		}
	}
	return false
}

func (t *Table) UpdateRule(old Rule, updated Rule) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, rule := range t.rules {
		if rulesEqual(rule, normalizeRule(old)) {
			t.rules[i] = normalizeRule(updated)
			if i < len(t.hits) {
				t.hits[i] = 0
			}
			return true
		}
	}
	return false
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
		Proto:   packetProtoKey(pkt.Metadata),
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
	rewritePacketData(pkt, val)
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

func packetProtoKey(meta network.PacketMetadata) uint8 {
	if meta.ProtocolNum != 0 {
		return meta.ProtocolNum
	}
	return protoKey(meta.Protocol)
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

func rulesEqual(a Rule, b Rule) bool {
	if a.Type != b.Type {
		return false
	}
	if a.SrcPort != b.SrcPort || a.DstPort != b.DstPort || a.ToPort != b.ToPort {
		return false
	}
	if !ipNetEqual(a.SrcNet, b.SrcNet) || !ipNetEqual(a.DstNet, b.DstNet) {
		return false
	}
	if !ipEqual(a.ToIP, b.ToIP) {
		return false
	}
	return true
}

func ipNetEqual(a *net.IPNet, b *net.IPNet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a.Mask) != len(b.Mask) {
		return false
	}
	for i := range a.Mask {
		if a.Mask[i] != b.Mask[i] {
			return false
		}
	}
	return ipEqual(a.IP, b.IP)
}

func ipEqual(a net.IP, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

func rewritePacketData(pkt *network.Packet, val ConnValue) {
	if len(pkt.Data) < 1 {
		return
	}
	switch pkt.Data[0] >> 4 {
	case 4:
		rewriteIPv4Packet(pkt, val)
	case 6:
		rewriteIPv6Packet(pkt, val)
	}
}

func rewriteIPv4Packet(pkt *network.Packet, val ConnValue) {
	if len(pkt.Data) < 20 {
		return
	}
	ihl := int(pkt.Data[0]&0x0F) * 4
	if ihl < 20 || len(pkt.Data) < ihl {
		return
	}
	proto := pkt.Data[9]
	totalLen := int(binary.BigEndian.Uint16(pkt.Data[2:4]))
	if totalLen <= 0 || totalLen > len(pkt.Data) {
		totalLen = len(pkt.Data)
	}

	changedIP := false
	if val.TranslatedIP != nil {
		if ip4 := val.TranslatedIP.To4(); ip4 != nil {
			switch val.Target {
			case "src":
				copy(pkt.Data[12:16], ip4)
				changedIP = true
			case "dst":
				copy(pkt.Data[16:20], ip4)
				changedIP = true
			}
		}
	}
	transportOffset := ihl
	if val.TranslatedPort != 0 && totalLen >= transportOffset+4 {
		switch val.Target {
		case "src":
			binary.BigEndian.PutUint16(pkt.Data[transportOffset:transportOffset+2], uint16(val.TranslatedPort))
		case "dst":
			binary.BigEndian.PutUint16(pkt.Data[transportOffset+2:transportOffset+4], uint16(val.TranslatedPort))
		}
	}

	if changedIP {
		binary.BigEndian.PutUint16(pkt.Data[10:12], 0)
		hdrChecksum := network.Checksum(pkt.Data[:ihl])
		binary.BigEndian.PutUint16(pkt.Data[10:12], hdrChecksum)
	}

	recomputeTransportChecksumIPv4(pkt.Data[:totalLen], ihl, proto)
}

func rewriteIPv6Packet(pkt *network.Packet, val ConnValue) {
	if len(pkt.Data) < 40 {
		return
	}
	nextHeader := pkt.Data[6]
	payloadLen := int(binary.BigEndian.Uint16(pkt.Data[4:6]))
	totalLen := 40 + payloadLen
	if totalLen > len(pkt.Data) {
		totalLen = len(pkt.Data)
	}

	if val.TranslatedIP != nil {
		if ip16 := val.TranslatedIP.To16(); ip16 != nil {
			switch val.Target {
			case "src":
				copy(pkt.Data[8:24], ip16)
			case "dst":
				copy(pkt.Data[24:40], ip16)
			}
		}
	}
	if val.TranslatedPort != 0 && totalLen >= 44 {
		switch val.Target {
		case "src":
			binary.BigEndian.PutUint16(pkt.Data[40:42], uint16(val.TranslatedPort))
		case "dst":
			binary.BigEndian.PutUint16(pkt.Data[42:44], uint16(val.TranslatedPort))
		}
	}

	recomputeTransportChecksumIPv6(pkt.Data[:totalLen], nextHeader)
}

func recomputeTransportChecksumIPv4(packet []byte, ihl int, proto uint8) {
	switch proto {
	case 6: // TCP
		if len(packet) < ihl+20 {
			return
		}
		segmentLen := len(packet) - ihl
		pseudo := make([]byte, 0, 12+segmentLen)
		pseudo = append(pseudo, packet[12:16]...)
		pseudo = append(pseudo, packet[16:20]...)
		pseudo = append(pseudo, 0, proto)
		pseudoLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pseudoLen, uint16(segmentLen))
		pseudo = append(pseudo, pseudoLen...)
		segment := make([]byte, segmentLen)
		copy(segment, packet[ihl:])
		if len(segment) < 18 {
			return
		}
		segment[16], segment[17] = 0, 0
		pseudo = append(pseudo, segment...)
		sum := network.Checksum(pseudo)
		binary.BigEndian.PutUint16(packet[ihl+16:ihl+18], sum)
	case 17: // UDP
		if len(packet) < ihl+8 {
			return
		}
		checksumOffset := ihl + 6
		if checksumOffset+2 > len(packet) {
			return
		}
		if binary.BigEndian.Uint16(packet[checksumOffset:checksumOffset+2]) == 0 {
			return
		}
		segmentLen := len(packet) - ihl
		pseudo := make([]byte, 0, 12+segmentLen)
		pseudo = append(pseudo, packet[12:16]...)
		pseudo = append(pseudo, packet[16:20]...)
		pseudo = append(pseudo, 0, proto)
		pseudoLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pseudoLen, uint16(segmentLen))
		pseudo = append(pseudo, pseudoLen...)
		segment := make([]byte, segmentLen)
		copy(segment, packet[ihl:])
		segment[6], segment[7] = 0, 0
		pseudo = append(pseudo, segment...)
		sum := network.Checksum(pseudo)
		binary.BigEndian.PutUint16(packet[checksumOffset:checksumOffset+2], sum)
	}
}

func recomputeTransportChecksumIPv6(packet []byte, nextHeader uint8) {
	if len(packet) < 40 {
		return
	}
	segmentLen := len(packet) - 40
	switch nextHeader {
	case 6: // TCP
		if segmentLen < 20 {
			return
		}
		pseudo := make([]byte, 0, 40+segmentLen)
		pseudo = append(pseudo, packet[8:24]...)
		pseudo = append(pseudo, packet[24:40]...)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(segmentLen))
		pseudo = append(pseudo, lenBuf...)
		pseudo = append(pseudo, 0, 0, 0, nextHeader)
		segment := make([]byte, segmentLen)
		copy(segment, packet[40:])
		segment[16], segment[17] = 0, 0
		pseudo = append(pseudo, segment...)
		sum := network.Checksum(pseudo)
		binary.BigEndian.PutUint16(packet[56:58], sum)
	case 17: // UDP
		if segmentLen < 8 {
			return
		}
		pseudo := make([]byte, 0, 40+segmentLen)
		pseudo = append(pseudo, packet[8:24]...)
		pseudo = append(pseudo, packet[24:40]...)
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(segmentLen))
		pseudo = append(pseudo, lenBuf...)
		pseudo = append(pseudo, 0, 0, 0, nextHeader)
		segment := make([]byte, segmentLen)
		copy(segment, packet[40:])
		segment[6], segment[7] = 0, 0
		pseudo = append(pseudo, segment...)
		sum := network.Checksum(pseudo)
		if sum == 0 {
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(packet[46:48], sum)
	}
}
