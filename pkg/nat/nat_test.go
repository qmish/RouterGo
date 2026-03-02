package nat

import (
	"encoding/binary"
	"net"
	"testing"

	"router-go/pkg/network"
)

func TestApplySNAT(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:   net.ParseIP("10.1.2.3"),
			DstIP:   net.ParseIP("1.1.1.1"),
			SrcPort: 1234,
			DstPort: 80,
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected SNAT src ip, got %s", out.Metadata.SrcIP)
	}
	if out.Metadata.DstIP.String() != "1.1.1.1" {
		t.Fatalf("expected dst ip unchanged, got %s", out.Metadata.DstIP)
	}
}

func TestApplyDNAT(t *testing.T) {
	_, dstNet, _ := net.ParseCIDR("198.51.100.0/24")
	table := NewTable([]Rule{
		{
			Type:   TypeDNAT,
			DstNet: dstNet,
			ToIP:   net.ParseIP("192.168.1.10"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("10.1.2.3"),
			DstIP: net.ParseIP("198.51.100.25"),
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.DstIP.String() != "192.168.1.10" {
		t.Fatalf("expected DNAT dst ip, got %s", out.Metadata.DstIP)
	}
}

func TestApplyNoMatch(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("192.168.1.5"),
			DstIP: net.ParseIP("1.1.1.1"),
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "192.168.1.5" {
		t.Fatalf("expected src ip unchanged, got %s", out.Metadata.SrcIP)
	}
}

func TestApplySNATPortMapping(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
			ToPort: 5555,
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:   net.ParseIP("10.1.2.3"),
			DstIP:   net.ParseIP("1.1.1.1"),
			SrcPort: 1234,
			DstPort: 80,
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcPort != 5555 {
		t.Fatalf("expected SNAT port, got %d", out.Metadata.SrcPort)
	}
}

func TestApplyRuleOrder(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.20"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("10.1.2.3"),
			DstIP: net.ParseIP("1.1.1.1"),
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected first rule applied, got %s", out.Metadata.SrcIP)
	}
}

func TestApplyPortFilter(t *testing.T) {
	table := NewTable([]Rule{
		{
			Type:    TypeSNAT,
			SrcPort: 1234,
			DstPort: 80,
			ToIP:    net.ParseIP("203.0.113.10"),
		},
	})

	pktMismatch := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:   net.ParseIP("10.1.2.3"),
			DstIP:   net.ParseIP("1.1.1.1"),
			SrcPort: 1234,
			DstPort: 81,
		},
	}
	out := table.Apply(pktMismatch)
	if out.Metadata.SrcIP.String() != "10.1.2.3" {
		t.Fatalf("expected no match for dst port, got %s", out.Metadata.SrcIP)
	}

	pktMatch := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:   net.ParseIP("10.1.2.3"),
			DstIP:   net.ParseIP("1.1.1.1"),
			SrcPort: 1234,
			DstPort: 80,
		},
	}
	out2 := table.Apply(pktMatch)
	if out2.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected SNAT on port match, got %s", out2.Metadata.SrcIP)
	}
}

func TestConnectionTrackingReuse(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected snat on first apply, got %s", out.Metadata.SrcIP)
	}

	table.rules = nil
	out2 := table.Apply(pkt)
	if out2.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected tracked snat, got %s", out2.Metadata.SrcIP)
	}
}

func TestConnectionTrackingReverseSNAT(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
			ToPort: 40000,
		},
	})

	outbound := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("8.8.8.8"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	table.Apply(outbound)

	inbound := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("8.8.8.8"),
			DstIP:    net.ParseIP("203.0.113.10"),
			SrcPort:  80,
			DstPort:  40000,
		},
	}
	out := table.Apply(inbound)
	if out.Metadata.DstIP.String() != "10.1.2.3" {
		t.Fatalf("expected reverse snat dst, got %s", out.Metadata.DstIP)
	}
	if out.Metadata.DstPort != 1234 {
		t.Fatalf("expected reverse snat dst port, got %d", out.Metadata.DstPort)
	}
}

func TestConnectionTrackingIPv6SNAT(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("2001:db8::/32")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("2001:db8::100"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("2001:db8::1"),
			DstIP:    net.ParseIP("2001:db8::200"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}

	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "2001:db8::100" {
		t.Fatalf("expected snat ipv6, got %s", out.Metadata.SrcIP)
	}

	table.rules = nil
	out2 := table.Apply(pkt)
	if out2.Metadata.SrcIP.String() != "2001:db8::100" {
		t.Fatalf("expected tracked snat ipv6, got %s", out2.Metadata.SrcIP)
	}
}

func TestConnectionTrackingReverseDNAT(t *testing.T) {
	_, dstNet, _ := net.ParseCIDR("203.0.113.0/24")
	table := NewTable([]Rule{
		{
			Type:   TypeDNAT,
			DstNet: dstNet,
			ToIP:   net.ParseIP("192.168.1.10"),
			ToPort: 8080,
		},
	})

	inbound := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("1.1.1.1"),
			DstIP:    net.ParseIP("203.0.113.25"),
			SrcPort:  50000,
			DstPort:  80,
		},
	}
	table.Apply(inbound)

	outbound := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("192.168.1.10"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  8080,
			DstPort:  50000,
		},
	}
	out := table.Apply(outbound)
	if out.Metadata.SrcIP.String() != "203.0.113.25" {
		t.Fatalf("expected reverse dnat src, got %s", out.Metadata.SrcIP)
	}
	if out.Metadata.SrcPort != 80 {
		t.Fatalf("expected reverse dnat src port, got %d", out.Metadata.SrcPort)
	}
}

func TestRuleHits(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	table.Apply(pkt)
	table.Apply(pkt)

	stats := table.RulesWithStats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(stats))
	}
	if stats[0].Hits != 2 {
		t.Fatalf("expected 2 hits, got %d", stats[0].Hits)
	}
}

func TestAddRuleAndRulesCopy(t *testing.T) {
	table := NewTable(nil)
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table.AddRule(Rule{
		Type:   TypeSNAT,
		SrcNet: srcNet,
		ToIP:   net.ParseIP("203.0.113.10"),
	})
	rules := table.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rules[0].Type = TypeDNAT
	if table.Rules()[0].Type != TypeSNAT {
		t.Fatalf("expected rules slice to be a copy")
	}
}

func TestResetStats(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})
	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	table.Apply(pkt)
	table.ResetStats()

	stats := table.RulesWithStats()
	if stats[0].Hits != 0 {
		t.Fatalf("expected hits reset to 0, got %d", stats[0].Hits)
	}
}

func TestReplaceRulesResetsConnsAndHits(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})
	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	out := table.Apply(pkt)
	if out.Metadata.SrcIP.String() != "203.0.113.10" {
		t.Fatalf("expected SNAT applied, got %s", out.Metadata.SrcIP)
	}

	_, newSrcNet, _ := net.ParseCIDR("192.168.0.0/16")
	table.ReplaceRules([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: newSrcNet,
			ToIP:   net.ParseIP("203.0.113.20"),
		},
	})
	out2 := table.Apply(pkt)
	if out2.Metadata.SrcIP.String() != "10.1.2.3" {
		t.Fatalf("expected no match after replace, got %s", out2.Metadata.SrcIP)
	}
	stats := table.RulesWithStats()
	if len(stats) != 1 || stats[0].Hits != 0 {
		t.Fatalf("expected hits reset after replace, got %+v", stats)
	}
}

func TestRemoveRule(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
			ToPort: 40000,
		},
	})
	ok := table.RemoveRule(Rule{
		Type:   TypeSNAT,
		SrcNet: srcNet,
		ToIP:   net.ParseIP("203.0.113.10"),
		ToPort: 40000,
	})
	if !ok {
		t.Fatalf("expected rule removed")
	}
	if len(table.Rules()) != 0 {
		t.Fatalf("expected no rules left")
	}
	if table.RemoveRule(Rule{Type: TypeSNAT}) {
		t.Fatalf("expected remove to fail for missing rule")
	}
}

func TestUpdateRule(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
			ToPort: 40000,
		},
	})
	ok := table.UpdateRule(
		Rule{Type: TypeSNAT, SrcNet: srcNet, ToIP: net.ParseIP("203.0.113.10"), ToPort: 40000},
		Rule{Type: TypeSNAT, SrcNet: srcNet, ToIP: net.ParseIP("203.0.113.11"), ToPort: 40001},
	)
	if !ok {
		t.Fatalf("expected update to succeed")
	}
	rules := table.Rules()
	if rules[0].ToPort != 40001 || !rules[0].ToIP.Equal(net.ParseIP("203.0.113.11")) {
		t.Fatalf("unexpected updated rule: %+v", rules[0])
	}
	if table.UpdateRule(Rule{Type: TypeDNAT}, Rule{Type: TypeDNAT}) {
		t.Fatalf("expected update to fail for missing rule")
	}
}

func TestApplySNATRewritesIPv4UDPData(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Rule{
		{
			Type:   TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
			ToPort: 40000,
		},
	})

	raw := buildIPv4UDPPacket(t, net.ParseIP("10.1.2.3"), net.ParseIP("8.8.8.8"), 1234, 53)
	out := table.Apply(network.Packet{
		Data: raw,
		Metadata: network.PacketMetadata{
			Protocol:    "UDP",
			ProtocolNum: 17,
			SrcIP:       net.ParseIP("10.1.2.3"),
			DstIP:       net.ParseIP("8.8.8.8"),
			SrcPort:     1234,
			DstPort:     53,
		},
	})

	meta, err := network.ParseIPMetadata(out.Data)
	if err != nil {
		t.Fatalf("parse metadata after snat: %v", err)
	}
	if got := meta.SrcIP.String(); got != "203.0.113.10" {
		t.Fatalf("expected src ip rewritten, got %s", got)
	}
	if meta.SrcPort != 40000 {
		t.Fatalf("expected src port rewritten, got %d", meta.SrcPort)
	}
	if !verifyIPv4HeaderChecksum(out.Data) {
		t.Fatalf("invalid ipv4 header checksum")
	}
	if !verifyIPv4UDPChecksum(out.Data) {
		t.Fatalf("invalid udp checksum after snat")
	}
}

func TestApplyDNATRewritesIPv4UDPData(t *testing.T) {
	_, dstNet, _ := net.ParseCIDR("198.51.100.0/24")
	table := NewTable([]Rule{
		{
			Type:   TypeDNAT,
			DstNet: dstNet,
			ToIP:   net.ParseIP("192.168.1.10"),
			ToPort: 8080,
		},
	})

	raw := buildIPv4UDPPacket(t, net.ParseIP("10.1.2.3"), net.ParseIP("198.51.100.25"), 60000, 80)
	out := table.Apply(network.Packet{
		Data: raw,
		Metadata: network.PacketMetadata{
			Protocol:    "UDP",
			ProtocolNum: 17,
			SrcIP:       net.ParseIP("10.1.2.3"),
			DstIP:       net.ParseIP("198.51.100.25"),
			SrcPort:     60000,
			DstPort:     80,
		},
	})

	meta, err := network.ParseIPMetadata(out.Data)
	if err != nil {
		t.Fatalf("parse metadata after dnat: %v", err)
	}
	if got := meta.DstIP.String(); got != "192.168.1.10" {
		t.Fatalf("expected dst ip rewritten, got %s", got)
	}
	if meta.DstPort != 8080 {
		t.Fatalf("expected dst port rewritten, got %d", meta.DstPort)
	}
	if !verifyIPv4HeaderChecksum(out.Data) {
		t.Fatalf("invalid ipv4 header checksum")
	}
	if !verifyIPv4UDPChecksum(out.Data) {
		t.Fatalf("invalid udp checksum after dnat")
	}
}

func buildIPv4UDPPacket(t *testing.T, srcIP net.IP, dstIP net.IP, srcPort int, dstPort int) []byte {
	t.Helper()
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		t.Fatalf("expected ipv4 addresses")
	}
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[6], pkt[7] = 0x40, 0x00
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], network.Checksum(pkt[:20]))

	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	udpSum := checksumIPv4UDP(pkt)
	if udpSum == 0 {
		udpSum = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[26:28], udpSum)
	return pkt
}

func verifyIPv4HeaderChecksum(pkt []byte) bool {
	if len(pkt) < 20 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return false
	}
	hdr := append([]byte(nil), pkt[:ihl]...)
	hdr[10], hdr[11] = 0, 0
	expected := network.Checksum(hdr)
	actual := binary.BigEndian.Uint16(pkt[10:12])
	return expected == actual
}

func verifyIPv4UDPChecksum(pkt []byte) bool {
	if len(pkt) < 28 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return false
	}
	actual := binary.BigEndian.Uint16(pkt[ihl+6 : ihl+8])
	if actual == 0 {
		return true
	}
	expected := checksumIPv4UDP(pkt)
	if expected == 0 {
		expected = 0xffff
	}
	return expected == actual
}

func checksumIPv4UDP(pkt []byte) uint16 {
	ihl := int(pkt[0]&0x0f) * 4
	udp := append([]byte(nil), pkt[ihl:]...)
	if len(udp) < 8 {
		return 0
	}
	udp[6], udp[7] = 0, 0
	pseudo := make([]byte, 0, 12+len(udp))
	pseudo = append(pseudo, pkt[12:16]...)
	pseudo = append(pseudo, pkt[16:20]...)
	pseudo = append(pseudo, 0, 17)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(udp)))
	pseudo = append(pseudo, lenBuf...)
	pseudo = append(pseudo, udp...)
	return network.Checksum(pseudo)
}
