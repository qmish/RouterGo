package nat

import (
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
