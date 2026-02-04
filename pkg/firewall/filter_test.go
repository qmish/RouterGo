package firewall

import (
	"net"
	"testing"

	"router-go/pkg/network"
)

func TestFirewallAccept(t *testing.T) {
	_, dstNet, _ := net.ParseCIDR("10.0.0.0/8")
	engine := NewEngine([]Rule{
		{
			Chain:    "FORWARD",
			Action:   ActionAccept,
			Protocol: "TCP",
			DstNet:   dstNet,
			DstPort:  80,
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			DstIP:    net.ParseIP("10.1.2.3"),
			DstPort:  80,
		},
	}

	if got := engine.Evaluate("FORWARD", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
}

func TestFirewallOutInterfaceMatch(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:        "FORWARD",
			Action:       ActionAccept,
			OutInterface: "wan0",
		},
	})

	pkt := network.Packet{
		EgressInterface: "wan0",
		Metadata: network.PacketMetadata{
			Protocol: "UDP",
		},
	}

	if got := engine.Evaluate("FORWARD", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
}

func TestFirewallChainMismatchDrops(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:  "INPUT",
			Action: ActionAccept,
		},
	})

	pkt := network.Packet{}
	if got := engine.Evaluate("FORWARD", pkt); got != ActionDrop {
		t.Fatalf("expected DROP, got %s", got)
	}
}

func TestFirewallDefaultPolicy(t *testing.T) {
	engine := NewEngineWithDefaults(nil, map[string]Action{
		"INPUT":  ActionAccept,
		"OUTPUT": ActionDrop,
	})

	pkt := network.Packet{}
	if got := engine.Evaluate("INPUT", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
	if got := engine.Evaluate("OUTPUT", pkt); got != ActionDrop {
		t.Fatalf("expected DROP, got %s", got)
	}
}
