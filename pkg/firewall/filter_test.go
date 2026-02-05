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

func TestFirewallRuleHits(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:  "FORWARD",
			Action: ActionAccept,
		},
	})

	pkt := network.Packet{}
	engine.Evaluate("FORWARD", pkt)
	engine.Evaluate("FORWARD", pkt)

	stats := engine.RulesWithStats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(stats))
	}
	if stats[0].Hits != 2 {
		t.Fatalf("expected 2 hits, got %d", stats[0].Hits)
	}
}

func TestFirewallChainHits(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:  "FORWARD",
			Action: ActionAccept,
		},
	})

	pkt := network.Packet{}
	engine.Evaluate("FORWARD", pkt)
	engine.Evaluate("INPUT", pkt)
	engine.Evaluate("INPUT", pkt)

	hits := engine.ChainHits()
	if hits["FORWARD"] != 1 {
		t.Fatalf("expected FORWARD hits 1, got %d", hits["FORWARD"])
	}
	if hits["INPUT"] != 2 {
		t.Fatalf("expected INPUT hits 2, got %d", hits["INPUT"])
	}
}

func TestFirewallCaseInsensitiveMatch(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:    "forward",
			Action:   ActionAccept,
			Protocol: "tcp",
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
		},
	}

	if got := engine.Evaluate("FORWARD", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
}

func TestFirewallProtocolKeyMatch(t *testing.T) {
	engine := NewEngine([]Rule{
		{
			Chain:    "FORWARD",
			Action:   ActionAccept,
			Protocol: "ICMPv6",
		},
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "icmpv6",
		},
	}

	if got := engine.Evaluate("FORWARD", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
}

func TestFirewallAddRuleAndRules(t *testing.T) {
	engine := NewEngine(nil)
	engine.AddRule(Rule{
		Chain:  "INPUT",
		Action: ActionAccept,
	})
	rules := engine.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rules[0].Chain = "OUTPUT"
	if engine.Rules()[0].Chain != "INPUT" {
		t.Fatalf("expected rules slice to be a copy")
	}
}

func TestFirewallSetDefaultPolicy(t *testing.T) {
	engine := NewEngine(nil)
	engine.SetDefaultPolicy("input", ActionAccept)
	engine.SetDefaultPolicy("OUTPUT", ActionDrop)
	policies := engine.DefaultPolicies()
	if policies["INPUT"] != ActionAccept {
		t.Fatalf("expected INPUT=ACCEPT, got %s", policies["INPUT"])
	}
	if policies["OUTPUT"] != ActionDrop {
		t.Fatalf("expected OUTPUT=DROP, got %s", policies["OUTPUT"])
	}
	policies["INPUT"] = ActionDrop
	if engine.DefaultPolicies()["INPUT"] != ActionAccept {
		t.Fatalf("expected default policies to be a copy")
	}
}

func TestFirewallResetStats(t *testing.T) {
	engine := NewEngine([]Rule{
		{Chain: "FORWARD", Action: ActionAccept},
	})
	pkt := network.Packet{}
	engine.Evaluate("FORWARD", pkt)
	engine.Evaluate("INPUT", pkt)
	engine.ResetStats()

	stats := engine.RulesWithStats()
	if stats[0].Hits != 0 {
		t.Fatalf("expected rule hits reset to 0, got %d", stats[0].Hits)
	}
	hits := engine.ChainHits()
	if hits["FORWARD"] != 0 || hits["INPUT"] != 0 {
		t.Fatalf("expected chain hits reset to 0, got %v", hits)
	}
}

func TestFirewallReplace(t *testing.T) {
	engine := NewEngine(nil)
	engine.Replace([]Rule{
		{Chain: "INPUT", Action: ActionAccept},
	}, map[string]Action{"INPUT": ActionDrop})
	pkt := network.Packet{}
	if got := engine.Evaluate("INPUT", pkt); got != ActionAccept {
		t.Fatalf("expected ACCEPT, got %s", got)
	}
	if engine.DefaultPolicies()["INPUT"] != ActionDrop {
		t.Fatalf("expected default policy INPUT=DROP")
	}
}

func TestFirewallRemoveRule(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	engine := NewEngine([]Rule{
		{
			Chain:    "INPUT",
			Action:   ActionAccept,
			Protocol: "TCP",
			SrcNet:   srcNet,
			DstPort:  22,
		},
	})
	ok := engine.RemoveRule(Rule{
		Chain:    "INPUT",
		Action:   ActionAccept,
		Protocol: "TCP",
		SrcNet:   srcNet,
		DstPort:  22,
	})
	if !ok {
		t.Fatalf("expected rule removed")
	}
	if len(engine.Rules()) != 0 {
		t.Fatalf("expected no rules left")
	}
	if engine.RemoveRule(Rule{Chain: "INPUT"}) {
		t.Fatalf("expected remove to fail for missing rule")
	}
}

func TestFirewallUpdateRule(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	engine := NewEngine([]Rule{
		{
			Chain:    "INPUT",
			Action:   ActionAccept,
			Protocol: "TCP",
			SrcNet:   srcNet,
			DstPort:  22,
		},
	})
	ok := engine.UpdateRule(
		Rule{Chain: "INPUT", Action: ActionAccept, Protocol: "TCP", SrcNet: srcNet, DstPort: 22},
		Rule{Chain: "INPUT", Action: ActionDrop, Protocol: "TCP", SrcNet: srcNet, DstPort: 22},
	)
	if !ok {
		t.Fatalf("expected update to succeed")
	}
	rules := engine.Rules()
	if len(rules) != 1 || rules[0].Action != ActionDrop {
		t.Fatalf("unexpected updated rule: %+v", rules)
	}
	if engine.UpdateRule(Rule{Chain: "OUTPUT"}, Rule{Chain: "OUTPUT"}) {
		t.Fatalf("expected update to fail for missing rule")
	}
}
