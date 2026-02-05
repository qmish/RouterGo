package ids

import (
	"fmt"
	"net"
	"testing"
	"time"

	"router-go/pkg/network"
)

func TestSignatureRuleMatch(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:            "test-signature",
		Action:          ActionDrop,
		Protocol:        "TCP",
		SrcNet:          srcNet,
		DstPort:         80,
		PayloadContains: "GET",
		Enabled:         true,
	})

	pkt := network.Packet{
		Data: []byte("GET / HTTP/1.1"),
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}

	res := engine.Detect(pkt)
	if !res.Drop {
		t.Fatalf("expected drop for signature match")
	}
	if res.Alert == nil || res.Alert.Type != "SIGNATURE" {
		t.Fatalf("expected signature alert")
	}
}

func TestSignatureRuleProtocolNumMatch(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:     "proto-num",
		Action:   ActionAlert,
		Protocol: "TCP",
		Enabled:  true,
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			ProtocolNum: 6,
			SrcIP:       net.ParseIP("10.0.0.1"),
			DstIP:       net.ParseIP("1.1.1.1"),
		},
	}

	res := engine.Detect(pkt)
	if res.Alert == nil || res.Alert.Reason != "proto-num" {
		t.Fatalf("expected protocol num match")
	}
}

func TestSignatureRuleProtocolNumMismatch(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:     "proto-udp",
		Action:   ActionAlert,
		Protocol: "UDP",
		Enabled:  true,
	})

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			ProtocolNum: 6,
			SrcIP:       net.ParseIP("10.0.0.1"),
			DstIP:       net.ParseIP("1.1.1.1"),
		},
	}

	res := engine.Detect(pkt)
	if res.Alert != nil {
		t.Fatalf("expected protocol num mismatch to skip")
	}
}

func TestRulePriority(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:     "low",
		Action:   ActionAlert,
		Protocol: "TCP",
		DstPort:  80,
		Priority: 1,
		Enabled:  true,
	})
	engine.AddRule(Rule{
		Name:     "high",
		Action:   ActionDrop,
		Protocol: "TCP",
		DstPort:  80,
		Priority: 10,
		Enabled:  true,
	})

	res := engine.Detect(network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("1.1.1.1"),
			DstPort:  80,
		},
	})
	if res.Alert == nil || res.Alert.Reason != "high" {
		t.Fatalf("expected high priority rule to match")
	}
	if !res.Drop {
		t.Fatalf("expected drop for high priority rule")
	}
}

func TestWhitelistSkipsDetection(t *testing.T) {
	_, whiteNet, _ := net.ParseCIDR("10.1.0.0/16")
	engine := NewEngine(Config{
		WhitelistSrc: []*net.IPNet{whiteNet},
		AlertLimit:   10,
	})
	engine.AddRule(Rule{
		Name:     "test",
		Action:   ActionDrop,
		Protocol: "TCP",
		DstPort:  80,
		Enabled:  true,
	})
	res := engine.Detect(network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			DstPort:  80,
		},
	})
	if res.Alert != nil || res.Drop {
		t.Fatalf("expected whitelist to bypass detection")
	}
}

func TestRateSpikeBehavior(t *testing.T) {
	engine := NewEngine(Config{
		Window:         5 * time.Second,
		RateThreshold:  3,
		BehaviorAction: ActionAlert,
		AlertLimit:     10,
	})
	now := time.Now()
	engine.nowFunc = func() time.Time { return now }

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "UDP",
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("1.1.1.1"),
			DstPort:  53,
		},
	}

	engine.Detect(pkt)
	engine.Detect(pkt)
	res := engine.Detect(pkt)

	if res.Alert == nil || res.Alert.Type != "RATE_SPIKE" {
		t.Fatalf("expected rate spike alert")
	}
	if res.Drop {
		t.Fatalf("expected alert-only behavior")
	}
}

func TestPortScanBehavior(t *testing.T) {
	engine := NewEngine(Config{
		Window:            5 * time.Second,
		PortScanThreshold: 3,
		BehaviorAction:    ActionDrop,
		AlertLimit:        10,
	})
	now := time.Now()
	engine.nowFunc = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		engine.Detect(network.Packet{
			Metadata: network.PacketMetadata{
				Protocol: "TCP",
				SrcIP:    net.ParseIP("10.0.0.2"),
				DstIP:    net.ParseIP("1.1.1.1"),
				DstPort:  1000 + i,
			},
		})
	}

	res := engine.Detect(network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.0.0.2"),
			DstIP:    net.ParseIP("1.1.1.1"),
			DstPort:  1002,
		},
	})

	if res.Alert == nil || res.Alert.Type != "PORT_SCAN" {
		t.Fatalf("expected port scan alert")
	}
	if !res.Drop {
		t.Fatalf("expected drop for port scan")
	}
}

func TestUniqueDstBehavior(t *testing.T) {
	engine := NewEngine(Config{
		Window:             5 * time.Second,
		UniqueDstThreshold: 3,
		BehaviorAction:     ActionAlert,
		AlertLimit:         10,
	})
	now := time.Now()
	engine.nowFunc = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		engine.Detect(network.Packet{
			Metadata: network.PacketMetadata{
				Protocol: "TCP",
				SrcIP:    net.ParseIP("10.0.0.3"),
				DstIP:    net.ParseIP(fmt.Sprintf("1.1.1.%d", i+1)),
			},
		})
	}

	res := engine.Detect(network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.0.0.3"),
			DstIP:    net.ParseIP("1.1.1.9"),
		},
	})

	if res.Alert == nil || res.Alert.Type != "DST_SWEEP" {
		t.Fatalf("expected dst sweep alert")
	}
	if res.Drop {
		t.Fatalf("expected alert-only behavior")
	}
}

func TestUpdateRuleAndGetRule(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:     "r1",
		Action:   ActionAlert,
		Protocol: "TCP",
		Enabled:  true,
	})

	if ok := engine.UpdateRule("r1", Rule{
		Action:   ActionDrop,
		Protocol: "UDP",
		DstPort:  53,
		Enabled:  false,
	}); !ok {
		t.Fatalf("expected update to succeed")
	}
	rule, ok := engine.GetRule("r1")
	if !ok {
		t.Fatalf("expected rule r1 to exist")
	}
	if rule.Action != ActionDrop || rule.Protocol != "UDP" || rule.DstPort != 53 || rule.Enabled {
		t.Fatalf("unexpected updated rule: %+v", rule)
	}
	if ok := engine.UpdateRule("missing", Rule{Action: ActionDrop}); ok {
		t.Fatalf("expected update to fail for missing rule")
	}
}

func TestDeleteRule(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{Name: "r1", Action: ActionAlert, Enabled: true})
	engine.AddRule(Rule{Name: "r2", Action: ActionAlert, Enabled: true})

	if ok := engine.DeleteRule("r1"); !ok {
		t.Fatalf("expected delete to succeed")
	}
	if _, ok := engine.GetRule("r1"); ok {
		t.Fatalf("expected r1 to be deleted")
	}
	if ok := engine.DeleteRule("missing"); ok {
		t.Fatalf("expected delete to fail for missing rule")
	}
}

func TestRulesAndAlertsReset(t *testing.T) {
	engine := NewEngine(Config{AlertLimit: 10})
	engine.AddRule(Rule{
		Name:            "sig",
		Action:          ActionAlert,
		Protocol:        "TCP",
		PayloadContains: "GET",
		Enabled:         true,
	})

	pkt := network.Packet{
		Data: []byte("GET / HTTP/1.1"),
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	engine.Detect(pkt)

	alerts := engine.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	alerts[0].Reason = "changed"
	alertsAgain := engine.Alerts()
	if alertsAgain[0].Reason != "sig" {
		t.Fatalf("expected alerts slice to be a copy")
	}

	rules := engine.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rules[0].Name = "changed"
	if engine.Rules()[0].Name != "sig" {
		t.Fatalf("expected rules slice to be a copy")
	}

	stats := engine.RulesWithStats()
	if len(stats) != 1 || stats[0].Hits == 0 {
		t.Fatalf("expected rule hits recorded")
	}

	engine.Reset()
	if len(engine.Alerts()) != 0 {
		t.Fatalf("expected alerts cleared")
	}
	stats = engine.RulesWithStats()
	if len(stats) != 1 || stats[0].Hits != 0 {
		t.Fatalf("expected rule hits reset, got %+v", stats)
	}
}
