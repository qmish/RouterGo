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
