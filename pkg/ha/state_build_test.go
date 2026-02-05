package ha

import (
	"net"
	"testing"

	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"
)

func TestBuildStateAndApplyState(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/24")
	_, dstNet, _ := net.ParseCIDR("192.168.1.0/24")
	_, routeNet, _ := net.ParseCIDR("172.16.0.0/16")

	fw := firewall.NewEngineWithDefaults([]firewall.Rule{
		{
			Chain:        "INPUT",
			Action:       firewall.ActionDrop,
			Protocol:     "tcp",
			SrcNet:       srcNet,
			DstNet:       dstNet,
			SrcPort:      1234,
			DstPort:      80,
			InInterface:  "eth0",
			OutInterface: "",
		},
	}, map[string]firewall.Action{
		"INPUT": firewall.ActionAccept,
	})

	natTable := nat.NewTable([]nat.Rule{
		{
			Type:    nat.TypeSNAT,
			SrcNet:  srcNet,
			SrcPort: 1234,
			ToIP:    net.ParseIP("1.2.3.4"),
			ToPort:  5555,
		},
	})

	qosQueue := qos.NewQueueManager([]qos.Class{
		{
			Name:          "video",
			Protocol:      "udp",
			DstPort:       5004,
			RateLimitKbps: 1000,
			Priority:      10,
			MaxQueue:      100,
			DropPolicy:    "tail",
		},
	})

	routes := routing.NewTable([]routing.Route{
		{
			Destination: *routeNet,
			Gateway:     net.ParseIP("172.16.0.1"),
			Interface:   "eth0",
			Metric:      10,
		},
	})

	state := BuildState(fw, natTable, qosQueue, routes)
	if len(state.FirewallRules) != 1 {
		t.Fatalf("expected 1 firewall rule, got %d", len(state.FirewallRules))
	}
	if state.FirewallDefaults["INPUT"] != "ACCEPT" {
		t.Fatalf("expected firewall default INPUT=ACCEPT, got %q", state.FirewallDefaults["INPUT"])
	}
	if len(state.NATRules) != 1 || state.NATRules[0].ToIP != "1.2.3.4" {
		t.Fatalf("expected nat rule with ToIP 1.2.3.4")
	}
	if !hasHAQoSClass(state.QoSClasses, "video") {
		t.Fatalf("expected qos class video")
	}
	if len(state.Routes) != 1 || state.Routes[0].Destination != routeNet.String() {
		t.Fatalf("expected route destination %s", routeNet.String())
	}

	fw2 := firewall.NewEngine(nil)
	nat2 := nat.NewTable(nil)
	qos2 := qos.NewQueueManager(nil)
	routes2 := routing.NewTable(nil)

	ApplyState(fw2, nat2, qos2, routes2, state)

	if len(fw2.Rules()) != 1 {
		t.Fatalf("expected 1 firewall rule after apply, got %d", len(fw2.Rules()))
	}
	if fw2.DefaultPolicies()["INPUT"] != firewall.ActionAccept {
		t.Fatalf("expected default policy INPUT=ACCEPT after apply")
	}
	if len(nat2.Rules()) != 1 {
		t.Fatalf("expected 1 nat rule after apply, got %d", len(nat2.Rules()))
	}
	if !hasQoSClass(qos2.Classes(), "video") {
		t.Fatalf("expected qos class video after apply")
	}
	if len(routes2.Routes()) != 1 {
		t.Fatalf("expected 1 route after apply, got %d", len(routes2.Routes()))
	}
}

func hasQoSClass(classes []qos.Class, name string) bool {
	for _, cl := range classes {
		if cl.Name == name {
			return true
		}
	}
	return false
}

func hasHAQoSClass(classes []QoSClass, name string) bool {
	for _, cl := range classes {
		if cl.Name == name {
			return true
		}
	}
	return false
}
