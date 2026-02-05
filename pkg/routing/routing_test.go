package routing

import (
	"net"
	"testing"
)

func TestLookupLongestPrefix(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, bNet, _ := net.ParseCIDR("10.1.0.0/16")

	table := NewTable([]Route{
		{Destination: *aNet, Interface: "eth0"},
		{Destination: *bNet, Interface: "eth1"},
	})

	dst := net.ParseIP("10.1.2.3")
	route, ok := table.Lookup(dst)
	if !ok {
		t.Fatalf("expected a route match")
	}
	if route.Interface != "eth1" {
		t.Fatalf("expected eth1, got %s", route.Interface)
	}
}

func TestLookupNoMatch(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Route{{Destination: *aNet, Interface: "eth0"}})
	dst := net.ParseIP("192.168.1.10")
	_, ok := table.Lookup(dst)
	if ok {
		t.Fatalf("expected no route match")
	}
}

func TestLookupPreferLowerMetricOnEqualPrefix(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.1.0.0/16")
	table := NewTable([]Route{
		{Destination: *aNet, Interface: "eth0", Metric: 100},
		{Destination: *aNet, Interface: "eth1", Metric: 10},
	})

	dst := net.ParseIP("10.1.2.3")
	route, ok := table.Lookup(dst)
	if !ok {
		t.Fatalf("expected a route match")
	}
	if route.Interface != "eth1" {
		t.Fatalf("expected eth1 (lower metric), got %s", route.Interface)
	}
}

func TestLookupAfterAdd(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, bNet, _ := net.ParseCIDR("10.2.0.0/16")
	table := NewTable([]Route{{Destination: *aNet, Interface: "eth0"}})

	table.Add(Route{Destination: *bNet, Interface: "eth1"})

	dst := net.ParseIP("10.2.1.1")
	route, ok := table.Lookup(dst)
	if !ok {
		t.Fatalf("expected a route match")
	}
	if route.Interface != "eth1" {
		t.Fatalf("expected eth1, got %s", route.Interface)
	}
}

func TestLookupAfterReplaceRoutes(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, bNet, _ := net.ParseCIDR("192.168.0.0/16")
	table := NewTable([]Route{{Destination: *aNet, Interface: "eth0"}})

	table.ReplaceRoutes([]Route{{Destination: *bNet, Interface: "eth1"}})

	dst := net.ParseIP("192.168.1.10")
	route, ok := table.Lookup(dst)
	if !ok {
		t.Fatalf("expected a route match")
	}
	if route.Interface != "eth1" {
		t.Fatalf("expected eth1, got %s", route.Interface)
	}
}

func TestRoutesReturnsCopy(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	table := NewTable([]Route{{Destination: *aNet, Interface: "eth0"}})

	routes := table.Routes()
	routes[0].Interface = "eth1"

	routes2 := table.Routes()
	if routes2[0].Interface != "eth0" {
		t.Fatalf("expected original routes unchanged, got %s", routes2[0].Interface)
	}
}

func TestRemoveRoute(t *testing.T) {
	_, aNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, bNet, _ := net.ParseCIDR("192.168.0.0/16")
	table := NewTable([]Route{
		{Destination: *aNet, Interface: "eth0", Metric: 10},
		{Destination: *bNet, Interface: "eth1", Metric: 5, Gateway: net.ParseIP("192.0.2.1")},
	})

	ok := table.RemoveRoute(Route{
		Destination: *bNet,
		Interface:   "eth1",
		Metric:      5,
		Gateway:     net.ParseIP("192.0.2.1"),
	})
	if !ok {
		t.Fatalf("expected route to be removed")
	}
	if len(table.Routes()) != 1 {
		t.Fatalf("expected 1 remaining route")
	}
	if table.RemoveRoute(Route{Destination: *bNet, Interface: "eth1"}) {
		t.Fatalf("expected remove to fail for missing route")
	}
}
