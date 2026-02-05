package main

import (
	"net"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/routing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestHandlePacketCallsRelease(t *testing.T) {
	released := false
	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("10.0.0.2"),
			Protocol: "UDP",
		},
		Release: func() {
			released = true
		},
	}
	routes := routing.NewTable(nil)
	fw := firewall.NewEngine(nil)
	natTable := nat.NewTable(nil)
	m := metrics.NewWithRegistry(prometheus.NewRegistry())

	handlePacket(pkt, nil, routes, fw, nil, natTable, nil, m, nil)

	if !released {
		t.Fatalf("expected packet release")
	}
}
