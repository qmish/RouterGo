package main

import (
	"net"
	"testing"

	"router-go/pkg/network"
)

func TestDetermineChain(t *testing.T) {
	local := []net.IP{net.ParseIP("192.168.1.1")}

	inbound := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("1.1.1.1"),
			DstIP: net.ParseIP("192.168.1.1"),
		},
	}
	if got := determineChain(inbound, local); got != "INPUT" {
		t.Fatalf("expected INPUT, got %s", got)
	}

	outbound := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("192.168.1.1"),
			DstIP: net.ParseIP("8.8.8.8"),
		},
	}
	if got := determineChain(outbound, local); got != "OUTPUT" {
		t.Fatalf("expected OUTPUT, got %s", got)
	}

	forward := network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP: net.ParseIP("10.0.0.2"),
			DstIP: net.ParseIP("8.8.4.4"),
		},
	}
	if got := determineChain(forward, local); got != "FORWARD" {
		t.Fatalf("expected FORWARD, got %s", got)
	}
}
