package flow

import (
	"net"
	"testing"

	"router-go/pkg/network"
)

func TestTopBandwidth(t *testing.T) {
	engine := NewEngine()
	engine.AddPacket(network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:  net.ParseIP("10.0.0.1"),
			DstIP:  net.ParseIP("1.1.1.1"),
			Length: 100,
		},
	})
	engine.AddPacket(network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:  net.ParseIP("10.0.0.2"),
			DstIP:  net.ParseIP("1.1.1.1"),
			Length: 300,
		},
	})

	top := engine.TopBandwidth(1)
	if len(top) != 1 || top[0].SrcIP != "10.0.0.2" {
		t.Fatalf("expected top src 10.0.0.2")
	}
}

func TestSessionsTree(t *testing.T) {
	engine := NewEngine()
	engine.AddPacket(network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:  net.ParseIP("10.0.0.1"),
			DstIP:  net.ParseIP("1.1.1.1"),
			Length: 100,
		},
	})
	engine.AddPacket(network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:  net.ParseIP("10.0.0.1"),
			DstIP:  net.ParseIP("1.1.1.2"),
			Length: 200,
		},
	})

	tree := engine.SessionsTree()
	if len(tree["10.0.0.1"]) != 2 {
		t.Fatalf("expected two destinations")
	}
	if tree["10.0.0.1"][0].Bytes != 200 {
		t.Fatalf("expected sorted by bytes desc")
	}
}
