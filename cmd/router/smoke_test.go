package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestSmokePacketPipelineThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skip smoke throughput test in short mode")
	}

	iterations := 50000

	_, routeNet, _ := net.ParseCIDR("8.8.8.0/24")
	_, natSrcNet, _ := net.ParseCIDR("10.0.0.0/24")
	_, fwSrcNet, _ := net.ParseCIDR("203.0.113.0/24")
	routes := routing.NewTable([]routing.Route{
		{Destination: *routeNet, Interface: "wan1", Metric: 10},
	})
	natTable := nat.NewTable([]nat.Rule{
		{Type: nat.TypeSNAT, SrcNet: natSrcNet, ToIP: net.ParseIP("203.0.113.10"), ToPort: 40000},
	})
	fw := firewall.NewEngineWithDefaults([]firewall.Rule{
		{
			Chain:        "FORWARD",
			Action:       firewall.ActionAccept,
			Protocol:     "UDP",
			SrcNet:       fwSrcNet,
			OutInterface: "wan1",
		},
	}, map[string]firewall.Action{
		"FORWARD": firewall.ActionDrop,
	})
	queue := qos.NewQueueManager(nil)
	metricsSrv := metrics.NewWithRegistry(prometheus.NewRegistry())

	templateData := buildSmokeIPv4UDPPacket(net.ParseIP("10.0.0.2"), net.ParseIP("8.8.8.8"), 12000, 53)
	start := time.Now()
	dropped := 0
	for i := 0; i < iterations; i++ {
		pkt := network.Packet{
			Data: append([]byte(nil), templateData...),
			Metadata: network.PacketMetadata{
				Protocol:    "UDP",
				ProtocolNum: 17,
				SrcIP:       net.ParseIP("10.0.0.2"),
				DstIP:       net.ParseIP("8.8.8.8"),
				SrcPort:     12000,
				DstPort:     53,
			},
		}
		processPacket(pkt, nil, routes, fw, nil, natTable, queue, metricsSrv, nil)
		if _, ok := queue.Dequeue(); !ok {
			dropped++
		}
	}
	elapsed := time.Since(start)
	processed := iterations - dropped
	pps := float64(processed) / elapsed.Seconds()
	dropRate := (float64(dropped) / float64(iterations)) * 100

	t.Logf("smoke iterations=%d processed=%d dropped=%d elapsed=%s pps=%.2f drop_rate=%.2f%%",
		iterations, processed, dropped, elapsed, pps, dropRate)

	if dropped != 0 {
		t.Fatalf("expected no drops in smoke test, got %d", dropped)
	}
}

func buildSmokeIPv4UDPPacket(srcIP net.IP, dstIP net.IP, srcPort int, dstPort int) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[6], pkt[7] = 0x40, 0x00
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], network.Checksum(pkt[:20]))

	binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
	binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	sum := smokeChecksumIPv4UDP(pkt)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[26:28], sum)
	return pkt
}

func smokeChecksumIPv4UDP(pkt []byte) uint16 {
	ihl := int(pkt[0]&0x0f) * 4
	udp := append([]byte(nil), pkt[ihl:]...)
	udp[6], udp[7] = 0, 0
	pseudo := make([]byte, 0, 12+len(udp))
	pseudo = append(pseudo, pkt[12:16]...)
	pseudo = append(pseudo, pkt[16:20]...)
	pseudo = append(pseudo, 0, 17)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(udp)))
	pseudo = append(pseudo, lenBuf...)
	pseudo = append(pseudo, udp...)
	return network.Checksum(pseudo)
}
