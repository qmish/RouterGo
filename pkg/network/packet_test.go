package network

import (
	"net"
	"testing"
)

func TestParseIPv4Header(t *testing.T) {
	data := []byte{
		0x45, 0x00, 0x00, 0x3c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x01,
		0x08, 0x08, 0x08, 0x08,
	}

	h, err := ParseIPv4Header(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Version != 4 || h.IHL != 20 {
		t.Fatalf("unexpected version/ihl: %d/%d", h.Version, h.IHL)
	}
	if h.TotalLength != 60 {
		t.Fatalf("unexpected total length: %d", h.TotalLength)
	}
	if h.Protocol != 0x11 {
		t.Fatalf("unexpected protocol: %d", h.Protocol)
	}
	if !h.SrcIP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("unexpected src ip: %s", h.SrcIP)
	}
	if !h.DstIP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("unexpected dst ip: %s", h.DstIP)
	}
}

func TestChecksumEvenLength(t *testing.T) {
	data := []byte{0x00, 0x01, 0xF2, 0x03}
	sum := Checksum(data)
	if sum != 0x0DFB {
		t.Fatalf("unexpected checksum: 0x%04X", sum)
	}
}

func TestChecksumOddLength(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56}
	sum := Checksum(data)
	if sum == 0 {
		t.Fatalf("unexpected checksum: 0x%04X", sum)
	}
}

func TestParseIPv4MetadataTCPPorts(t *testing.T) {
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
	}
	tcpHeader := []byte{
		0x1f, 0x90, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipHeader, tcpHeader...)

	meta, err := ParseIPv4Metadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "TCP" {
		t.Fatalf("expected TCP, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 6 {
		t.Fatalf("expected protocol num 6, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 8080 || meta.DstPort != 80 {
		t.Fatalf("unexpected ports: %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPv4MetadataUDPPorts(t *testing.T) {
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
	}
	udpHeader := []byte{
		0x13, 0x88, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	data := append(ipHeader, udpHeader...)

	meta, err := ParseIPv4Metadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "UDP" {
		t.Fatalf("expected UDP, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 17 {
		t.Fatalf("expected protocol num 17, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 5000 || meta.DstPort != 53 {
		t.Fatalf("unexpected ports: %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPv4MetadataICMP(t *testing.T) {
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
	}
	icmpHeader := []byte{
		0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipHeader, icmpHeader...)

	meta, err := ParseIPv4Metadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "ICMP" {
		t.Fatalf("expected ICMP, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 1 {
		t.Fatalf("expected protocol num 1, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 0 || meta.DstPort != 0 {
		t.Fatalf("expected empty ports, got %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPv6Header(t *testing.T) {
	data := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x14, 0x06, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	h, err := ParseIPv6Header(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Version != 6 {
		t.Fatalf("expected version 6, got %d", h.Version)
	}
	if h.PayloadLength != 20 {
		t.Fatalf("expected payload length 20, got %d", h.PayloadLength)
	}
	if h.NextHeader != 6 {
		t.Fatalf("expected TCP next header, got %d", h.NextHeader)
	}
}

func TestParseIPv6MetadataTCPPorts(t *testing.T) {
	ipv6Header := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x14, 0x06, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	tcpHeader := []byte{
		0x1f, 0x90, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x72, 0x10,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipv6Header, tcpHeader...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "TCP" {
		t.Fatalf("expected TCP, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 6 {
		t.Fatalf("expected protocol num 6, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 8080 || meta.DstPort != 80 {
		t.Fatalf("unexpected ports: %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPv6MetadataUDPPorts(t *testing.T) {
	ipv6Header := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x11, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	udpHeader := []byte{
		0x13, 0x88, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	data := append(ipv6Header, udpHeader...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "UDP" {
		t.Fatalf("expected UDP, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 17 {
		t.Fatalf("expected protocol num 17, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 5000 || meta.DstPort != 53 {
		t.Fatalf("unexpected ports: %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPv6MetadataICMPv6(t *testing.T) {
	ipv6Header := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x3a, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	icmpHeader := []byte{
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipv6Header, icmpHeader...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "ICMPv6" {
		t.Fatalf("expected ICMPv6, got %s", meta.Protocol)
	}
	if meta.ProtocolNum != 58 {
		t.Fatalf("expected protocol num 58, got %d", meta.ProtocolNum)
	}
	if meta.SrcPort != 0 || meta.DstPort != 0 {
		t.Fatalf("expected empty ports, got %d -> %d", meta.SrcPort, meta.DstPort)
	}
}

func TestParseIPMetadataCopiesIPv4Addresses(t *testing.T) {
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
	}
	udpHeader := []byte{
		0x13, 0x88, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	data := append(ipHeader, udpHeader...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	src := meta.SrcIP
	dst := meta.DstIP

	data[12] = 0x7f
	data[16] = 0x7f

	if !src.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("src ip changed unexpectedly: %s", src)
	}
	if !dst.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("dst ip changed unexpectedly: %s", dst)
	}
}

func TestParseIPv4MetadataICMPTypeCode(t *testing.T) {
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x02,
	}
	icmpHeader := []byte{
		0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipHeader, icmpHeader...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "ICMP" {
		t.Fatalf("expected ICMP, got %s", meta.Protocol)
	}
	if meta.ICMPType != 8 || meta.ICMPCode != 0 {
		t.Fatalf("unexpected icmp type/code: %d/%d", meta.ICMPType, meta.ICMPCode)
	}
}

func TestParseIPv6MetadataICMPv6TypeCode(t *testing.T) {
	ipv6Header := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x3a, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	icmpv6Header := []byte{
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	data := append(ipv6Header, icmpv6Header...)

	meta, err := ParseIPMetadata(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != "ICMPv6" {
		t.Fatalf("expected ICMPv6, got %s", meta.Protocol)
	}
	if meta.ICMPType != 128 || meta.ICMPCode != 0 {
		t.Fatalf("unexpected icmpv6 type/code: %d/%d", meta.ICMPType, meta.ICMPCode)
	}
}
