package network

import (
	"encoding/binary"
	"errors"
	"net"
)

var ErrPacketTooShort = errors.New("packet too short")

type Packet struct {
	Data             []byte
	IngressInterface string
	EgressInterface  string
	Metadata         PacketMetadata
}

type PacketMetadata struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string
	SrcPort  int
	DstPort  int
	Length   int
}

type IPv4Header struct {
	Version     int
	IHL         int
	TotalLength int
	Protocol    uint8
	SrcIP       net.IP
	DstIP       net.IP
}

type IPv6Header struct {
	Version       int
	PayloadLength int
	NextHeader    uint8
	HopLimit      uint8
	SrcIP         net.IP
	DstIP         net.IP
}

func ParseIPv4Header(data []byte) (*IPv4Header, error) {
	if len(data) < 20 {
		return nil, ErrPacketTooShort
	}

	versionIHL := data[0]
	version := int(versionIHL >> 4)
	ihl := int(versionIHL&0x0F) * 4
	if len(data) < ihl {
		return nil, ErrPacketTooShort
	}

	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	proto := data[9]
	src := net.IPv4(data[12], data[13], data[14], data[15])
	dst := net.IPv4(data[16], data[17], data[18], data[19])

	return &IPv4Header{
		Version:     version,
		IHL:         ihl,
		TotalLength: totalLength,
		Protocol:    proto,
		SrcIP:       src,
		DstIP:       dst,
	}, nil
}

func ParseIPv6Header(data []byte) (*IPv6Header, error) {
	if len(data) < 40 {
		return nil, ErrPacketTooShort
	}
	version := int(data[0] >> 4)
	payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	nextHeader := data[6]
	hopLimit := data[7]

	src := net.IP(append([]byte(nil), data[8:24]...))
	dst := net.IP(append([]byte(nil), data[24:40]...))

	return &IPv6Header{
		Version:       version,
		PayloadLength: payloadLength,
		NextHeader:    nextHeader,
		HopLimit:      hopLimit,
		SrcIP:         src,
		DstIP:         dst,
	}, nil
}

func ParseIPv4Metadata(data []byte) (PacketMetadata, error) {
	h, err := ParseIPv4Header(data)
	if err != nil {
		return PacketMetadata{}, err
	}

	meta := PacketMetadata{
		SrcIP:  h.SrcIP,
		DstIP:  h.DstIP,
		Length: h.TotalLength,
	}

	switch h.Protocol {
	case 6:
		meta.Protocol = "TCP"
	case 17:
		meta.Protocol = "UDP"
	case 1:
		meta.Protocol = "ICMP"
	default:
		meta.Protocol = "OTHER"
	}

	if meta.Protocol == "TCP" || meta.Protocol == "UDP" {
		if len(data) < h.IHL+4 {
			return PacketMetadata{}, ErrPacketTooShort
		}
		meta.SrcPort = int(binary.BigEndian.Uint16(data[h.IHL : h.IHL+2]))
		meta.DstPort = int(binary.BigEndian.Uint16(data[h.IHL+2 : h.IHL+4]))
	}

	return meta, nil
}

func ParseIPv6Metadata(data []byte) (PacketMetadata, error) {
	h, err := ParseIPv6Header(data)
	if err != nil {
		return PacketMetadata{}, err
	}

	meta := PacketMetadata{
		SrcIP:  h.SrcIP,
		DstIP:  h.DstIP,
		Length: h.PayloadLength + 40,
	}

	switch h.NextHeader {
	case 6:
		meta.Protocol = "TCP"
	case 17:
		meta.Protocol = "UDP"
	case 58:
		meta.Protocol = "ICMPv6"
	default:
		meta.Protocol = "OTHER"
	}

	if meta.Protocol == "TCP" || meta.Protocol == "UDP" {
		if len(data) < 40+4 {
			return PacketMetadata{}, ErrPacketTooShort
		}
		meta.SrcPort = int(binary.BigEndian.Uint16(data[40:42]))
		meta.DstPort = int(binary.BigEndian.Uint16(data[42:44]))
	}

	return meta, nil
}

func ParseIPMetadata(data []byte) (PacketMetadata, error) {
	if len(data) == 0 {
		return PacketMetadata{}, ErrPacketTooShort
	}
	version := data[0] >> 4
	switch version {
	case 4:
		return ParseIPv4Metadata(data)
	case 6:
		return ParseIPv6Metadata(data)
	default:
		return PacketMetadata{}, ErrPacketTooShort
	}
}

func Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
