package ha

import "router-go/pkg/routing"

type Role string

const (
	RoleActive  Role = "active"
	RoleStandby Role = "standby"
)

type PeerStatus struct {
	NodeID   string `json:"node_id"`
	Priority int    `json:"priority"`
	LastSeen int64  `json:"last_seen"`
}

type State struct {
	FirewallDefaults map[string]string `json:"firewall_defaults"`
	FirewallRules    []FirewallRule    `json:"firewall_rules"`
	NATRules         []NATRule         `json:"nat_rules"`
	QoSClasses       []QoSClass        `json:"qos_classes"`
	Routes           []Route           `json:"routes"`
}

type FirewallRule struct {
	Chain        string `json:"chain"`
	Action       string `json:"action"`
	Protocol     string `json:"protocol"`
	SrcCIDR      string `json:"src_cidr,omitempty"`
	DstCIDR      string `json:"dst_cidr,omitempty"`
	SrcPort      int    `json:"src_port,omitempty"`
	DstPort      int    `json:"dst_port,omitempty"`
	InInterface  string `json:"in_interface,omitempty"`
	OutInterface string `json:"out_interface,omitempty"`
}

type NATRule struct {
	Type    string `json:"type"`
	SrcCIDR string `json:"src_cidr,omitempty"`
	DstCIDR string `json:"dst_cidr,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	ToIP    string `json:"to_ip,omitempty"`
	ToPort  int    `json:"to_port,omitempty"`
}

type QoSClass struct {
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	SrcPort       int    `json:"src_port,omitempty"`
	DstPort       int    `json:"dst_port,omitempty"`
	RateLimitKbps int    `json:"rate_limit_kbps"`
	Priority      int    `json:"priority"`
	MaxQueue      int    `json:"max_queue,omitempty"`
	DropPolicy    string `json:"drop_policy,omitempty"`
}

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

func RouteFrom(r routing.Route) Route {
	return Route{
		Destination: r.Destination.String(),
		Gateway:     r.Gateway.String(),
		Interface:   r.Interface,
		Metric:      r.Metric,
	}
}
