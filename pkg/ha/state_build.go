package ha

import (
	"net"

	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"
)

func BuildState(fw *firewall.Engine, natTable *nat.Table, qosQueue *qos.QueueManager, routes *routing.Table) State {
	state := State{
		FirewallDefaults: map[string]string{},
	}
	for k, v := range fw.DefaultPolicies() {
		state.FirewallDefaults[k] = string(v)
	}
	for _, rule := range fw.Rules() {
		state.FirewallRules = append(state.FirewallRules, FirewallRule{
			Chain:        rule.Chain,
			Action:       string(rule.Action),
			Protocol:     rule.Protocol,
			SrcCIDR:      cidrFromNet(rule.SrcNet),
			DstCIDR:      cidrFromNet(rule.DstNet),
			SrcPort:      rule.SrcPort,
			DstPort:      rule.DstPort,
			InInterface:  rule.InInterface,
			OutInterface: rule.OutInterface,
		})
	}
	for _, rule := range natTable.Rules() {
		state.NATRules = append(state.NATRules, NATRule{
			Type:    string(rule.Type),
			SrcCIDR: cidrFromNet(rule.SrcNet),
			DstCIDR: cidrFromNet(rule.DstNet),
			SrcPort: rule.SrcPort,
			DstPort: rule.DstPort,
			ToIP:    rule.ToIP.String(),
			ToPort:  rule.ToPort,
		})
	}
	for _, class := range qosQueue.Classes() {
		state.QoSClasses = append(state.QoSClasses, QoSClass{
			Name:          class.Name,
			Protocol:      class.Protocol,
			SrcPort:       class.SrcPort,
			DstPort:       class.DstPort,
			RateLimitKbps: class.RateLimitKbps,
			Priority:      class.Priority,
			MaxQueue:      class.MaxQueue,
			DropPolicy:    class.DropPolicy,
		})
	}
	for _, route := range routes.Routes() {
		state.Routes = append(state.Routes, RouteFrom(route))
	}
	return state
}

func ApplyState(fw *firewall.Engine, natTable *nat.Table, qosQueue *qos.QueueManager, routes *routing.Table, state State) {
	firewallRules := make([]firewall.Rule, 0, len(state.FirewallRules))
	for _, rule := range state.FirewallRules {
		firewallRules = append(firewallRules, firewall.Rule{
			Chain:        rule.Chain,
			Action:       firewall.Action(rule.Action),
			Protocol:     rule.Protocol,
			SrcNet:       parseCIDR(rule.SrcCIDR),
			DstNet:       parseCIDR(rule.DstCIDR),
			SrcPort:      rule.SrcPort,
			DstPort:      rule.DstPort,
			InInterface:  rule.InInterface,
			OutInterface: rule.OutInterface,
		})
	}
	defaults := map[string]firewall.Action{}
	for k, v := range state.FirewallDefaults {
		defaults[k] = firewall.Action(v)
	}
	fw.Replace(firewallRules, defaults)

	natRules := make([]nat.Rule, 0, len(state.NATRules))
	for _, rule := range state.NATRules {
		natRules = append(natRules, nat.Rule{
			Type:    nat.Type(rule.Type),
			SrcNet:  parseCIDR(rule.SrcCIDR),
			DstNet:  parseCIDR(rule.DstCIDR),
			SrcPort: rule.SrcPort,
			DstPort: rule.DstPort,
			ToIP:    net.ParseIP(rule.ToIP),
			ToPort:  rule.ToPort,
		})
	}
	natTable.ReplaceRules(natRules)

	qosClasses := make([]qos.Class, 0, len(state.QoSClasses))
	for _, class := range state.QoSClasses {
		qosClasses = append(qosClasses, qos.Class{
			Name:          class.Name,
			Protocol:      class.Protocol,
			SrcPort:       class.SrcPort,
			DstPort:       class.DstPort,
			RateLimitKbps: class.RateLimitKbps,
			Priority:      class.Priority,
			MaxQueue:      class.MaxQueue,
			DropPolicy:    class.DropPolicy,
		})
	}
	qosQueue.ReplaceClasses(qosClasses)

	routeList := make([]routing.Route, 0, len(state.Routes))
	for _, r := range state.Routes {
		_, dst, err := net.ParseCIDR(r.Destination)
		if err != nil {
			continue
		}
		routeList = append(routeList, routing.Route{
			Destination: *dst,
			Gateway:     net.ParseIP(r.Gateway),
			Interface:   r.Interface,
			Metric:      r.Metric,
		})
	}
	routes.ReplaceRoutes(routeList)
}

func cidrFromNet(netw *net.IPNet) string {
	if netw == nil {
		return ""
	}
	return netw.String()
}

func parseCIDR(value string) *net.IPNet {
	if value == "" {
		return nil
	}
	_, netw, err := net.ParseCIDR(value)
	if err != nil {
		return nil
	}
	return netw
}
