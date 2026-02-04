package firewall

import (
	"net"
	"strings"

	"router-go/pkg/network"
)

type Action string

const (
	ActionAccept Action = "ACCEPT"
	ActionDrop   Action = "DROP"
	ActionReject Action = "REJECT"
)

type Rule struct {
	Chain        string
	Action       Action
	Protocol     string
	SrcNet       *net.IPNet
	DstNet       *net.IPNet
	SrcPort      int
	DstPort      int
	InInterface  string
	OutInterface string
}

type Engine struct {
	rules           []Rule
	defaultPolicies map[string]Action
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{
		rules:           rules,
		defaultPolicies: map[string]Action{},
	}
}

func NewEngineWithDefaults(rules []Rule, defaults map[string]Action) *Engine {
	policies := make(map[string]Action, len(defaults))
	for k, v := range defaults {
		policies[strings.ToUpper(k)] = v
	}
	return &Engine{
		rules:           rules,
		defaultPolicies: policies,
	}
}

func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

func (e *Engine) SetDefaultPolicy(chain string, action Action) {
	if e.defaultPolicies == nil {
		e.defaultPolicies = map[string]Action{}
	}
	e.defaultPolicies[strings.ToUpper(chain)] = action
}

func (e *Engine) Evaluate(chain string, pkt network.Packet) Action {
	for _, rule := range e.rules {
		if rule.Chain != "" && !strings.EqualFold(rule.Chain, chain) {
			continue
		}
		if rule.Protocol != "" && !strings.EqualFold(rule.Protocol, pkt.Metadata.Protocol) {
			continue
		}
		if rule.SrcNet != nil && pkt.Metadata.SrcIP != nil && !rule.SrcNet.Contains(pkt.Metadata.SrcIP) {
			continue
		}
		if rule.DstNet != nil && pkt.Metadata.DstIP != nil && !rule.DstNet.Contains(pkt.Metadata.DstIP) {
			continue
		}
		if rule.SrcPort != 0 && rule.SrcPort != pkt.Metadata.SrcPort {
			continue
		}
		if rule.DstPort != 0 && rule.DstPort != pkt.Metadata.DstPort {
			continue
		}
		if rule.InInterface != "" && rule.InInterface != pkt.IngressInterface {
			continue
		}
		if rule.OutInterface != "" && rule.OutInterface != pkt.EgressInterface {
			continue
		}
		return rule.Action
	}
	if e.defaultPolicies != nil {
		if action, ok := e.defaultPolicies[strings.ToUpper(chain)]; ok {
			return action
		}
	}
	return ActionDrop
}
