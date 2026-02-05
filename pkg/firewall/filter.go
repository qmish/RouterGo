package firewall

import (
	"net"
	"strings"
	"sync"

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
	hits            []uint64
	mu              sync.Mutex
	chainHits       map[string]uint64
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{
		rules:           rules,
		defaultPolicies: map[string]Action{},
		hits:            make([]uint64, len(rules)),
		chainHits:       map[string]uint64{},
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
		hits:            make([]uint64, len(rules)),
		chainHits:       map[string]uint64{},
	}
}

func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	e.hits = append(e.hits, 0)
}

func (e *Engine) SetDefaultPolicy(chain string, action Action) {
	if e.defaultPolicies == nil {
		e.defaultPolicies = map[string]Action{}
	}
	e.defaultPolicies[strings.ToUpper(chain)] = action
}

func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, 0, len(e.rules))
	out = append(out, e.rules...)
	return out
}

func (e *Engine) DefaultPolicies() map[string]Action {
	out := make(map[string]Action, len(e.defaultPolicies))
	for k, v := range e.defaultPolicies {
		out[k] = v
	}
	return out
}

type RuleStat struct {
	Rule Rule
	Hits uint64
}

func (e *Engine) RulesWithStats() []RuleStat {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleStat, 0, len(e.rules))
	for i, rule := range e.rules {
		out = append(out, RuleStat{
			Rule: rule,
			Hits: e.hits[i],
		})
	}
	return out
}

func (e *Engine) ChainHits() map[string]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]uint64, len(e.chainHits))
	for k, v := range e.chainHits {
		out[k] = v
	}
	return out
}

func (e *Engine) ResetStats() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.hits {
		e.hits[i] = 0
	}
	for k := range e.chainHits {
		e.chainHits[k] = 0
	}
}

func (e *Engine) Replace(rules []Rule, defaults map[string]Action) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	e.hits = make([]uint64, len(rules))
	e.defaultPolicies = map[string]Action{}
	for k, v := range defaults {
		e.defaultPolicies[strings.ToUpper(k)] = v
	}
	e.chainHits = map[string]uint64{}
}

func (e *Engine) Evaluate(chain string, pkt network.Packet) Action {
	e.mu.Lock()
	defer e.mu.Unlock()
	if chain != "" {
		e.chainHits[strings.ToUpper(chain)]++
	}
	for i, rule := range e.rules {
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
		e.hits[i]++
		return rule.Action
	}
	if e.defaultPolicies != nil {
		if action, ok := e.defaultPolicies[strings.ToUpper(chain)]; ok {
			return action
		}
	}
	return ActionDrop
}
