package ids

import (
	"bytes"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"router-go/pkg/network"
)

type Action string

const (
	ActionAlert Action = "ALERT"
	ActionDrop  Action = "DROP"
)

type Rule struct {
	Name            string
	Action          Action
	Protocol        string
	SrcNet          *net.IPNet
	DstNet          *net.IPNet
	SrcPort         int
	DstPort         int
	PayloadContains string
	Priority        int
	Enabled         bool
	protoKey        uint8
	hasProto        bool
}

type Alert struct {
	Type      string
	Severity  string
	Reason    string
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Timestamp time.Time
}

type Config struct {
	Window             time.Duration
	RateThreshold      int
	PortScanThreshold  int
	UniqueDstThreshold int
	BehaviorAction     Action
	AlertLimit         int
	WhitelistSrc       []*net.IPNet
	WhitelistDst       []*net.IPNet
}

type Engine struct {
	mu      sync.Mutex
	rules   []Rule
	alerts  []Alert
	stats   map[string]*ipStats
	ruleHits map[string]uint64
	cfg     Config
	nowFunc func() time.Time
}

type ipStats struct {
	windowStart time.Time
	count       int
	ports       map[int]struct{}
	dsts        map[string]struct{}
}

type Result struct {
	Drop  bool
	Alert *Alert
}

func NewEngine(cfg Config) *Engine {
	if cfg.Window == 0 {
		cfg.Window = 10 * time.Second
	}
	if cfg.RateThreshold == 0 {
		cfg.RateThreshold = 200
	}
	if cfg.PortScanThreshold == 0 {
		cfg.PortScanThreshold = 20
	}
	if cfg.UniqueDstThreshold == 0 {
		cfg.UniqueDstThreshold = 10
	}
	if cfg.BehaviorAction == "" {
		cfg.BehaviorAction = ActionAlert
	}
	if cfg.AlertLimit == 0 {
		cfg.AlertLimit = 1000
	}
	return &Engine{
		rules:   nil,
		alerts:  nil,
		stats:   map[string]*ipStats{},
		ruleHits: map[string]uint64{},
		cfg:     cfg,
		nowFunc: time.Now,
	}
}

func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rule.Action == "" {
		rule.Action = ActionAlert
	}
	e.rules = append(e.rules, normalizeRule(rule))
	e.sortRules()
}

func (e *Engine) UpdateRule(name string, rule Rule) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.rules {
		if existing.Name == name {
			if rule.Action == "" {
				rule.Action = ActionAlert
			}
			rule.Name = name
			e.rules[i] = normalizeRule(rule)
			e.sortRules()
			return true
		}
	}
	return false
}

func (e *Engine) DeleteRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, rule := range e.rules {
		if rule.Name == name {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			delete(e.ruleHits, name)
			return true
		}
	}
	return false
}

func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, 0, len(e.rules))
	out = append(out, e.rules...)
	return out
}

func (e *Engine) GetRule(name string) (Rule, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rule := range e.rules {
		if rule.Name == name {
			return rule, true
		}
	}
	return Rule{}, false
}

func (e *Engine) Alerts() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Alert, 0, len(e.alerts))
	out = append(out, e.alerts...)
	return out
}

type RuleWithStats struct {
	Rule Rule
	Hits uint64
}

func (e *Engine) RulesWithStats() []RuleWithStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleWithStats, 0, len(e.rules))
	for _, rule := range e.rules {
		out = append(out, RuleWithStats{
			Rule: rule,
			Hits: e.ruleHits[rule.Name],
		})
	}
	return out
}

func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = nil
	e.stats = map[string]*ipStats{}
	e.ruleHits = map[string]uint64{}
}

func (e *Engine) Detect(pkt network.Packet) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	srcIP := pkt.Metadata.SrcIP
	if srcIP == nil {
		return Result{}
	}
	if e.isWhitelisted(pkt) {
		return Result{}
	}

	if res, ok := e.matchSignature(pkt); ok {
		return res
	}

	if res, ok := e.matchBehavior(pkt); ok {
		return res
	}

	return Result{}
}

func (e *Engine) matchSignature(pkt network.Packet) (Result, bool) {
	packetProto := packetProtoKey(pkt.Metadata)
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.hasProto && rule.protoKey != packetProto {
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
		if rule.PayloadContains != "" && !bytes.Contains(pkt.Data, []byte(rule.PayloadContains)) {
			continue
		}

		e.ruleHits[rule.Name]++
		alert := e.addAlert(Alert{
			Type:      "SIGNATURE",
			Severity:  "high",
			Reason:    rule.Name,
			SrcIP:     pkt.Metadata.SrcIP.String(),
			DstIP:     pkt.Metadata.DstIP.String(),
			SrcPort:   pkt.Metadata.SrcPort,
			DstPort:   pkt.Metadata.DstPort,
			Protocol:  pkt.Metadata.Protocol,
			Timestamp: e.nowFunc(),
		})

		return Result{
			Drop:  rule.Action == ActionDrop,
			Alert: &alert,
		}, true
	}
	return Result{}, false
}

func normalizeRule(rule Rule) Rule {
	rule.protoKey = protoToKey(rule.Protocol)
	rule.hasProto = rule.Protocol != ""
	return rule
}

func protoToKey(proto string) uint8 {
	switch {
	case strings.EqualFold(proto, "TCP"):
		return 6
	case strings.EqualFold(proto, "UDP"):
		return 17
	case strings.EqualFold(proto, "ICMP"):
		return 1
	case strings.EqualFold(proto, "ICMPv6"):
		return 58
	default:
		return 0
	}
}

func packetProtoKey(meta network.PacketMetadata) uint8 {
	if meta.ProtocolNum != 0 {
		return meta.ProtocolNum
	}
	return protoToKey(meta.Protocol)
}

func (e *Engine) matchBehavior(pkt network.Packet) (Result, bool) {
	now := e.nowFunc()
	key := pkt.Metadata.SrcIP.String()
	st, ok := e.stats[key]
	if !ok {
		st = &ipStats{
			windowStart: now,
			ports:       map[int]struct{}{},
			dsts:        map[string]struct{}{},
		}
		e.stats[key] = st
	}

	if now.Sub(st.windowStart) > e.cfg.Window {
		st.windowStart = now
		st.count = 0
		st.ports = map[int]struct{}{}
		st.dsts = map[string]struct{}{}
	}

	st.count++
	if pkt.Metadata.DstPort != 0 {
		st.ports[pkt.Metadata.DstPort] = struct{}{}
	}
	if pkt.Metadata.DstIP != nil {
		st.dsts[pkt.Metadata.DstIP.String()] = struct{}{}
	}

	if st.count >= e.cfg.RateThreshold {
		alert := e.addAlert(Alert{
			Type:      "RATE_SPIKE",
			Severity:  "high",
			Reason:    "rate_threshold",
			SrcIP:     pkt.Metadata.SrcIP.String(),
			DstIP:     pkt.Metadata.DstIP.String(),
			SrcPort:   pkt.Metadata.SrcPort,
			DstPort:   pkt.Metadata.DstPort,
			Protocol:  pkt.Metadata.Protocol,
			Timestamp: now,
		})
		return Result{Drop: e.cfg.BehaviorAction == ActionDrop, Alert: &alert}, true
	}

	if len(st.ports) >= e.cfg.PortScanThreshold {
		alert := e.addAlert(Alert{
			Type:      "PORT_SCAN",
			Severity:  "medium",
			Reason:    "port_scan",
			SrcIP:     pkt.Metadata.SrcIP.String(),
			DstIP:     pkt.Metadata.DstIP.String(),
			SrcPort:   pkt.Metadata.SrcPort,
			DstPort:   pkt.Metadata.DstPort,
			Protocol:  pkt.Metadata.Protocol,
			Timestamp: now,
		})
		return Result{Drop: e.cfg.BehaviorAction == ActionDrop, Alert: &alert}, true
	}

	if e.cfg.UniqueDstThreshold > 0 && len(st.dsts) >= e.cfg.UniqueDstThreshold {
		alert := e.addAlert(Alert{
			Type:      "DST_SWEEP",
			Severity:  "medium",
			Reason:    "unique_dst_threshold",
			SrcIP:     pkt.Metadata.SrcIP.String(),
			DstIP:     pkt.Metadata.DstIP.String(),
			SrcPort:   pkt.Metadata.SrcPort,
			DstPort:   pkt.Metadata.DstPort,
			Protocol:  pkt.Metadata.Protocol,
			Timestamp: now,
		})
		return Result{Drop: e.cfg.BehaviorAction == ActionDrop, Alert: &alert}, true
	}

	return Result{}, false
}

func (e *Engine) addAlert(alert Alert) Alert {
	if len(e.alerts) >= e.cfg.AlertLimit {
		e.alerts = e.alerts[1:]
	}
	e.alerts = append(e.alerts, alert)
	return alert
}

func (e *Engine) isWhitelisted(pkt network.Packet) bool {
	for _, netw := range e.cfg.WhitelistSrc {
		if netw != nil && pkt.Metadata.SrcIP != nil && netw.Contains(pkt.Metadata.SrcIP) {
			return true
		}
	}
	for _, netw := range e.cfg.WhitelistDst {
		if netw != nil && pkt.Metadata.DstIP != nil && netw.Contains(pkt.Metadata.DstIP) {
			return true
		}
	}
	return false
}

func (e *Engine) sortRules() {
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
}
