package ids

import (
	"bytes"
	"net"
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
	Window          time.Duration
	RateThreshold   int
	PortScanThreshold int
	BehaviorAction  Action
	AlertLimit      int
}

type Engine struct {
	mu      sync.Mutex
	rules   []Rule
	alerts  []Alert
	stats   map[string]*ipStats
	cfg     Config
	nowFunc func() time.Time
}

type ipStats struct {
	windowStart time.Time
	count       int
	ports       map[int]struct{}
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
	e.rules = append(e.rules, rule)
}

func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, 0, len(e.rules))
	out = append(out, e.rules...)
	return out
}

func (e *Engine) Alerts() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Alert, 0, len(e.alerts))
	out = append(out, e.alerts...)
	return out
}

func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = nil
	e.stats = map[string]*ipStats{}
}

func (e *Engine) Detect(pkt network.Packet) Result {
	e.mu.Lock()
	defer e.mu.Unlock()

	srcIP := pkt.Metadata.SrcIP
	if srcIP == nil {
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
	for _, rule := range e.rules {
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
		if rule.PayloadContains != "" && !bytes.Contains(pkt.Data, []byte(rule.PayloadContains)) {
			continue
		}

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

func (e *Engine) matchBehavior(pkt network.Packet) (Result, bool) {
	now := e.nowFunc()
	key := pkt.Metadata.SrcIP.String()
	st, ok := e.stats[key]
	if !ok {
		st = &ipStats{
			windowStart: now,
			ports:       map[int]struct{}{},
		}
		e.stats[key] = st
	}

	if now.Sub(st.windowStart) > e.cfg.Window {
		st.windowStart = now
		st.count = 0
		st.ports = map[int]struct{}{}
	}

	st.count++
	if pkt.Metadata.DstPort != 0 {
		st.ports[pkt.Metadata.DstPort] = struct{}{}
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

	return Result{}, false
}

func (e *Engine) addAlert(alert Alert) Alert {
	if len(e.alerts) >= e.cfg.AlertLimit {
		e.alerts = e.alerts[1:]
	}
	e.alerts = append(e.alerts, alert)
	return alert
}
