package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-go/internal/config"
	"router-go/internal/logger"
	"router-go/internal/metrics"
	"router-go/internal/observability"
	"router-go/internal/presets"
	"router-go/pkg/enrich"
	"router-go/pkg/firewall"
	"router-go/pkg/flow"
	"router-go/pkg/ha"
	"router-go/pkg/ids"
	"router-go/pkg/nat"
	"router-go/pkg/p2p"
	"router-go/pkg/proxy"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"go.yaml.in/yaml/v3"
)

type apiKeyView struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at,omitempty"`
	RotatedAt string   `json:"rotated_at,omitempty"`
	Disabled  bool     `json:"disabled"`
}

type Handlers struct {
	Routes           *routing.Table
	Firewall         *firewall.Engine
	IDS              *ids.Engine
	NAT              *nat.Table
	QoS              *qos.QueueManager
	Flow             *flow.Engine
	P2P              *p2p.Engine
	Proxy            *proxy.Proxy
	Enrich           *enrich.Service
	EnrichTimeout    time.Duration
	HA               *ha.Manager
	Security         *config.SecurityConfig
	Log              *logger.Logger
	ConfigMgr        *config.Manager
	Metrics          *metrics.Metrics
	Observability    *observability.Store
	Alerts           *observability.AlertStore
	Presets          *presets.Store
	vpnMu            sync.Mutex
	vpnPeers         []VPNPeer
	dhcpMu           sync.Mutex
	dhcpPools        []DHCPPool
	dhcpReservations []DHCPReservation
	webhookMu        sync.Mutex
	webhooks         []WebhookConfig
}

type WebhookConfig struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"created_at,omitempty"`
}

type WebhookEvent struct {
	Event     string         `json:"event"`
	Timestamp string         `json:"timestamp"`
	Actor     string         `json:"actor,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type PolicyBundle struct {
	Routes           []config.RouteConfig          `json:"routes"`
	Firewall         []config.FirewallRuleConfig   `json:"firewall"`
	FirewallDefaults config.FirewallDefaultsConfig `json:"firewall_defaults"`
	NAT              []config.NATRuleConfig        `json:"nat"`
	QoS              []config.QoSClassConfig       `json:"qos"`
	IDS              config.IDSConfig              `json:"ids"`
}

func (h *Handlers) GetRoutes(c *gin.Context) {
	type routeView struct {
		Destination string `json:"destination"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"interface"`
		Metric      int    `json:"metric"`
	}
	routes := h.Routes.Routes()
	out := make([]routeView, 0, len(routes))
	for _, r := range routes {
		out = append(out, routeView{
			Destination: r.Destination.String(),
			Gateway:     r.Gateway.String(),
			Interface:   r.Interface,
			Metric:      r.Metric,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) AddRoute(c *gin.Context) {
	var req struct {
		Destination string `json:"destination"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"interface"`
		Metric      int    `json:"metric"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Destination) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "destination is required"})
		return
	}
	_, dst, err := net.ParseCIDR(req.Destination)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid destination"})
		return
	}
	var gw net.IP
	if strings.TrimSpace(req.Gateway) != "" {
		gw = net.ParseIP(req.Gateway)
		if gw == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid gateway"})
			return
		}
	}
	h.Routes.Add(routing.Route{
		Destination: *dst,
		Gateway:     gw,
		Interface:   req.Interface,
		Metric:      req.Metric,
	})
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) DeleteRoute(c *gin.Context) {
	var req struct {
		Destination string `json:"destination"`
		Gateway     string `json:"gateway"`
		Interface   string `json:"interface"`
		Metric      int    `json:"metric"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Destination) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "destination is required"})
		return
	}
	_, dst, err := net.ParseCIDR(req.Destination)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid destination"})
		return
	}
	var gw net.IP
	if strings.TrimSpace(req.Gateway) != "" {
		gw = net.ParseIP(req.Gateway)
		if gw == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid gateway"})
			return
		}
	}
	ok := h.Routes.RemoveRoute(routing.Route{
		Destination: *dst,
		Gateway:     gw,
		Interface:   req.Interface,
		Metric:      req.Metric,
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateRoute(c *gin.Context) {
	var req struct {
		OldDestination string `json:"old_destination"`
		OldGateway     string `json:"old_gateway"`
		OldInterface   string `json:"old_interface"`
		OldMetric      int    `json:"old_metric"`
		Destination    string `json:"destination"`
		Gateway        string `json:"gateway"`
		Interface      string `json:"interface"`
		Metric         int    `json:"metric"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.OldDestination) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "old_destination is required"})
		return
	}
	if strings.TrimSpace(req.Destination) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "destination is required"})
		return
	}
	_, oldDst, err := net.ParseCIDR(req.OldDestination)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_destination"})
		return
	}
	_, dst, err := net.ParseCIDR(req.Destination)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid destination"})
		return
	}
	var oldGw net.IP
	if strings.TrimSpace(req.OldGateway) != "" {
		oldGw = net.ParseIP(req.OldGateway)
		if oldGw == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_gateway"})
			return
		}
	}
	var gw net.IP
	if strings.TrimSpace(req.Gateway) != "" {
		gw = net.ParseIP(req.Gateway)
		if gw == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid gateway"})
			return
		}
	}
	ok := h.Routes.UpdateRoute(
		routing.Route{
			Destination: *oldDst,
			Gateway:     oldGw,
			Interface:   req.OldInterface,
			Metric:      req.OldMetric,
		},
		routing.Route{
			Destination: *dst,
			Gateway:     gw,
			Interface:   req.Interface,
			Metric:      req.Metric,
		},
	)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetInterfaces(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	cfg := h.ConfigMgr.Current()
	type ifaceView struct {
		Name  string `json:"name"`
		IP    string `json:"ip"`
		State string `json:"state"`
	}
	out := make([]ifaceView, 0, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		out = append(out, ifaceView{
			Name:  iface.Name,
			IP:    iface.IP,
			State: "configured",
		})
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) AddFirewallRule(c *gin.Context) {
	var req struct {
		Chain        string `json:"chain"`
		Action       string `json:"action"`
		Protocol     string `json:"protocol"`
		SrcIP        string `json:"src_ip"`
		DstIP        string `json:"dst_ip"`
		SrcPort      int    `json:"src_port"`
		DstPort      int    `json:"dst_port"`
		InInterface  string `json:"in_interface"`
		OutInterface string `json:"out_interface"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	var srcNet *net.IPNet
	if req.SrcIP != "" {
		_, parsed, err := net.ParseCIDR(req.SrcIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
			return
		}
		srcNet = parsed
	}

	var dstNet *net.IPNet
	if req.DstIP != "" {
		_, parsed, err := net.ParseCIDR(req.DstIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
			return
		}
		dstNet = parsed
	}

	rule := firewall.Rule{
		Chain:        req.Chain,
		Action:       firewall.Action(req.Action),
		Protocol:     req.Protocol,
		SrcNet:       srcNet,
		DstNet:       dstNet,
		SrcPort:      req.SrcPort,
		DstPort:      req.DstPort,
		InInterface:  req.InInterface,
		OutInterface: req.OutInterface,
	}
	h.Firewall.AddRule(rule)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) DeleteFirewallRule(c *gin.Context) {
	var req struct {
		Chain        string `json:"chain"`
		Action       string `json:"action"`
		Protocol     string `json:"protocol"`
		SrcIP        string `json:"src_ip"`
		DstIP        string `json:"dst_ip"`
		SrcPort      int    `json:"src_port"`
		DstPort      int    `json:"dst_port"`
		InInterface  string `json:"in_interface"`
		OutInterface string `json:"out_interface"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	var srcNet *net.IPNet
	if req.SrcIP != "" {
		_, parsed, err := net.ParseCIDR(req.SrcIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
			return
		}
		srcNet = parsed
	}

	var dstNet *net.IPNet
	if req.DstIP != "" {
		_, parsed, err := net.ParseCIDR(req.DstIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
			return
		}
		dstNet = parsed
	}

	ok := h.Firewall.RemoveRule(firewall.Rule{
		Chain:        req.Chain,
		Action:       firewall.Action(req.Action),
		Protocol:     req.Protocol,
		SrcNet:       srcNet,
		DstNet:       dstNet,
		SrcPort:      req.SrcPort,
		DstPort:      req.DstPort,
		InInterface:  req.InInterface,
		OutInterface: req.OutInterface,
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateFirewallRule(c *gin.Context) {
	var req struct {
		OldChain        string `json:"old_chain"`
		OldAction       string `json:"old_action"`
		OldProtocol     string `json:"old_protocol"`
		OldSrcIP        string `json:"old_src_ip"`
		OldDstIP        string `json:"old_dst_ip"`
		OldSrcPort      int    `json:"old_src_port"`
		OldDstPort      int    `json:"old_dst_port"`
		OldInInterface  string `json:"old_in_interface"`
		OldOutInterface string `json:"old_out_interface"`
		Chain           string `json:"chain"`
		Action          string `json:"action"`
		Protocol        string `json:"protocol"`
		SrcIP           string `json:"src_ip"`
		DstIP           string `json:"dst_ip"`
		SrcPort         int    `json:"src_port"`
		DstPort         int    `json:"dst_port"`
		InInterface     string `json:"in_interface"`
		OutInterface    string `json:"out_interface"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	parseNet := func(value string) (*net.IPNet, error) {
		if strings.TrimSpace(value) == "" {
			return nil, nil
		}
		_, parsed, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	}

	oldSrc, err := parseNet(req.OldSrcIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_src_ip"})
		return
	}
	oldDst, err := parseNet(req.OldDstIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_dst_ip"})
		return
	}
	src, err := parseNet(req.SrcIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
		return
	}
	dst, err := parseNet(req.DstIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
		return
	}

	ok := h.Firewall.UpdateRule(
		firewall.Rule{
			Chain:        req.OldChain,
			Action:       firewall.Action(req.OldAction),
			Protocol:     req.OldProtocol,
			SrcNet:       oldSrc,
			DstNet:       oldDst,
			SrcPort:      req.OldSrcPort,
			DstPort:      req.OldDstPort,
			InInterface:  req.OldInInterface,
			OutInterface: req.OldOutInterface,
		},
		firewall.Rule{
			Chain:        req.Chain,
			Action:       firewall.Action(req.Action),
			Protocol:     req.Protocol,
			SrcNet:       src,
			DstNet:       dst,
			SrcPort:      req.SrcPort,
			DstPort:      req.DstPort,
			InInterface:  req.InInterface,
			OutInterface: req.OutInterface,
		},
	)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetStats(c *gin.Context) {
	snapshot := h.Metrics.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":                    "ok",
		"routes_count":              len(h.Routes.Routes()),
		"packets_total":             snapshot.Packets,
		"rx_packets_total":          snapshot.RxPackets,
		"tx_packets_total":          snapshot.TxPackets,
		"ids_alerts_total":          snapshot.IDSAlerts,
		"ids_drops_total":           snapshot.IDSDrops,
		"ids_alerts_by_type":        snapshot.IDSAlertsByType,
		"ids_alerts_by_rule":        snapshot.IDSAlertsByRule,
		"config_apply_total":        snapshot.ConfigApply,
		"config_rollback_total":     snapshot.ConfigRollback,
		"config_apply_failed_total": snapshot.ConfigApplyFailed,
		"p2p_peers_total":           snapshot.P2PPeers,
		"p2p_routes_synced_total":   snapshot.P2PRoutesSynced,
		"proxy_cache_hits_total":    snapshot.ProxyCacheHits,
		"proxy_cache_miss_total":    snapshot.ProxyCacheMiss,
		"proxy_compress_total":      snapshot.ProxyCompress,
		"bytes_total":               snapshot.Bytes,
		"errors_total":              snapshot.Errors,
		"drops_total":               snapshot.Drops,
		"drops_by_reason":           snapshot.DropsByReason,
		"qos_drops_by_class":        snapshot.QoSDropsByClass,
	})
}

func (h *Handlers) GetFirewallRules(c *gin.Context) {
	type ruleView struct {
		Chain        string `json:"chain"`
		Action       string `json:"action"`
		Protocol     string `json:"protocol,omitempty"`
		SrcIP        string `json:"src_ip,omitempty"`
		DstIP        string `json:"dst_ip,omitempty"`
		SrcPort      int    `json:"src_port,omitempty"`
		DstPort      int    `json:"dst_port,omitempty"`
		InInterface  string `json:"in_interface,omitempty"`
		OutInterface string `json:"out_interface,omitempty"`
		Hits         uint64 `json:"hits"`
	}
	stats := h.Firewall.RulesWithStats()
	out := make([]ruleView, 0, len(stats))
	for _, stat := range stats {
		r := stat.Rule
		view := ruleView{
			Chain:        r.Chain,
			Action:       string(r.Action),
			Protocol:     r.Protocol,
			SrcPort:      r.SrcPort,
			DstPort:      r.DstPort,
			InInterface:  r.InInterface,
			OutInterface: r.OutInterface,
			Hits:         stat.Hits,
		}
		if r.SrcNet != nil {
			view.SrcIP = r.SrcNet.String()
		}
		if r.DstNet != nil {
			view.DstIP = r.DstNet.String()
		}
		out = append(out, view)
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetFirewallDefaults(c *gin.Context) {
	defaults := h.Firewall.DefaultPolicies()
	out := map[string]string{}
	for k, v := range defaults {
		out[k] = string(v)
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetFirewallStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"chain_hits": h.Firewall.ChainHits(),
	})
}

func (h *Handlers) ResetFirewallStats(c *gin.Context) {
	h.Firewall.ResetStats()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) SetFirewallDefault(c *gin.Context) {
	var req struct {
		Chain  string `json:"chain"`
		Action string `json:"action"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	chain := strings.ToUpper(strings.TrimSpace(req.Chain))
	action := strings.ToUpper(strings.TrimSpace(req.Action))

	if chain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "chain is required"})
		return
	}
	switch action {
	case string(firewall.ActionAccept), string(firewall.ActionDrop), string(firewall.ActionReject):
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action"})
		return
	}

	h.Firewall.SetDefaultPolicy(chain, firewall.Action(action))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetIDSRules(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	type ruleView struct {
		Name            string `json:"name"`
		Action          string `json:"action"`
		Protocol        string `json:"protocol,omitempty"`
		SrcCIDR         string `json:"src_cidr,omitempty"`
		DstCIDR         string `json:"dst_cidr,omitempty"`
		SrcPort         int    `json:"src_port,omitempty"`
		DstPort         int    `json:"dst_port,omitempty"`
		PayloadContains string `json:"payload_contains,omitempty"`
		Priority        int    `json:"priority"`
		Enabled         bool   `json:"enabled"`
		Hits            uint64 `json:"hits"`
	}
	rules := h.IDS.RulesWithStats()
	out := make([]ruleView, 0, len(rules))
	for _, entry := range rules {
		r := entry.Rule
		view := ruleView{
			Name:            r.Name,
			Action:          string(r.Action),
			Protocol:        r.Protocol,
			SrcPort:         r.SrcPort,
			DstPort:         r.DstPort,
			PayloadContains: r.PayloadContains,
			Priority:        r.Priority,
			Enabled:         r.Enabled,
			Hits:            entry.Hits,
		}
		if r.SrcNet != nil {
			view.SrcCIDR = r.SrcNet.String()
		}
		if r.DstNet != nil {
			view.DstCIDR = r.DstNet.String()
		}
		out = append(out, view)
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) AddIDSRule(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	var req struct {
		Name            string `json:"name"`
		Action          string `json:"action"`
		Protocol        string `json:"protocol"`
		SrcCIDR         string `json:"src_cidr"`
		DstCIDR         string `json:"dst_cidr"`
		SrcPort         int    `json:"src_port"`
		DstPort         int    `json:"dst_port"`
		PayloadContains string `json:"payload_contains"`
		Priority        int    `json:"priority"`
		Enabled         *bool  `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	var srcNet *net.IPNet
	if req.SrcCIDR != "" {
		_, parsed, err := net.ParseCIDR(req.SrcCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_cidr"})
			return
		}
		srcNet = parsed
	}
	var dstNet *net.IPNet
	if req.DstCIDR != "" {
		_, parsed, err := net.ParseCIDR(req.DstCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_cidr"})
			return
		}
		dstNet = parsed
	}

	rule := ids.Rule{
		Name:            req.Name,
		Action:          ids.Action(strings.ToUpper(req.Action)),
		Protocol:        req.Protocol,
		SrcNet:          srcNet,
		DstNet:          dstNet,
		SrcPort:         req.SrcPort,
		DstPort:         req.DstPort,
		PayloadContains: req.PayloadContains,
		Priority:        req.Priority,
		Enabled:         true,
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	h.IDS.AddRule(rule)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateIDSRule(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	existing, ok := h.IDS.GetRule(name)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	var req struct {
		Action          string `json:"action"`
		Protocol        string `json:"protocol"`
		SrcCIDR         string `json:"src_cidr"`
		DstCIDR         string `json:"dst_cidr"`
		SrcPort         int    `json:"src_port"`
		DstPort         int    `json:"dst_port"`
		PayloadContains string `json:"payload_contains"`
		Priority        int    `json:"priority"`
		Enabled         *bool  `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	var srcNet *net.IPNet
	if req.SrcCIDR != "" {
		_, parsed, err := net.ParseCIDR(req.SrcCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_cidr"})
			return
		}
		srcNet = parsed
	} else {
		srcNet = existing.SrcNet
	}
	var dstNet *net.IPNet
	if req.DstCIDR != "" {
		_, parsed, err := net.ParseCIDR(req.DstCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_cidr"})
			return
		}
		dstNet = parsed
	} else {
		dstNet = existing.DstNet
	}

	action := req.Action
	if action == "" {
		action = string(existing.Action)
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = existing.Protocol
	}
	srcPort := req.SrcPort
	if srcPort == 0 {
		srcPort = existing.SrcPort
	}
	dstPort := req.DstPort
	if dstPort == 0 {
		dstPort = existing.DstPort
	}
	payload := req.PayloadContains
	if payload == "" {
		payload = existing.PayloadContains
	}
	priority := req.Priority
	if priority == 0 {
		priority = existing.Priority
	}

	rule := ids.Rule{
		Name:            name,
		Action:          ids.Action(strings.ToUpper(action)),
		Protocol:        protocol,
		SrcNet:          srcNet,
		DstNet:          dstNet,
		SrcPort:         srcPort,
		DstPort:         dstPort,
		PayloadContains: payload,
		Priority:        priority,
		Enabled:         existing.Enabled,
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if ok := h.IDS.UpdateRule(name, rule); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) DeleteIDSRule(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	name := c.Param("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if ok := h.IDS.DeleteRule(name); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetIDSAlerts(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	alertType := strings.TrimSpace(c.Query("type"))
	srcIP := strings.TrimSpace(c.Query("src_ip"))
	sinceValue := strings.TrimSpace(c.Query("since"))
	var since time.Time
	if sinceValue != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceValue); err == nil {
			since = parsed
		}
	}
	alerts := h.IDS.Alerts()
	filtered := make([]ids.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if alertType != "" && !strings.EqualFold(alert.Type, alertType) {
			continue
		}
		if srcIP != "" && alert.SrcIP != srcIP {
			continue
		}
		if !since.IsZero() && alert.Timestamp.Before(since) {
			continue
		}
		filtered = append(filtered, alert)
	}
	c.JSON(http.StatusOK, filtered)
}

func (h *Handlers) ResetIDS(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	h.IDS.Reset()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetAuthInfo(c *gin.Context) {
	role := c.GetString("role")
	if role == "" {
		role = roleRead
	}
	scopesAny, ok := c.Get("scopes")
	scopes := defaultScopesForRole(role)
	if ok {
		if cast, ok := scopesAny.([]string); ok && len(cast) > 0 {
			scopes = cast
		}
	}
	tokenID := c.GetString("token_id")
	c.JSON(http.StatusOK, gin.H{
		"role":     role,
		"scopes":   scopes,
		"token_id": tokenID,
	})
}

func (h *Handlers) ListWebhooks(c *gin.Context) {
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	out := make([]WebhookConfig, 0, len(h.webhooks))
	out = append(out, h.webhooks...)
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) CreateWebhook(c *gin.Context) {
	var req struct {
		ID      string   `json:"id"`
		URL     string   `json:"url"`
		Events  []string `json:"events"`
		Enabled *bool    `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = "wh_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	}
	if strings.TrimSpace(req.URL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	events := normalizeWebhookEvents(req.Events)
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	for _, wh := range h.webhooks {
		if wh.ID == id {
			c.JSON(http.StatusConflict, gin.H{"error": "webhook id already exists"})
			return
		}
	}
	h.webhooks = append(h.webhooks, WebhookConfig{
		ID:        id,
		URL:       strings.TrimSpace(req.URL),
		Events:    events,
		Enabled:   enabled,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id})
}

func (h *Handlers) DeleteWebhook(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	for i, wh := range h.webhooks {
		if wh.ID != id {
			continue
		}
		h.webhooks = append(h.webhooks[:i], h.webhooks[i+1:]...)
		c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
}

func (h *Handlers) TestWebhook(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	wh, ok := h.webhookByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return
	}
	ev := WebhookEvent{
		Event:     "webhook.test",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     resolveActor(c, ""),
		Details:   map[string]any{"webhook_id": id},
	}
	if err := postWebhook(wh.URL, ev); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id})
}

func (h *Handlers) ExportPolicyBundle(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	cfg := h.ConfigMgr.Current()
	bundle := PolicyBundle{
		Routes:           append([]config.RouteConfig(nil), cfg.Routes...),
		Firewall:         append([]config.FirewallRuleConfig(nil), cfg.Firewall...),
		FirewallDefaults: cfg.FirewallDefaults,
		NAT:              append([]config.NATRuleConfig(nil), cfg.NAT...),
		QoS:              append([]config.QoSClassConfig(nil), cfg.QoS...),
		IDS:              cfg.IDS,
	}
	c.JSON(http.StatusOK, gin.H{
		"version": 1,
		"bundle":  bundle,
	})
}

func (h *Handlers) ImportPolicyBundle(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		Mode   string       `json:"mode"`
		Bundle PolicyBundle `json:"bundle"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "replace"
	}
	if mode != "replace" && mode != "merge" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be replace or merge"})
		return
	}
	cfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	if mode == "replace" {
		cfg.Routes = append([]config.RouteConfig(nil), req.Bundle.Routes...)
		cfg.Firewall = append([]config.FirewallRuleConfig(nil), req.Bundle.Firewall...)
		cfg.FirewallDefaults = req.Bundle.FirewallDefaults
		cfg.NAT = append([]config.NATRuleConfig(nil), req.Bundle.NAT...)
		cfg.QoS = append([]config.QoSClassConfig(nil), req.Bundle.QoS...)
		cfg.IDS = req.Bundle.IDS
	} else {
		cfg.Routes = append(cfg.Routes, req.Bundle.Routes...)
		cfg.Firewall = append(cfg.Firewall, req.Bundle.Firewall...)
		if req.Bundle.FirewallDefaults.Input != "" || req.Bundle.FirewallDefaults.Output != "" || req.Bundle.FirewallDefaults.Forward != "" {
			cfg.FirewallDefaults = req.Bundle.FirewallDefaults
		}
		cfg.NAT = append(cfg.NAT, req.Bundle.NAT...)
		cfg.QoS = append(cfg.QoS, req.Bundle.QoS...)
		if hasIDSOverrides(req.Bundle.IDS) {
			cfg.IDS = req.Bundle.IDS
		}
	}
	if err := h.ConfigMgr.Apply(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	actor := resolveActor(c, "")
	h.emitWebhookEvent("policy.bundle.imported", actor, map[string]any{"mode": mode})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": mode})
}

func (h *Handlers) GetMonitoringSLO(c *gin.Context) {
	if h.Metrics == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "metrics unavailable"})
		return
	}
	snap := h.Metrics.Snapshot()
	totalConfigOps := snap.ConfigApply + snap.ConfigApplyFailed
	applySuccessRate := 1.0
	if totalConfigOps > 0 {
		applySuccessRate = float64(snap.ConfigApply) / float64(totalConfigOps)
	}
	dropRate := 0.0
	errorRate := 0.0
	if snap.Packets > 0 {
		dropRate = float64(snap.Drops) / float64(snap.Packets)
		errorRate = float64(snap.Errors) / float64(snap.Packets)
	}
	c.JSON(http.StatusOK, gin.H{
		"apply_success_rate":  applySuccessRate,
		"drop_rate":           dropRate,
		"error_rate":          errorRate,
		"packets_total":       snap.Packets,
		"config_apply_total":  snap.ConfigApply,
		"config_apply_failed": snap.ConfigApplyFailed,
	})
}

func (h *Handlers) ApplyConfig(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		ConfigYAML string `json:"config_yaml"`
		Actor      string `json:"actor"`
		Reason     string `json:"reason"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.ConfigYAML == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_yaml is required"})
		return
	}

	newCfg, err := config.LoadFromBytes([]byte(req.ConfigYAML))
	if err != nil {
		h.Metrics.IncConfigApplyFailed()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}

	plan, err := h.ConfigMgr.Plan(newCfg)
	if err != nil {
		h.Metrics.IncConfigApplyFailed()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor := resolveActor(c, req.Actor)
	if err := h.ConfigMgr.ApplyWithMeta(newCfg, plan, config.ChangeMeta{
		Actor:  actor,
		Reason: strings.TrimSpace(req.Reason),
	}); err != nil {
		h.Metrics.IncConfigApplyFailed()
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.Metrics.IncConfigApply()
	h.emitWebhookEvent("config.applied", actor, map[string]any{
		"planned_snapshot_id": plan.PlannedSnapshotID,
		"changed_sections":    plan.ChangedSections,
	})
	c.JSON(http.StatusOK, gin.H{
		"status":              "ok",
		"actor":               actor,
		"planned_snapshot_id": plan.PlannedSnapshotID,
		"changed_sections":    plan.ChangedSections,
	})
}

func (h *Handlers) PlanConfig(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		ConfigYAML string `json:"config_yaml"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.ConfigYAML == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_yaml is required"})
		return
	}

	newCfg, err := config.LoadFromBytes([]byte(req.ConfigYAML))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}

	plan, err := h.ConfigMgr.Plan(newCfg)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

func (h *Handlers) RollbackConfig(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		Actor  string `json:"actor"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if err := h.ConfigMgr.RollbackWithMeta(config.ChangeMeta{
		Actor:  resolveActor(c, req.Actor),
		Reason: strings.TrimSpace(req.Reason),
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no snapshots"})
		return
	}
	h.Metrics.IncConfigRollback()
	h.emitWebhookEvent("config.rollback", resolveActor(c, req.Actor), map[string]any{
		"reason": strings.TrimSpace(req.Reason),
	})
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetConfigSnapshots(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	c.JSON(http.StatusOK, h.ConfigMgr.Snapshots())
}

func (h *Handlers) GetConfigHistory(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"revision": h.ConfigMgr.Revision(),
		"history":  h.ConfigMgr.History(),
	})
}

func (h *Handlers) GetConfigHistoryExport(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	payload := gin.H{
		"revision": h.ConfigMgr.Revision(),
		"history":  h.ConfigMgr.History(),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=config-history.json")
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

func (h *Handlers) GetConfigBackup(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	data, err := h.ConfigMgr.BackupJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "backup failed"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=config-backup.json")
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

func (h *Handlers) ListAPIKeys(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	tokens := h.ConfigMgr.Current().Security.Tokens
	out := make([]apiKeyView, 0, len(tokens))
	for _, token := range tokens {
		if strings.TrimSpace(token.ID) == "" {
			continue
		}
		out = append(out, apiKeyView{
			ID:        token.ID,
			Role:      token.Role,
			Scopes:    normalizeScopes(token.Scopes, token.Role),
			CreatedAt: token.CreatedAt,
			RotatedAt: token.RotatedAt,
			Disabled:  token.Disabled,
		})
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) CreateAPIKey(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		Role   string   `json:"role"`
		Scopes []string `json:"scopes"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = roleOps
	}
	if role != roleAdmin && role != roleOps && role != roleRead {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	cfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	keyID := newKeyID()
	plain, hash := generateAPIKey()
	now := time.Now().UTC().Format(time.RFC3339)
	cfg.Security.Tokens = append(cfg.Security.Tokens, config.TokenConfig{
		ID:        keyID,
		Role:      role,
		Scopes:    normalizeScopes(req.Scopes, role),
		Value:     hash,
		CreatedAt: now,
		RotatedAt: now,
		Disabled:  false,
	})
	if err := h.ConfigMgr.Apply(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":      keyID,
		"role":    role,
		"scopes":  normalizeScopes(req.Scopes, role),
		"api_key": plain,
	})
	h.emitWebhookEvent("security.key.created", resolveActor(c, ""), map[string]any{
		"id":     keyID,
		"role":   role,
		"scopes": normalizeScopes(req.Scopes, role),
	})
}

func (h *Handlers) RotateAPIKey(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	keyID := strings.TrimSpace(c.Param("id"))
	if keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	cfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	plain, hash := generateAPIKey()
	found := false
	for i := range cfg.Security.Tokens {
		token := &cfg.Security.Tokens[i]
		if token.ID != keyID {
			continue
		}
		token.Value = hash
		token.Disabled = false
		token.RotatedAt = time.Now().UTC().Format(time.RFC3339)
		found = true
		break
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}
	if err := h.ConfigMgr.Apply(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":      keyID,
		"api_key": plain,
	})
	h.emitWebhookEvent("security.key.rotated", resolveActor(c, ""), map[string]any{"id": keyID})
}

func (h *Handlers) RevokeAPIKey(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	keyID := strings.TrimSpace(c.Param("id"))
	if keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	cfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	found := false
	for i := range cfg.Security.Tokens {
		token := &cfg.Security.Tokens[i]
		if token.ID != keyID {
			continue
		}
		token.Disabled = true
		token.RotatedAt = time.Now().UTC().Format(time.RFC3339)
		found = true
		break
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}
	if err := h.ConfigMgr.Apply(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	h.emitWebhookEvent("security.key.revoked", resolveActor(c, ""), map[string]any{"id": keyID})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": keyID})
}

func (h *Handlers) RestoreConfig(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		BackupJSON string `json:"backup_json"`
		Actor      string `json:"actor"`
		Reason     string `json:"reason"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.BackupJSON) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup_json is required"})
		return
	}
	actor := resolveActor(c, req.Actor)
	if err := h.ConfigMgr.RestoreFromBackupJSON([]byte(req.BackupJSON), config.ChangeMeta{
		Actor:  actor,
		Reason: strings.TrimSpace(req.Reason),
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"actor":    actor,
		"revision": h.ConfigMgr.Revision(),
	})
	h.emitWebhookEvent("config.restore", actor, map[string]any{"revision": h.ConfigMgr.Revision()})
}

func (h *Handlers) GetConfigDiff(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	fromValue := strings.TrimSpace(c.Query("from"))
	toValue := strings.TrimSpace(c.Query("to"))
	if fromValue == "" || toValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from and to are required"})
		return
	}
	fromRevision, err := strconv.Atoi(fromValue)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from revision"})
		return
	}
	toRevision, err := strconv.Atoi(toValue)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to revision"})
		return
	}
	diff, err := h.ConfigMgr.DiffRevisions(fromRevision, toRevision)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, diff)
}

func (h *Handlers) GetSystemTimeSettings(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	cfg := h.ConfigMgr.Current()
	c.JSON(http.StatusOK, gin.H{
		"timezone":    cfg.System.Timezone,
		"ntp_servers": cfg.System.NTPServers,
	})
}

func (h *Handlers) UpdateSystemTimeSettings(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		Timezone   string   `json:"timezone"`
		NTPServers []string `json:"ntp_servers"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	newCfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	if strings.TrimSpace(req.Timezone) != "" {
		newCfg.System.Timezone = strings.TrimSpace(req.Timezone)
	}
	clean := make([]string, 0, len(req.NTPServers))
	for _, server := range req.NTPServers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		clean = append(clean, server)
	}
	newCfg.System.NTPServers = clean
	if err := h.ConfigMgr.Apply(newCfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetSystemTLSSettings(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	tlsCfg := h.ConfigMgr.Current().Security.TLS
	c.JSON(http.StatusOK, gin.H{
		"enabled":             tlsCfg.Enabled,
		"cert_file":           tlsCfg.CertFile,
		"key_file":            tlsCfg.KeyFile,
		"client_ca_file":      tlsCfg.ClientCAFile,
		"require_client_cert": tlsCfg.RequireClientCert,
	})
}

func (h *Handlers) UpdateSystemTLSSettings(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	var req struct {
		Enabled           bool   `json:"enabled"`
		CertFile          string `json:"cert_file"`
		KeyFile           string `json:"key_file"`
		ClientCAFile      string `json:"client_ca_file"`
		RequireClientCert bool   `json:"require_client_cert"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.Enabled && (strings.TrimSpace(req.CertFile) == "" || strings.TrimSpace(req.KeyFile) == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cert_file and key_file are required"})
		return
	}
	newCfg, err := cloneConfig(h.ConfigMgr.Current())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config clone failed"})
		return
	}
	newCfg.Security.TLS.Enabled = req.Enabled
	newCfg.Security.TLS.CertFile = strings.TrimSpace(req.CertFile)
	newCfg.Security.TLS.KeyFile = strings.TrimSpace(req.KeyFile)
	newCfg.Security.TLS.ClientCAFile = strings.TrimSpace(req.ClientCAFile)
	newCfg.Security.TLS.RequireClientCert = req.RequireClientCert
	if err := h.ConfigMgr.Apply(newCfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "apply failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetConfigExport(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	format := strings.ToLower(strings.TrimSpace(c.Query("format")))
	cfg := h.ConfigMgr.Current()
	switch format {
	case "", "json":
		c.JSON(http.StatusOK, cfg)
		return
	case "yaml", "yml":
		data, err := yaml.Marshal(cfg)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
			return
		}
		c.Data(http.StatusOK, "text/yaml; charset=utf-8", data)
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format"})
		return
	}
}

func (h *Handlers) GetMonitoringSummary(c *gin.Context) {
	var chainHits map[string]uint64
	if h.Firewall != nil {
		chainHits = h.Firewall.ChainHits()
	} else {
		chainHits = map[string]uint64{}
	}
	natRules := 0
	if h.NAT != nil {
		natRules = len(h.NAT.Rules())
	}
	qosClasses := 0
	if h.QoS != nil {
		qosClasses = len(h.QoS.Classes())
	}
	drops := uint64(0)
	errors := uint64(0)
	if h.Metrics != nil {
		snap := h.Metrics.Snapshot()
		drops = snap.Drops
		errors = snap.Errors
	}
	c.JSON(http.StatusOK, gin.H{
		"firewall_chain_hits": chainHits,
		"nat_rules":           natRules,
		"qos_classes":         qosClasses,
		"drops":               drops,
		"errors":              errors,
	})
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func resolveActor(c *gin.Context, requested string) string {
	requested = strings.TrimSpace(requested)
	if requested != "" {
		return requested
	}
	headerActor := strings.TrimSpace(c.GetHeader("X-Actor"))
	if headerActor != "" {
		return headerActor
	}
	if role, ok := c.Get("role"); ok {
		if roleStr, cast := role.(string); cast {
			return "role:" + roleStr
		}
	}
	return "system"
}

func normalizeWebhookEvents(events []string) []string {
	if len(events) == 0 {
		return []string{"*"}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(events))
	for _, ev := range events {
		ev = strings.ToLower(strings.TrimSpace(ev))
		if ev == "" {
			continue
		}
		if _, ok := seen[ev]; ok {
			continue
		}
		seen[ev] = struct{}{}
		out = append(out, ev)
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

func webhookMatchesEvent(wh WebhookConfig, event string) bool {
	if len(wh.Events) == 0 {
		return true
	}
	event = strings.ToLower(strings.TrimSpace(event))
	for _, configured := range wh.Events {
		configured = strings.ToLower(strings.TrimSpace(configured))
		if configured == "*" || configured == event {
			return true
		}
	}
	return false
}

func (h *Handlers) webhookByID(id string) (WebhookConfig, bool) {
	h.webhookMu.Lock()
	defer h.webhookMu.Unlock()
	for _, wh := range h.webhooks {
		if wh.ID == id {
			return wh, true
		}
	}
	return WebhookConfig{}, false
}

func (h *Handlers) emitWebhookEvent(event string, actor string, details map[string]any) {
	h.webhookMu.Lock()
	targets := make([]WebhookConfig, 0, len(h.webhooks))
	targets = append(targets, h.webhooks...)
	h.webhookMu.Unlock()
	if len(targets) == 0 {
		return
	}
	payload := WebhookEvent{
		Event:     strings.ToLower(strings.TrimSpace(event)),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     strings.TrimSpace(actor),
		Details:   details,
	}
	for _, wh := range targets {
		if !wh.Enabled || strings.TrimSpace(wh.URL) == "" || !webhookMatchesEvent(wh, payload.Event) {
			continue
		}
		target := wh
		go func() {
			if err := postWebhook(target.URL, payload); err != nil && h.Log != nil {
				h.Log.Warn("webhook dispatch failed", map[string]any{
					"id":    target.ID,
					"event": payload.Event,
					"error": err.Error(),
				})
			}
		}()
	}
}

func postWebhook(url string, payload WebhookEvent) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func hasIDSOverrides(cfg config.IDSConfig) bool {
	return cfg.Enabled ||
		cfg.WindowSeconds != 0 ||
		cfg.RateThreshold != 0 ||
		cfg.PortScanThreshold != 0 ||
		cfg.UniqueDstThreshold != 0 ||
		strings.TrimSpace(cfg.BehaviorAction) != "" ||
		cfg.AlertLimit != 0 ||
		len(cfg.WhitelistSrc) > 0 ||
		len(cfg.WhitelistDst) > 0
}

func generateAPIKey() (string, string) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		now := []byte(time.Now().UTC().Format(time.RFC3339Nano))
		sum := sha256.Sum256(now)
		plain := "rg_" + hex.EncodeToString(sum[:16])
		hash := sha256.Sum256([]byte(plain))
		return plain, "sha256:" + hex.EncodeToString(hash[:])
	}
	plain := "rg_" + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, "sha256:" + hex.EncodeToString(sum[:])
}

func newKeyID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "key_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	}
	return "key_" + hex.EncodeToString(buf)
}

func (h *Handlers) GetDashboardTopBandwidth(c *gin.Context) {
	if h.Flow == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "flow tracking disabled"})
		return
	}
	limit := 5
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	c.JSON(http.StatusOK, h.Flow.TopBandwidth(limit))
}

func (h *Handlers) GetDashboardSessionsTree(c *gin.Context) {
	if h.Flow == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "flow tracking disabled"})
		return
	}
	c.JSON(http.StatusOK, h.Flow.SessionsTree())
}

func (h *Handlers) GetDashboardAlerts(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	alertType := strings.TrimSpace(c.Query("type"))
	alerts := h.IDS.Alerts()
	if alertType == "" {
		c.JSON(http.StatusOK, alerts)
		return
	}
	filtered := make([]ids.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if strings.EqualFold(alert.Type, alertType) {
			filtered = append(filtered, alert)
		}
	}
	c.JSON(http.StatusOK, filtered)
}

func (h *Handlers) GetP2PPeers(c *gin.Context) {
	if h.P2P == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "p2p disabled"})
		return
	}
	c.JSON(http.StatusOK, h.P2P.Peers())
}

func (h *Handlers) GetP2PRoutes(c *gin.Context) {
	if h.P2P == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "p2p disabled"})
		return
	}
	c.JSON(http.StatusOK, h.P2P.Routes())
}

func (h *Handlers) ResetP2P(c *gin.Context) {
	if h.P2P == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "p2p disabled"})
		return
	}
	h.P2P.Reset()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetProxyStats(c *gin.Context) {
	if h.Proxy == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy disabled"})
		return
	}
	c.JSON(http.StatusOK, h.Proxy.Stats())
}

func (h *Handlers) ClearProxyCache(c *gin.Context) {
	if h.Proxy == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy disabled"})
		return
	}
	h.Proxy.ClearCache()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetEnrichIP(c *gin.Context) {
	if h.Enrich == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrich disabled"})
		return
	}
	ip := strings.TrimSpace(c.Query("ip"))
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}
	timeout := h.EnrichTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()
	result, err := h.Enrich.Lookup(ctx, ip)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lookup failed"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *Handlers) GetNAT(c *gin.Context) {
	type natView struct {
		Type    string `json:"type"`
		SrcIP   string `json:"src_ip,omitempty"`
		DstIP   string `json:"dst_ip,omitempty"`
		SrcPort int    `json:"src_port,omitempty"`
		DstPort int    `json:"dst_port,omitempty"`
		ToIP    string `json:"to_ip,omitempty"`
		ToPort  int    `json:"to_port,omitempty"`
		Hits    uint64 `json:"hits"`
	}
	stats := h.NAT.RulesWithStats()
	out := make([]natView, 0, len(stats))
	for _, stat := range stats {
		r := stat.Rule
		view := natView{
			Type:    string(r.Type),
			SrcPort: r.SrcPort,
			DstPort: r.DstPort,
			ToPort:  r.ToPort,
			Hits:    stat.Hits,
		}
		if r.SrcNet != nil {
			view.SrcIP = r.SrcNet.String()
		}
		if r.DstNet != nil {
			view.DstIP = r.DstNet.String()
		}
		if r.ToIP != nil {
			view.ToIP = r.ToIP.String()
		}
		out = append(out, view)
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) DeleteNATRule(c *gin.Context) {
	var req struct {
		Type    string `json:"type"`
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dst_ip"`
		SrcPort int    `json:"src_port"`
		DstPort int    `json:"dst_port"`
		ToIP    string `json:"to_ip"`
		ToPort  int    `json:"to_port"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	var srcNet *net.IPNet
	if req.SrcIP != "" {
		_, parsed, err := net.ParseCIDR(req.SrcIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
			return
		}
		srcNet = parsed
	}

	var dstNet *net.IPNet
	if req.DstIP != "" {
		_, parsed, err := net.ParseCIDR(req.DstIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
			return
		}
		dstNet = parsed
	}

	ok := h.NAT.RemoveRule(nat.Rule{
		Type:    nat.Type(req.Type),
		SrcNet:  srcNet,
		DstNet:  dstNet,
		SrcPort: req.SrcPort,
		DstPort: req.DstPort,
		ToIP:    net.ParseIP(req.ToIP),
		ToPort:  req.ToPort,
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateNATRule(c *gin.Context) {
	var req struct {
		OldType    string `json:"old_type"`
		OldSrcIP   string `json:"old_src_ip"`
		OldDstIP   string `json:"old_dst_ip"`
		OldSrcPort int    `json:"old_src_port"`
		OldDstPort int    `json:"old_dst_port"`
		OldToIP    string `json:"old_to_ip"`
		OldToPort  int    `json:"old_to_port"`
		Type       string `json:"type"`
		SrcIP      string `json:"src_ip"`
		DstIP      string `json:"dst_ip"`
		SrcPort    int    `json:"src_port"`
		DstPort    int    `json:"dst_port"`
		ToIP       string `json:"to_ip"`
		ToPort     int    `json:"to_port"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	parseNet := func(value string) (*net.IPNet, error) {
		if strings.TrimSpace(value) == "" {
			return nil, nil
		}
		_, parsed, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		return parsed, nil
	}

	oldSrc, err := parseNet(req.OldSrcIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_src_ip"})
		return
	}
	oldDst, err := parseNet(req.OldDstIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid old_dst_ip"})
		return
	}
	src, err := parseNet(req.SrcIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
		return
	}
	dst, err := parseNet(req.DstIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
		return
	}

	ok := h.NAT.UpdateRule(
		nat.Rule{
			Type:    nat.Type(req.OldType),
			SrcNet:  oldSrc,
			DstNet:  oldDst,
			SrcPort: req.OldSrcPort,
			DstPort: req.OldDstPort,
			ToIP:    net.ParseIP(req.OldToIP),
			ToPort:  req.OldToPort,
		},
		nat.Rule{
			Type:    nat.Type(req.Type),
			SrcNet:  src,
			DstNet:  dst,
			SrcPort: req.SrcPort,
			DstPort: req.DstPort,
			ToIP:    net.ParseIP(req.ToIP),
			ToPort:  req.ToPort,
		},
	)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) ResetNATStats(c *gin.Context) {
	h.NAT.ResetStats()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) AddNATRule(c *gin.Context) {
	var req struct {
		Type    string `json:"type"`
		SrcIP   string `json:"src_ip"`
		DstIP   string `json:"dst_ip"`
		SrcPort int    `json:"src_port"`
		DstPort int    `json:"dst_port"`
		ToIP    string `json:"to_ip"`
		ToPort  int    `json:"to_port"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}

	var srcNet *net.IPNet
	if req.SrcIP != "" {
		_, parsed, err := net.ParseCIDR(req.SrcIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src_ip"})
			return
		}
		srcNet = parsed
	}

	var dstNet *net.IPNet
	if req.DstIP != "" {
		_, parsed, err := net.ParseCIDR(req.DstIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dst_ip"})
			return
		}
		dstNet = parsed
	}

	rule := nat.Rule{
		Type:    nat.Type(req.Type),
		SrcNet:  srcNet,
		DstNet:  dstNet,
		SrcPort: req.SrcPort,
		DstPort: req.DstPort,
		ToIP:    net.ParseIP(req.ToIP),
		ToPort:  req.ToPort,
	}
	h.NAT.AddRule(rule)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetQoS(c *gin.Context) {
	classes := h.QoS.Classes()
	c.JSON(http.StatusOK, classes)
}

func (h *Handlers) DeleteQoSClass(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if !h.QoS.RemoveClass(req.Name) {
		c.JSON(http.StatusNotFound, gin.H{"error": "class not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateQoSClass(c *gin.Context) {
	var req struct {
		OldName       string `json:"old_name"`
		Name          string `json:"name"`
		Protocol      string `json:"protocol"`
		SrcPort       int    `json:"src_port"`
		DstPort       int    `json:"dst_port"`
		RateLimitKbps int    `json:"rate_limit_kbps"`
		Priority      int    `json:"priority"`
		MaxQueue      int    `json:"max_queue"`
		DropPolicy    string `json:"drop_policy"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.OldName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "old_name is required"})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	ok := h.QoS.UpdateClass(req.OldName, qos.Class{
		Name:          req.Name,
		Protocol:      req.Protocol,
		SrcPort:       req.SrcPort,
		DstPort:       req.DstPort,
		RateLimitKbps: req.RateLimitKbps,
		Priority:      req.Priority,
		MaxQueue:      req.MaxQueue,
		DropPolicy:    req.DropPolicy,
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "class not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) AddQoSClass(c *gin.Context) {
	var req struct {
		Name          string `json:"name"`
		Protocol      string `json:"protocol"`
		SrcPort       int    `json:"src_port"`
		DstPort       int    `json:"dst_port"`
		RateLimitKbps int    `json:"rate_limit_kbps"`
		Priority      int    `json:"priority"`
		MaxQueue      int    `json:"max_queue"`
		DropPolicy    string `json:"drop_policy"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	class := qos.Class{
		Name:          req.Name,
		Protocol:      req.Protocol,
		SrcPort:       req.SrcPort,
		DstPort:       req.DstPort,
		RateLimitKbps: req.RateLimitKbps,
		Priority:      req.Priority,
		MaxQueue:      req.MaxQueue,
		DropPolicy:    req.DropPolicy,
	}
	h.QoS.AddClass(class)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
