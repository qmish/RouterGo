package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"router-go/internal/config"
	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/flow"
	"router-go/pkg/ids"
	"router-go/pkg/nat"
	"router-go/pkg/p2p"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Routes   *routing.Table
	Firewall *firewall.Engine
	IDS      *ids.Engine
	NAT      *nat.Table
	QoS      *qos.QueueManager
	Flow     *flow.Engine
	P2P      *p2p.Engine
	ConfigMgr *config.Manager
	Metrics  *metrics.Metrics
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

func (h *Handlers) GetStats(c *gin.Context) {
	snapshot := h.Metrics.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":             "ok",
		"routes_count":       len(h.Routes.Routes()),
		"packets_total":      snapshot.Packets,
		"rx_packets_total":   snapshot.RxPackets,
		"tx_packets_total":   snapshot.TxPackets,
		"ids_alerts_total":   snapshot.IDSAlerts,
		"ids_drops_total":    snapshot.IDSDrops,
		"config_apply_total": snapshot.ConfigApply,
		"config_rollback_total": snapshot.ConfigRollback,
		"config_apply_failed_total": snapshot.ConfigApplyFailed,
		"p2p_peers_total": snapshot.P2PPeers,
		"p2p_routes_synced_total": snapshot.P2PRoutesSynced,
		"bytes_total":        snapshot.Bytes,
		"errors_total":       snapshot.Errors,
		"drops_total":        snapshot.Drops,
		"drops_by_reason":    snapshot.DropsByReason,
		"qos_drops_by_class": snapshot.QoSDropsByClass,
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
	}
	rules := h.IDS.Rules()
	out := make([]ruleView, 0, len(rules))
	for _, r := range rules {
		view := ruleView{
			Name:            r.Name,
			Action:          string(r.Action),
			Protocol:        r.Protocol,
			SrcPort:         r.SrcPort,
			DstPort:         r.DstPort,
			PayloadContains: r.PayloadContains,
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
	}
	h.IDS.AddRule(rule)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetIDSAlerts(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	c.JSON(http.StatusOK, h.IDS.Alerts())
}

func (h *Handlers) ResetIDS(c *gin.Context) {
	if h.IDS == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ids disabled"})
		return
	}
	h.IDS.Reset()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) ApplyConfig(c *gin.Context) {
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
		h.Metrics.IncConfigApplyFailed()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}

	if err := h.ConfigMgr.Apply(newCfg); err != nil {
		h.Metrics.IncConfigApplyFailed()
		h.Metrics.IncConfigRollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "health check failed"})
		return
	}
	h.Metrics.IncConfigApply()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) RollbackConfig(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	if err := h.ConfigMgr.RollbackLast(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no snapshots"})
		return
	}
	h.Metrics.IncConfigRollback()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) GetConfigSnapshots(c *gin.Context) {
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager unavailable"})
		return
	}
	c.JSON(http.StatusOK, h.ConfigMgr.Snapshots())
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
	c.JSON(http.StatusOK, h.IDS.Alerts())
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
