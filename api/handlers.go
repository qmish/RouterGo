package api

import (
	"net"
	"net/http"
	"strings"

	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Routes   *routing.Table
	Firewall *firewall.Engine
	NAT      *nat.Table
	QoS      *qos.QueueManager
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
		"status":        "ok",
		"routes_count":  len(h.Routes.Routes()),
		"packets_total": snapshot.Packets,
		"bytes_total":   snapshot.Bytes,
		"errors_total":  snapshot.Errors,
		"drops_total":   snapshot.Drops,
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
	}
	rules := h.Firewall.Rules()
	out := make([]ruleView, 0, len(rules))
	for _, r := range rules {
		view := ruleView{
			Chain:        r.Chain,
			Action:       string(r.Action),
			Protocol:     r.Protocol,
			SrcPort:      r.SrcPort,
			DstPort:      r.DstPort,
			InInterface:  r.InInterface,
			OutInterface: r.OutInterface,
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

func (h *Handlers) GetNAT(c *gin.Context) {
	type natView struct {
		Type    string `json:"type"`
		SrcIP   string `json:"src_ip,omitempty"`
		DstIP   string `json:"dst_ip,omitempty"`
		SrcPort int    `json:"src_port,omitempty"`
		DstPort int    `json:"dst_port,omitempty"`
		ToIP    string `json:"to_ip,omitempty"`
		ToPort  int    `json:"to_port,omitempty"`
	}
	rules := h.NAT.Rules()
	out := make([]natView, 0, len(rules))
	for _, r := range rules {
		view := natView{
			Type:    string(r.Type),
			SrcPort: r.SrcPort,
			DstPort: r.DstPort,
			ToPort:  r.ToPort,
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
	}
	h.QoS.AddClass(class)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
