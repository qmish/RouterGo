package api

import (
	"net"
	"net/http"

	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Routes   *routing.Table
	Firewall *firewall.Engine
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
	})
}
